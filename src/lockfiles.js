import { readFile, stat } from "node:fs/promises";
import path from "node:path";

// 探测目标路径下支持的 lockfile,返回 { ecosystem, file, packages, manifestDirect }
// packages: [{ name, version, ecosystem, direct }]
// manifestDirect: Set<string> 直接依赖名(用于可达性判断)
export async function loadLockfiles(targetPath) {
  const dir = await resolveDir(targetPath);
  const out = [];

  const npmLock = path.join(dir, "package-lock.json");
  if (await exists(npmLock)) out.push(await parseNpmLock(npmLock, dir));

  const composerLock = path.join(dir, "composer.lock");
  if (await exists(composerLock)) out.push(await parseComposerLock(composerLock, dir));

  const reqTxt = path.join(dir, "requirements.txt");
  if (await exists(reqTxt)) out.push(await parseRequirements(reqTxt));

  const goMod = path.join(dir, "go.mod");
  if (await exists(goMod)) out.push(await parseGoModFile(goMod));

  const cargoLock = path.join(dir, "Cargo.lock");
  if (await exists(cargoLock)) out.push(await parseCargoLockFile(cargoLock, dir));

  const gemLock = path.join(dir, "Gemfile.lock");
  if (await exists(gemLock)) out.push(await parseGemfileLockFile(gemLock));

  const pom = path.join(dir, "pom.xml");
  if (await exists(pom)) out.push(await parsePomFile(pom));

  const nugetLock = path.join(dir, "packages.lock.json");
  if (await exists(nugetLock)) out.push(await parseNugetLockFile(nugetLock));

  return { dir, sources: out.filter(Boolean) };
}

async function resolveDir(p) {
  const s = await stat(p);
  return s.isDirectory() ? p : path.dirname(p);
}

async function exists(p) {
  try { await stat(p); return true; } catch { return false; }
}

// ---- npm: package-lock.json(v2/v3 的 packages,回退 v1 的 dependencies)----
async function parseNpmLock(file, dir) {
  const raw = JSON.parse(await readFile(file, "utf8"));
  const direct = await readNpmDirect(dir);
  const map = new Map();

  if (raw.packages && typeof raw.packages === "object") {
    for (const [key, info] of Object.entries(raw.packages)) {
      if (!key || !info?.version) continue; // "" 是根项目,跳过
      const name = key.startsWith("node_modules/")
        ? key.slice(key.lastIndexOf("node_modules/") + "node_modules/".length)
        : key;
      if (!name) continue;
      map.set(`${name}@${info.version}`, { name, version: info.version });
    }
  } else if (raw.dependencies && typeof raw.dependencies === "object") {
    walkV1(raw.dependencies, map);
  }

  const packages = [...map.values()].map((p) => ({
    ...p,
    ecosystem: "npm",
    direct: direct.has(p.name),
  }));
  return { ecosystem: "npm", file, packages, manifestDirect: direct };
}

function walkV1(deps, map) {
  for (const [name, info] of Object.entries(deps)) {
    if (info?.version) map.set(`${name}@${info.version}`, { name, version: info.version });
    if (info?.dependencies) walkV1(info.dependencies, map);
  }
}

async function readNpmDirect(dir) {
  const pkgPath = path.join(dir, "package.json");
  const set = new Set();
  if (!(await exists(pkgPath))) return set;
  try {
    const pkg = JSON.parse(await readFile(pkgPath, "utf8"));
    for (const field of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
      for (const name of Object.keys(pkg[field] || {})) set.add(name);
    }
  } catch { /* 忽略损坏的 package.json */ }
  return set;
}

// ---- PHP: composer.lock ----
async function parseComposerLock(file, dir) {
  const raw = JSON.parse(await readFile(file, "utf8"));
  const direct = await readComposerDirect(dir);
  const packages = [];
  for (const group of ["packages", "packages-dev"]) {
    for (const p of raw[group] || []) {
      if (!p.name || !p.version) continue;
      const version = String(p.version).replace(/^v/, "");
      packages.push({ name: p.name, version, ecosystem: "Packagist", direct: direct.has(p.name) });
    }
  }
  return { ecosystem: "Packagist", file, packages, manifestDirect: direct };
}

async function readComposerDirect(dir) {
  const p = path.join(dir, "composer.json");
  const set = new Set();
  if (!(await exists(p))) return set;
  try {
    const json = JSON.parse(await readFile(p, "utf8"));
    for (const field of ["require", "require-dev"]) {
      for (const name of Object.keys(json[field] || {})) set.add(name);
    }
  } catch { /* 忽略 */ }
  return set;
}

// ---- Python: requirements.txt(只取用 == 钉死的版本)----
async function parseRequirements(file) {
  const text = await readFile(file, "utf8");
  const packages = [];
  for (const line of text.split(/\r?\n/)) {
    const s = line.trim();
    if (!s || s.startsWith("#") || s.startsWith("-")) continue;
    const m = s.match(/^([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9._-]+)/);
    if (m) packages.push({ name: m[1], version: m[2], ecosystem: "PyPI", direct: true });
  }
  return { ecosystem: "PyPI", file, packages, manifestDirect: new Set(packages.map((p) => p.name)) };
}

// ---- Go: go.mod(require 块 / 单行 require;// indirect 视为传递依赖)----
// 纯函数,可单测。OSV 的 Go 生态版本不带前导 v,这里统一去掉。
export function parseGoModText(text) {
  const packages = [];
  const direct = new Set();
  const seen = new Set();
  let inBlock = false;
  for (const raw of text.split(/\r?\n/)) {
    const indirect = /\/\/\s*indirect/.test(raw);
    const line = raw.replace(/\/\/.*$/, "").trim();
    if (/^require\s*\($/.test(line)) { inBlock = true; continue; }
    if (inBlock && line === ")") { inBlock = false; continue; }
    const m = inBlock
      ? line.match(/^(\S+)\s+v(\S+)/)
      : line.match(/^require\s+(\S+)\s+v(\S+)/);
    if (m) {
      const name = m[1];
      const version = m[2];
      const key = `${name}@${version}`;
      if (seen.has(key)) continue;
      seen.add(key);
      packages.push({ name, version });
      if (!indirect) direct.add(name);
    }
  }
  return { packages, direct };
}

async function parseGoModFile(file) {
  const text = await readFile(file, "utf8");
  const { packages, direct } = parseGoModText(text);
  return {
    ecosystem: "Go",
    file,
    packages: packages.map((p) => ({ ...p, ecosystem: "Go", direct: direct.has(p.name) })),
    manifestDirect: direct,
  };
}

// ---- Rust: Cargo.lock([[package]] 块);直接依赖取自 Cargo.toml ----
export function parseCargoLockText(text) {
  const packages = [];
  const blocks = text.split(/\[\[package\]\]/).slice(1);
  for (const b of blocks) {
    const name = (b.match(/\bname\s*=\s*"([^"]+)"/) || [])[1];
    const version = (b.match(/\bversion\s*=\s*"([^"]+)"/) || [])[1];
    if (name && version) packages.push({ name, version });
  }
  return { packages };
}

// 从 Cargo.toml 的 [dependencies]/[dev-dependencies]/[build-dependencies] 抽直接依赖名
export function parseCargoTomlDirect(text) {
  const set = new Set();
  let inDeps = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, "").trim();
    const sec = line.match(/^\[([^\]]+)\]$/);
    if (sec) { inDeps = /(^|\.)(dependencies|dev-dependencies|build-dependencies)$/.test(sec[1]); continue; }
    if (inDeps) {
      const m = line.match(/^([A-Za-z0-9_-]+)\s*=/);
      if (m) set.add(m[1]);
    }
  }
  return set;
}

async function parseCargoLockFile(file, dir) {
  const text = await readFile(file, "utf8");
  const { packages } = parseCargoLockText(text);
  let direct = new Set();
  const cargoToml = path.join(dir, "Cargo.toml");
  if (await exists(cargoToml)) {
    try { direct = parseCargoTomlDirect(await readFile(cargoToml, "utf8")); } catch { /* 忽略 */ }
  }
  return {
    ecosystem: "crates.io",
    file,
    packages: packages.map((p) => ({ ...p, ecosystem: "crates.io", direct: direct.has(p.name) })),
    manifestDirect: direct,
  };
}

// ---- Ruby: Gemfile.lock(GEM > specs: 为解析出的包;DEPENDENCIES 为直接依赖)----
export function parseGemfileLockText(text) {
  const packages = [];
  const direct = new Set();
  const seen = new Set();
  let section = null;
  for (const raw of text.split(/\r?\n/)) {
    if (/^[A-Za-z]/.test(raw)) { section = raw.trim(); continue; }
    if (section === "GEM" || section === "GIT" || section === "PATH") {
      const m = raw.match(/^ {4}([A-Za-z0-9._-]+) \(([^()]+)\)\s*$/);
      if (m) {
        const key = `${m[1]}@${m[2]}`;
        if (!seen.has(key)) { seen.add(key); packages.push({ name: m[1], version: m[2] }); }
      }
    } else if (section === "DEPENDENCIES") {
      const m = raw.match(/^ {2}([A-Za-z0-9._-]+)/);
      if (m) direct.add(m[1]);
    }
  }
  return { packages, direct };
}

async function parseGemfileLockFile(file) {
  const text = await readFile(file, "utf8");
  const { packages, direct } = parseGemfileLockText(text);
  return {
    ecosystem: "RubyGems",
    file,
    packages: packages.map((p) => ({ ...p, ecosystem: "RubyGems", direct: direct.has(p.name) })),
    manifestDirect: direct,
  };
}

// ---- Java/Maven: pom.xml(解析 <dependencies> 的直接依赖;${属性} 从 <properties> 解析)----
// 纯函数,可单测。OSV 的 Maven 包名是 groupId:artifactId。pom 只声明直接依赖,
// 传递依赖需要跑 Maven 解析器(路线图)。test 作用域仍纳入,但标注在 scope 里。
export function parsePomXml(text) {
  // 先收集 <properties> 里的键值,用于解析 ${...} 版本
  const props = new Map();
  const propsBlock = (text.match(/<properties>([\s\S]*?)<\/properties>/) || [])[1] || "";
  for (const m of propsBlock.matchAll(/<([A-Za-z0-9_.-]+)>([^<]+)<\/\1>/g)) {
    props.set(m[1], m[2].trim());
  }
  // project.version / version 常用兜底
  const projVersion = (text.match(/<project[\s\S]*?<version>([^<]+)<\/version>/) || [])[1];

  const resolve = (v) => {
    if (!v) return v;
    let out = v.trim();
    const pm = out.match(/^\$\{([^}]+)\}$/);
    if (pm) {
      const key = pm[1];
      if (props.has(key)) return props.get(key);
      if (/project\.version|version/.test(key) && projVersion) return projVersion.trim();
      return null; // 无法解析的属性 → 跳过该依赖版本
    }
    return out;
  };

  const packages = [];
  const direct = new Set();
  const seen = new Set();
  for (const dep of text.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
    const body = dep[1];
    const g = (body.match(/<groupId>([^<]+)<\/groupId>/) || [])[1];
    const a = (body.match(/<artifactId>([^<]+)<\/artifactId>/) || [])[1];
    const vRaw = (body.match(/<version>([^<]+)<\/version>/) || [])[1];
    if (!g || !a) continue;
    const version = resolve(vRaw);
    if (!version) continue; // 版本缺失或无法解析(BOM 管理的版本)→ 跳过
    const name = `${g.trim()}:${a.trim()}`;
    const key = `${name}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    packages.push({ name, version });
    direct.add(name);
  }
  return { packages, direct };
}

async function parsePomFile(file) {
  const text = await readFile(file, "utf8");
  const { packages, direct } = parsePomXml(text);
  return {
    ecosystem: "Maven",
    file,
    packages: packages.map((p) => ({ ...p, ecosystem: "Maven", direct: direct.has(p.name) })),
    manifestDirect: direct,
  };
}

// ---- .NET/NuGet: packages.lock.json(含解析后的完整依赖树,type=Direct 为直接依赖)----
export function parseNugetLock(json) {
  let data = json;
  if (typeof json === "string") {
    try { data = JSON.parse(json); } catch { return { packages: [], direct: new Set() }; }
  }
  const packages = [];
  const direct = new Set();
  const seen = new Set();
  const frameworks = (data && data.dependencies) || {};
  for (const tfm of Object.keys(frameworks)) {
    const deps = frameworks[tfm] || {};
    for (const [name, info] of Object.entries(deps)) {
      const version = info && (info.resolved || info.requested);
      if (!version) continue;
      const key = `${name}@${version}`;
      if (!seen.has(key)) { seen.add(key); packages.push({ name, version }); }
      if (info && /direct/i.test(info.type || "")) direct.add(name);
    }
  }
  return { packages, direct };
}

async function parseNugetLockFile(file) {
  const text = await readFile(file, "utf8");
  const { packages, direct } = parseNugetLock(text);
  return {
    ecosystem: "NuGet",
    file,
    packages: packages.map((p) => ({ ...p, ecosystem: "NuGet", direct: direct.has(p.name) })),
    manifestDirect: direct,
  };
}
