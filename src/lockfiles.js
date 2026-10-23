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
