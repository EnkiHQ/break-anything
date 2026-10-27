// SBOM(软件物料清单)生成与比对,输出标准 CycloneDX 1.5 JSON。
// 用途:把依赖清单变成可归档、可审计、可在 CI 里 diff 的标准制品。纯本地,不触网。

import path from "node:path";
import { randomUUID } from "node:crypto";
import { loadLockfiles } from "./lockfiles.js";

const VERSION = "0.11.0";

// 每个生态对应的 purl(Package URL)类型与命名(纯函数,可单测)
export function purlFor(ecosystem, name, version) {
  const enc = (s) => encodeURIComponent(s);
  const v = enc(version);
  switch (ecosystem) {
    case "npm": {
      // scope @scope/name → namespace %40scope
      if (name.startsWith("@") && name.includes("/")) {
        const [scope, pkg] = name.slice(1).split("/");
        return `pkg:npm/%40${enc(scope)}/${enc(pkg)}@${v}`;
      }
      return `pkg:npm/${enc(name)}@${v}`;
    }
    case "PyPI":
      return `pkg:pypi/${enc(name.toLowerCase().replace(/_/g, "-"))}@${v}`;
    case "Packagist": {
      const [vendor, pkg] = name.split("/");
      return pkg ? `pkg:composer/${enc(vendor)}/${enc(pkg)}@${v}` : `pkg:composer/${enc(name)}@${v}`;
    }
    case "Go":
      // golang purl 保留模块路径(不编码斜杠)
      return `pkg:golang/${name}@${v}`;
    case "crates.io":
      return `pkg:cargo/${enc(name)}@${v}`;
    case "RubyGems":
      return `pkg:gem/${enc(name)}@${v}`;
    case "Maven": {
      const [group, artifact] = name.split(":");
      return artifact ? `pkg:maven/${enc(group)}/${enc(artifact)}@${v}` : `pkg:maven/${enc(name)}@${v}`;
    }
    case "NuGet":
      return `pkg:nuget/${enc(name)}@${v}`;
    default:
      return `pkg:generic/${enc(name)}@${v}`;
  }
}

// 从 loadLockfiles 的 sources 构建 CycloneDX BOM(纯函数;时间戳/序列号可注入以便测试)
export function buildSbom(sources, { name = "application", now = new Date().toISOString(), serialNumber } = {}) {
  const components = [];
  const seen = new Set();
  for (const s of sources || []) {
    for (const p of s.packages || []) {
      const purl = purlFor(p.ecosystem, p.name, p.version);
      if (seen.has(purl)) continue;
      seen.add(purl);
      components.push({
        type: "library",
        "bom-ref": purl,
        name: p.name,
        version: p.version,
        purl,
        ...(p.direct === false ? { scope: "optional" } : {}),
      });
    }
  }
  components.sort((a, b) => a.purl.localeCompare(b.purl));
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: serialNumber || `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: now,
      tools: [{ vendor: "EnkiHQ", name: "break-anything", version: VERSION }],
      component: { type: "application", name },
    },
    components,
  };
}

// 去掉 purl 末尾的版本,作为稳定比对键
function purlKey(purl) {
  return String(purl).replace(/@[^@/]*$/, "");
}

// 比对两个 BOM(纯函数,可单测):新增 / 移除 / 版本变化
export function diffSbom(oldBom, newBom) {
  const index = (bom) => {
    const m = new Map();
    for (const c of (bom && bom.components) || []) m.set(purlKey(c.purl || c["bom-ref"]), c);
    return m;
  };
  const a = index(oldBom), b = index(newBom);
  const added = [], removed = [], changed = [];
  for (const [k, c] of b) if (!a.has(k)) added.push({ name: c.name, version: c.version, purl: c.purl });
  for (const [k, c] of a) if (!b.has(k)) removed.push({ name: c.name, version: c.version, purl: c.purl });
  for (const [k, c] of b) {
    if (a.has(k) && a.get(k).version !== c.version) {
      changed.push({ name: c.name, from: a.get(k).version, to: c.version, purl: c.purl });
    }
  }
  const cmp = (x, y) => x.name.localeCompare(y.name);
  added.sort(cmp); removed.sort(cmp); changed.sort(cmp);
  return { added, removed, changed, summary: { added: added.length, removed: removed.length, changed: changed.length } };
}

// 入口:扫描目标目录的 lockfile,生成 BOM
export async function generateSbom(targetPath, opts = {}) {
  const { dir, sources } = await loadLockfiles(targetPath);
  if (!sources.length) {
    return { ok: false, message: "未找到受支持的 lockfile,无法生成 SBOM。", bom: null };
  }
  const bom = buildSbom(sources, { name: path.basename(dir) || "application", ...opts });
  return { ok: true, dir, bom, componentCount: bom.components.length, sources: sources.map((s) => ({ ecosystem: s.ecosystem, packages: s.packages.length })) };
}
