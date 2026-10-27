// 修复方案(Find → Prove → Fix 的第三条腿)。
// 诚实边界:这是基于 OSV 修复数据算出的「升级方案」,不会改你的文件。
// 它给出可直接执行的命令、按可达性+严重度排序、一次升级尽量多关 CVE;
// 上游无修复的单独列出,给缓解建议并指向 Patch Anything 做真正的打补丁。

import { scanDependencies } from "./scan.js";
import { severityRank } from "./osv.js";
import { reachRank } from "./reachability.js";

// 版本比较(纯函数,可单测):按点分段数值比较,忽略预发布/构建后缀
export function compareVersions(a, b) {
  const seg = (v) => String(v).split("-")[0].split("+")[0].split(".").map((n) => parseInt(n, 10) || 0);
  const pa = seg(a), pb = seg(b);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d < 0 ? -1 : 1;
  }
  return 0;
}

// 对单个 CVE:选「大于当前版本里最小的那个修复版」,没有更大的就退回已知最高修复版
function minimalFix(current, fixes) {
  const sorted = [...fixes].sort(compareVersions);
  const greater = sorted.filter((f) => compareVersions(f, current) > 0);
  if (greater.length) return greater[0];
  return sorted[sorted.length - 1];
}

// 选一个目标版本,使其 >= 该包每个可修复 CVE 的最小修复版 → 一次升级关掉全部(纯函数,可单测)
export function pickTarget(current, fixArrays) {
  let target = null;
  for (const arr of fixArrays) {
    if (!arr || !arr.length) continue;
    const m = minimalFix(current, arr);
    if (!target || compareVersions(m, target) > 0) target = m;
  }
  return target;
}

export function upgradeCommand(ecosystem, name, version) {
  switch (ecosystem) {
    case "npm": return `npm install ${name}@${version}`;
    case "PyPI": return `pip install '${name}==${version}'`;
    case "Packagist": return `composer require ${name}:${version}`;
    default: return `# upgrade ${name} to ${version}`;
  }
}

// 从一组发现(findings)构建修复方案(纯函数,可单测)。
// 返回形状与 report.renderFix / CLI 对齐:
//   { ok, target, upgrades:[{package,from,to,resolves,command,maxReach(数值),maxSeverity}],
//     noFix:[{package,version,cve,severity,reachability}],
//     summary:{upgradeCount,noFixCount,resolvedVulns} }
export function buildFixPlan(findings, target = "") {
  const groups = new Map();
  for (const f of findings || []) {
    const key = `${f.ecosystem}|${f.package}|${f.version}`;
    if (!groups.has(key)) {
      groups.set(key, {
        package: f.package, version: f.version, ecosystem: f.ecosystem,
        reachability: f.reachability || "unknown", severity: f.severity || "UNKNOWN",
        fixable: [], unfixable: [],
      });
    }
    const g = groups.get(key);
    if (severityRank(f.severity) > severityRank(g.severity)) g.severity = f.severity;
    if (reachRank(f.reachability) > reachRank(g.reachability)) g.reachability = f.reachability;
    const id = f.cve || f.id;
    if (Array.isArray(f.fixedVersions) && f.fixedVersions.length) {
      g.fixable.push({ id, fixedVersions: f.fixedVersions });
    } else {
      g.unfixable.push({ id, severity: f.severity || "UNKNOWN", reachability: f.reachability || "unknown" });
    }
  }

  const upgrades = [], noFix = [];
  for (const g of groups.values()) {
    if (g.fixable.length) {
      const to = pickTarget(g.version, g.fixable.map((c) => c.fixedVersions));
      upgrades.push({
        package: g.package, from: g.version, to,
        resolves: g.fixable.length,
        command: upgradeCommand(g.ecosystem, g.package, to),
        maxReach: reachRank(g.reachability),
        maxSeverity: g.severity,
      });
    }
    for (const c of g.unfixable) {
      noFix.push({ package: g.package, version: g.version, cve: c.id, severity: c.severity, reachability: c.reachability });
    }
  }

  const order = (a, b) =>
    (b.maxReach ?? reachRank(b.reachability)) - (a.maxReach ?? reachRank(a.reachability)) ||
    severityRank(b.maxSeverity ?? b.severity) - severityRank(a.maxSeverity ?? a.severity) ||
    (b.resolves ?? 0) - (a.resolves ?? 0);
  upgrades.sort(order);
  noFix.sort(order);

  return {
    ok: true,
    target,
    upgrades,
    noFix,
    summary: {
      upgradeCount: upgrades.length,
      noFixCount: noFix.length,
      resolvedVulns: upgrades.reduce((n, u) => n + u.resolves, 0),
    },
  };
}

// 对一个项目:先扫依赖(或接收现成 findings),再出修复方案
export async function fixDependencies(targetPath, { reachability = true, findings } = {}) {
  if (Array.isArray(findings)) {
    return buildFixPlan(findings, targetPath);
  }
  const scan = await scanDependencies(targetPath, { reachability });
  if (!scan.ok) {
    return { ok: false, target: scan.target, message: scan.message, upgrades: [], noFix: [], summary: { upgradeCount: 0, noFixCount: 0, resolvedVulns: 0 } };
  }
  return buildFixPlan(scan.findings, scan.target);
}
