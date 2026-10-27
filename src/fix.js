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

// 对单个 CVE 的修复版本集合:取「大于当前版本里最小的」,没有更高的就退回已知最高修复版
function minimalFix(current, fixes) {
  const sorted = [...fixes].sort(compareVersions);
  const greater = sorted.filter((f) => compareVersions(f, current) > 0);
  if (greater.length) return greater[0];
  return sorted[sorted.length - 1];
}

// 给一个包的若干 CVE(每个有 fixedVersions),挑出能覆盖全部的最小安全升级目标(纯函数,可单测)
export function pickUpgradeTarget(currentVersion, findings) {
  let target = null;
  for (const f of findings) {
    const fixes = f.fixedVersions || [];
    if (!fixes.length) continue;
    const m = minimalFix(currentVersion, fixes);
    if (!target || compareVersions(m, target) > 0) target = m;
  }
  return target;
}

function upgradeCommand(ecosystem, name, version) {
  switch (ecosystem) {
    case "npm": return `npm install ${name}@${version}`;
    case "PyPI": return `pip install "${name}==${version}"`;
    case "Packagist": return `composer require ${name}:${version}`;
    default: return `# upgrade ${name} to ${version}`;
  }
}

function topSeverity(findings) {
  return findings.reduce((a, f) => (severityRank(f.severity) > severityRank(a) ? f.severity : a), "UNKNOWN");
}

// ---- 核心:从发现列表生成修复计划(纯函数,可单测)----
// 返回形状与 report.renderFix / CLI 对齐:
//   { upgrades:[{package,from,to,resolves,command,maxReach(数值),maxSeverity}],
//     noFix:[{package,version,cve,severity,reachability}],
//     summary:{upgradeCount,noFixCount,resolvedVulns} }
export function planFix(findings = []) {
  const groups = new Map();
  for (const f of findings) {
    const key = `${f.ecosystem}|${f.package}|${f.version}`;
    if (!groups.has(key)) {
      groups.set(key, { package: f.package, version: f.version, ecosystem: f.ecosystem, items: [] });
    }
    groups.get(key).items.push(f);
  }

  const upgrades = [], noFix = [];
  for (const g of groups.values()) {
    const fixable = g.items.filter((f) => Array.isArray(f.fixedVersions) && f.fixedVersions.length);
    const unfixable = g.items.filter((f) => !(Array.isArray(f.fixedVersions) && f.fixedVersions.length));

    if (fixable.length) {
      const to = pickUpgradeTarget(g.version, fixable);
      upgrades.push({
        package: g.package,
        ecosystem: g.ecosystem,
        from: g.version,
        to,
        resolves: fixable.length,
        cves: fixable.map((f) => f.cve || f.id),
        maxReach: fixable.reduce((m, f) => Math.max(m, reachRank(f.reachability)), 0),
        maxSeverity: topSeverity(fixable),
        maxEpss: fixable.reduce((m, f) => Math.max(m, f.epss || 0), 0),
        command: upgradeCommand(g.ecosystem, g.package, to),
      });
    }
    for (const f of unfixable) {
      noFix.push({
        package: g.package, version: g.version, ecosystem: g.ecosystem,
        cve: f.cve || f.id, severity: f.severity || "UNKNOWN", reachability: f.reachability || "unknown",
        summary: (f.summary || "").replace(/\s+/g, " ").slice(0, 120),
      });
    }
  }

  upgrades.sort((a, b) =>
    (b.maxReach - a.maxReach) ||
    (severityRank(b.maxSeverity) - severityRank(a.maxSeverity)) ||
    (b.resolves - a.resolves) ||
    (b.maxEpss - a.maxEpss));
  noFix.sort((a, b) =>
    (reachRank(b.reachability) - reachRank(a.reachability)) ||
    (severityRank(b.severity) - severityRank(a.severity)));

  return {
    upgrades,
    noFix,
    summary: {
      upgradeCount: upgrades.length,
      noFixCount: noFix.length,
      resolvedVulns: upgrades.reduce((n, u) => n + u.resolves, 0),
    },
  };
}

// ---- 入口:扫一次依赖并出计划(也可传入现成 findings 跳过扫描)----
export async function fixDependencies(targetPath, { reachability = true, findings } = {}) {
  if (Array.isArray(findings)) {
    return { ok: true, target: targetPath, ...planFix(findings) };
  }
  const scan = await scanDependencies(targetPath, { reachability });
  if (!scan.ok) {
    return { ok: false, target: scan.target || targetPath, message: scan.message, upgrades: [], noFix: [], summary: { upgradeCount: 0, noFixCount: 0, resolvedVulns: 0 } };
  }
  return { ok: true, target: scan.target, scanned: scan.scanned, ...planFix(scan.findings) };
}
