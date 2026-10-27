// 修复规划(Find → Prove → Fix 的第三条腿)。
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

function upgradeCommand(ecosystem, name, to) {
  switch (ecosystem) {
    case "npm": return `npm install ${name}@${to}`;
    case "PyPI": return `pip install "${name}==${to}"`;
    case "Packagist": return `composer require ${name}:${to}`;
    default: return `upgrade ${name} to ${to}`;
  }
}

function topSeverity(findings) {
  return findings.map((f) => f.severity).reduce((a, b) => (severityRank(b) > severityRank(a) ? b : a), "UNKNOWN");
}

// 给一个包的若干(可修复)CVE,挑出能覆盖全部的最小安全升级目标(纯函数,可单测)。
// findings: [{ fixedVersions: [...] }]。对每个 CVE 取「比当前版本高里最小的」,没有更高的就取该 CVE 已知最高修复版;
// 最终目标取这些值里的最大者 → 一次升级关掉该包所有有修复的 CVE。
export function pickUpgradeTarget(currentVersion, findings) {
  let target = null;
  for (const f of findings) {
    const fixes = f.fixedVersions || [];
    if (!fixes.length) continue;
    const sorted = [...fixes].sort(compareVersions);
    const greater = sorted.filter((v) => compareVersions(v, currentVersion) > 0);
    const minimal = greater.length ? greater[0] : sorted[sorted.length - 1];
    if (!target || compareVersions(minimal, target) > 0) target = minimal;
  }
  return target;
}

// 从发现列表生成修复计划(纯函数,可单测)。
// 返回 { upgrades, noFix, summary },形状与 report.renderFix / CLI 对齐。
export function planFix(findings = []) {
  const groups = new Map(); // key: eco|name|version
  for (const f of findings) {
    const key = `${f.ecosystem}|${f.package}|${f.version}`;
    if (!groups.has(key)) {
      groups.set(key, { package: f.package, version: f.version, ecosystem: f.ecosystem, findings: [] });
    }
    groups.get(key).findings.push(f);
  }

  const upgrades = [], noFix = [];
  for (const g of groups.values()) {
    const fixable = g.findings.filter((f) => (f.fixedVersions || []).length > 0);
    const unfixable = g.findings.filter((f) => !((f.fixedVersions || []).length > 0));

    if (fixable.length) {
      const to = pickUpgradeTarget(g.version, fixable);
      if (to) {
        upgrades.push({
          package: g.package,
          ecosystem: g.ecosystem,
          from: g.version,
          to,
          resolves: fixable.length,
          cves: fixable.map((f) => f.cve || f.id),
          command: upgradeCommand(g.ecosystem, g.package, to),
          maxReach: fixable.reduce((m, f) => Math.max(m, reachRank(f.reachability)), 0),
          maxSeverity: topSeverity(fixable),
          maxEpss: fixable.reduce((m, f) => Math.max(m, f.epss || 0), 0),
          kev: fixable.some((f) => f.kev),
        });
      } else {
        unfixable.push(...fixable);
      }
    }

    for (const f of unfixable) {
      noFix.push({
        package: g.package, version: g.version, ecosystem: g.ecosystem,
        cve: f.cve || f.id, severity: f.severity, reachability: f.reachability,
        kev: !!f.kev,
        summary: (f.summary || "").replace(/\s+/g, " ").slice(0, 120),
      });
    }
  }

  // 排序:可达性 → KEV(在野利用) → 严重度 → 能关的 CVE 数 → EPSS
  upgrades.sort((a, b) =>
    (b.maxReach - a.maxReach) ||
    ((b.kev ? 1 : 0) - (a.kev ? 1 : 0)) ||
    (severityRank(b.maxSeverity) - severityRank(a.maxSeverity)) ||
    (b.resolves - a.resolves) ||
    (b.maxEpss - a.maxEpss));
  noFix.sort((a, b) =>
    (reachRank(b.reachability) - reachRank(a.reachability)) ||
    ((b.kev ? 1 : 0) - (a.kev ? 1 : 0)) ||
    (severityRank(b.severity) - severityRank(a.severity)));

  return {
    upgrades,
    noFix,
    summary: {
      upgradeCount: upgrades.length,
      resolvedVulns: upgrades.reduce((n, u) => n + u.resolves, 0),
      noFixCount: noFix.length,
      kevCount: upgrades.filter((u) => u.kev).length + noFix.filter((n) => n.kev).length,
    },
  };
}

// 入口:扫一次依赖并生成计划(也可传入已有 findings 跳过扫描)
export async function fixDependencies(targetPath, { reachability = true, findings } = {}) {
  if (Array.isArray(findings)) {
    return { ok: true, target: targetPath, ...planFix(findings) };
  }
  const scan = await scanDependencies(targetPath, { reachability });
  if (!scan.ok) {
    return { ok: false, target: scan.target || targetPath, message: scan.message, upgrades: [], noFix: [], summary: { upgradeCount: 0, resolvedVulns: 0, noFixCount: 0 } };
  }
  return { ok: true, target: scan.target, scanned: scan.scanned, ...planFix(scan.findings) };
}
