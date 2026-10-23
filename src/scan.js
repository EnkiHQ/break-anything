import { loadLockfiles } from "./lockfiles.js";
import { scanPackages, severityRank } from "./osv.js";
import { enrichEpss } from "./epss.js";
import { buildReachability, classify, reachRank } from "./reachability.js";

// 一次完整的依赖扫描:lockfile → OSV → EPSS → 可达性 → 排序后的发现列表
export async function scanDependencies(targetPath, { reachability = true, concurrency = 8 } = {}) {
  const { dir, sources } = await loadLockfiles(targetPath);
  if (!sources.length) {
    return {
      target: dir,
      ok: false,
      message: "未找到受支持的 lockfile(package-lock.json / composer.lock / requirements.txt)。",
      sources: [],
      findings: [],
      summary: emptySummary(),
    };
  }

  const allPackages = sources.flatMap((s) => s.packages);
  const { findings: raw, errors } = await scanPackages(allPackages, { concurrency });

  // EPSS:汇总所有 CVE 一次性查
  const cves = raw.flatMap((f) => f.vulns.map((v) => v.cve)).filter(Boolean);
  const epss = await enrichEpss(cves);

  // 可达性:只在有源码时做
  let imported = new Set();
  if (reachability) {
    const names = [...new Set(allPackages.map((p) => p.name))];
    imported = await buildReachability(dir, names);
  }

  // 展开成「每个漏洞一行」的发现
  const flat = [];
  for (const { pkg, vulns } of raw) {
    const reach = reachability ? classify(pkg, imported) : "unknown";
    for (const v of vulns) {
      const ep = v.cve ? epss.get(v.cve) : null;
      flat.push({
        package: pkg.name,
        version: pkg.version,
        ecosystem: pkg.ecosystem,
        direct: pkg.direct,
        reachability: reach,
        id: v.id,
        cve: v.cve,
        aliases: v.aliases,
        severity: v.severity,
        epss: ep ? ep.epss : null,
        epssPercentile: ep ? ep.percentile : null,
        fixedVersions: v.fixedVersions,
        summary: v.summary,
        references: v.references,
      });
    }
  }

  flat.sort(cmpFinding);

  return {
    target: dir,
    ok: true,
    sources: sources.map((s) => ({ ecosystem: s.ecosystem, file: s.file, packages: s.packages.length })),
    scanned: allPackages.length,
    errors,
    findings: flat,
    summary: summarize(flat),
  };
}

// 排序:先严重度,再可达性,再 EPSS
function cmpFinding(a, b) {
  const s = severityRank(b.severity) - severityRank(a.severity);
  if (s) return s;
  const r = reachRank(b.reachability) - reachRank(a.reachability);
  if (r) return r;
  return (b.epss ?? 0) - (a.epss ?? 0);
}

function summarize(flat) {
  const sum = emptySummary();
  for (const f of flat) {
    sum.total++;
    sum.bySeverity[f.severity] = (sum.bySeverity[f.severity] || 0) + 1;
    if (f.reachability === "imported") sum.reachable++;
  }
  return sum;
}

function emptySummary() {
  return { total: 0, reachable: 0, bySeverity: {} };
}
