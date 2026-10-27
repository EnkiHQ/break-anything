import { loadLockfiles } from "./lockfiles.js";
import { scanPackages, severityRank } from "./osv.js";
import { enrichEpss } from "./epss.js";
import { analyzeUsage, classifyUsage, reachRank } from "./reachability.js";
import { enrichKev } from "./kev.js";

// 一次完整的依赖扫描:lockfile → OSV → EPSS → 可达性 → 排序后的发现列表
export async function scanDependencies(targetPath, { reachability = true, concurrency = 8 } = {}) {
  const { dir, sources } = await loadLockfiles(targetPath);
  if (!sources.length) {
    return {
      target: dir,
      ok: false,
      message: "未找到受支持的 lockfile(package-lock.json / composer.lock / requirements.txt / go.mod / Cargo.lock / Gemfile.lock)。",
      sources: [],
      findings: [],
      summary: emptySummary(),
    };
  }

  const allPackages = sources.flatMap((s) => s.packages);
  const { findings: raw, errors } = await scanPackages(allPackages, { concurrency });

  // EPSS + CISA KEV:汇总所有 CVE 一次性查(并行,各自尽力而为)
  const cves = raw.flatMap((f) => f.vulns.map((v) => v.cve)).filter(Boolean);
  const [epss, kev] = await Promise.all([enrichEpss(cves), enrichKev(cves)]);

  // 可达性:只在有源码时做
  let usage = new Map();
  if (reachability) {
    const names = [...new Set(allPackages.map((p) => p.name))];
    usage = await analyzeUsage(dir, names);
  }

  // 展开成「每个漏洞一行」的发现
  const flat = [];
  for (const { pkg, vulns } of raw) {
    const reach = reachability ? classifyUsage(pkg, usage) : "unknown";
    for (const v of vulns) {
      const ep = v.cve ? epss.get(v.cve) : null;
      const kv = v.cve ? kev.get(v.cve.toUpperCase()) : null;
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
        kev: !!kv,
        kevRansomware: kv ? kv.ransomware : false,
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

// 排序:先严重度,再可达性,再 KEV(在野利用),再 EPSS
function cmpFinding(a, b) {
  const s = severityRank(b.severity) - severityRank(a.severity);
  if (s) return s;
  const r = reachRank(b.reachability) - reachRank(a.reachability);
  if (r) return r;
  const k = (b.kev ? 1 : 0) - (a.kev ? 1 : 0);
  if (k) return k;
  return (b.epss ?? 0) - (a.epss ?? 0);
}

function summarize(flat) {
  const sum = emptySummary();
  for (const f of flat) {
    sum.total++;
    sum.bySeverity[f.severity] = (sum.bySeverity[f.severity] || 0) + 1;
    if (f.reachability === "called" || f.reachability === "imported") sum.reachable++;
    if (f.reachability === "called") sum.called++;
    if (f.kev) sum.kev++;
  }
  return sum;
}

function emptySummary() {
  return { total: 0, reachable: 0, called: 0, kev: 0, bySeverity: {} };
}
