// 一条命令跑完整条流水线的安全门禁:deps + secrets + iac + sast 聚合成一份报告、一个退出码。
// 面向 CI:npx break-anything ci 即可。纯编排已验证的扫描器,门禁逻辑是可单测纯函数。

import { scanDependencies } from "./scan.js";
import { scanSecrets } from "./secrets.js";
import { scanIac } from "./iac.js";
import { scanSast } from "./sast.js";

const SEV = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
function sevRank(s) { return SEV[String(s || "").toUpperCase()] ?? 0; }

export const CI_CATEGORIES = ["deps", "secrets", "iac", "sast"];

// 门禁判定(纯函数,可单测):返回是否通过 + 触发原因列表
export function evaluateGate(categories, { failOn = "HIGH" } = {}) {
  const thr = sevRank(failOn);
  const reasons = [];

  const deps = categories.deps;
  if (deps && deps.ok) {
    const reachable = (deps.findings || []).filter(
      (f) => (f.reachability === "called" || f.reachability === "imported") && sevRank(f.severity) >= thr,
    );
    const kev = (deps.findings || []).filter((f) => f.kev);
    if (reachable.length) reasons.push(`${reachable.length} reachable ${failOn}+ dependency ${reachable.length === 1 ? "vuln" : "vulns"}`);
    if (kev.length) reasons.push(`${kev.length} known-exploited (KEV) dependency ${kev.length === 1 ? "vuln" : "vulns"}`);
  }

  const secrets = categories.secrets;
  if (secrets && secrets.ok && (secrets.findings || []).length) {
    reasons.push(`${secrets.findings.length} leaked secret${secrets.findings.length === 1 ? "" : "s"}`);
  }

  for (const [key, label] of [["iac", "IaC"], ["sast", "code"]]) {
    const c = categories[key];
    if (c && c.ok) {
      const bad = (c.findings || []).filter((f) => sevRank(f.severity) >= thr);
      if (bad.length) reasons.push(`${bad.length} ${failOn}+ ${label} issue${bad.length === 1 ? "" : "s"}`);
    }
  }

  return { passed: reasons.length === 0, failOn, reasons };
}

// 聚合所有类别的发现(纯函数,可单测)
export function aggregate(categories) {
  const bySeverity = {};
  let total = 0;
  const counts = {};
  for (const key of Object.keys(categories)) {
    const c = categories[key];
    if (!c) continue;
    if (!c.ok) { counts[key] = { skipped: true, reason: c.message || "unavailable" }; continue; }
    const n = (c.findings || []).length;
    counts[key] = { findings: n };
    for (const f of c.findings || []) {
      total++;
      const s = (f.severity || "UNKNOWN").toUpperCase();
      bySeverity[s] = (bySeverity[s] || 0) + 1;
    }
  }
  return { total, bySeverity, counts };
}

async function safe(fn) {
  try { return await fn(); }
  catch (e) { return { ok: false, message: e instanceof Error ? e.message : String(e), findings: [] }; }
}

// 入口:按需跑各扫描器并聚合 + 门禁
export async function runCi(targetPath, { failOn = "HIGH", skip = [], reachability = true } = {}) {
  const categories = {};
  const want = (k) => !skip.includes(k);
  if (want("deps")) categories.deps = await safe(() => scanDependencies(targetPath, { reachability }));
  if (want("secrets")) categories.secrets = await safe(() => scanSecrets(targetPath, { history: false }));
  if (want("iac")) categories.iac = await safe(() => scanIac(targetPath));
  if (want("sast")) categories.sast = await safe(() => scanSast(targetPath));

  const summary = aggregate(categories);
  const gate = evaluateGate(categories, { failOn });
  return { target: targetPath, ok: true, engine: "ci", categories, summary, gate };
}
