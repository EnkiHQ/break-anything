// 自包含 HTML 报告:把 ci 聚合结果渲染成一份可分享的单文件 HTML(内联样式,无外部依赖)。
// 纯函数,可单测。所有来自扫描内容的值都做 HTML 转义(发现来自被扫代码/依赖,必须防 XSS)。

const TOOL_VERSION = "0.18.0";

export function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

const SEV_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };

// 把一条发现按类别归一成一行 { severity, name, meta, location }(纯函数)
export function findingRow(kind, f) {
  switch (kind) {
    case "deps":
      return {
        severity: f.severity || "UNKNOWN",
        name: `${f.package}@${f.version}${f.kev ? " [KEV]" : ""}`,
        meta: `${f.cve || f.id}${f.summary ? " — " + f.summary : ""}`,
        location: `${f.ecosystem} · ${f.reachability || "—"}`,
      };
    case "secrets":
      return {
        severity: f.severity || "HIGH",
        name: f.rule,
        meta: "leaked secret",
        location: f.source === "history" ? `git history ${f.commit || ""}` : `${f.location || ""}${f.line ? ":" + f.line : ""}`,
      };
    case "iac":
      return {
        severity: f.severity || "UNKNOWN",
        name: f.title || f.rule,
        meta: [f.rule, f.cwe].filter(Boolean).join(" · "),
        location: f.location || "",
      };
    case "sast":
      return {
        severity: f.severity || "UNKNOWN",
        name: f.rule,
        meta: f.message || "",
        location: f.location || "",
      };
    default:
      return { severity: f.severity || "UNKNOWN", name: f.rule || f.id || "finding", meta: "", location: "" };
  }
}

function badge(sev) {
  const s = String(sev || "UNKNOWN").toUpperCase();
  return `<span class="sev sev-${s.toLowerCase()}">${esc(s)}</span>`;
}

const CAT_LABEL = { deps: "Dependencies", secrets: "Secrets", iac: "Infrastructure as Code", sast: "Static code" };

// 入口:ci 结果 → 完整 HTML 文档(纯函数,可单测)
export function renderHtml(result, { now = new Date().toISOString() } = {}) {
  const g = result.gate || { passed: true, failOn: "HIGH", reasons: [] };
  const s = result.summary || { total: 0, bySeverity: {} };
  const sevLine = Object.entries(s.bySeverity || {})
    .sort((a, b) => (SEV_RANK[b[0]] ?? 0) - (SEV_RANK[a[0]] ?? 0))
    .map(([k, v]) => `${esc(k)} ${v}`).join(" · ");

  const sections = [];
  for (const [kind, cat] of Object.entries(result.categories || {})) {
    const label = CAT_LABEL[kind] || kind;
    if (!cat || cat.ok === false) {
      sections.push(`<section><h2>${esc(label)} <span class="skip">skipped</span></h2></section>`);
      continue;
    }
    const findings = (cat.findings || []).slice().sort((a, b) => (SEV_RANK[b.severity] ?? 0) - (SEV_RANK[a.severity] ?? 0));
    if (!findings.length) {
      sections.push(`<section><h2>${esc(label)} <span class="ok">0 findings</span></h2></section>`);
      continue;
    }
    const rows = findings.map((f) => {
      const r = findingRow(kind, f);
      return `<tr><td>${badge(r.severity)}</td><td class="name">${esc(r.name)}</td><td class="meta">${esc(r.meta)}</td><td class="loc">${esc(r.location)}</td></tr>`;
    }).join("\n");
    sections.push(
      `<section><h2>${esc(label)} <span class="count">${findings.length}</span></h2>` +
      `<table><thead><tr><th>Severity</th><th>Finding</th><th>Detail</th><th>Location</th></tr></thead><tbody>${rows}</tbody></table></section>`,
    );
  }

  const gateClass = g.passed ? "pass" : "fail";
  const gateText = g.passed ? "✓ GATE PASSED" : "✗ GATE FAILED";
  const reasons = (g.reasons || []).map((r) => `<li>${esc(r)}</li>`).join("");
  const suppressed = result.policy && result.policy.suppressed
    ? `<div class="suppressed">${result.policy.suppressed} suppressed by policy</div>` : "";

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Break Anything — security report</title>
<style>
:root{color-scheme:light dark}
body{font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;background:#0d1117;color:#e6edf3}
.wrap{max-width:960px;margin:0 auto;padding:32px 20px}
h1{font-size:22px;margin:0 0 4px} .target{color:#8b949e;font-family:ui-monospace,monospace;margin-bottom:20px}
.gate{font-size:18px;font-weight:700;padding:12px 16px;border-radius:8px;margin:16px 0}
.gate.pass{background:#12261a;color:#3fb950;border:1px solid #238636}
.gate.fail{background:#2a1416;color:#f85149;border:1px solid #da3633}
.gate .foc{font-weight:400;font-size:13px;color:#8b949e}
ul.reasons{margin:8px 0 0;padding-left:20px;color:#f0a3a0} ul.reasons li{margin:2px 0}
.summary{color:#8b949e;margin:12px 0 4px} .suppressed{color:#8b949e;font-size:13px;margin-bottom:8px}
section{margin:22px 0} h2{font-size:15px;border-bottom:1px solid #30363d;padding-bottom:6px}
h2 .count{color:#8b949e;font-weight:400} h2 .skip,h2 .ok{color:#8b949e;font-weight:400;font-size:13px}
table{width:100%;border-collapse:collapse;margin-top:8px} th{text-align:left;color:#8b949e;font-weight:600;font-size:12px;padding:6px 8px}
td{padding:6px 8px;border-top:1px solid #21262d;vertical-align:top} td.name{font-weight:600} td.meta,td.loc{color:#8b949e}
.sev{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:700}
.sev-critical,.sev-high{background:#da3633;color:#fff} .sev-medium{background:#9e6a03;color:#fff}
.sev-low{background:#1f6feb;color:#fff} .sev-unknown,.sev-moderate{background:#6e7681;color:#fff}
footer{color:#6e7681;font-size:12px;margin-top:32px;border-top:1px solid #21262d;padding-top:12px}
footer a{color:#8b949e}
</style></head>
<body><div class="wrap">
<h1>Break Anything — security report</h1>
<div class="target">${esc(result.target || "")}</div>
<div class="gate ${gateClass}">${gateText} <span class="foc">(fail-on ${esc(g.failOn || "HIGH")})</span></div>
${reasons ? `<ul class="reasons">${reasons}</ul>` : ""}
<div class="summary">${s.total || 0} findings${sevLine ? " · " + sevLine : ""}</div>
${suppressed}
${sections.join("\n")}
<footer>Generated by <a href="https://github.com/EnkiHQ/break-anything">break-anything</a> v${TOOL_VERSION} · ${esc(now)}</footer>
</div></body></html>`;
}
