// Nuclei 集成:把 ProjectDiscovery 的社区模板库(数千条检测)接进来,一次性拉满 DAST 广度。
// 封装 nuclei 的 JSONL 输出并归一化成 Break Anything 统一发现结构。
//
// 安全红线:这是会向目标发真实请求的动态能力,沿用 api 那套闸门——
// 必须 BRK_DYNAMIC_ENABLED=true 且目标在 BRK_AUTHORIZED_TARGETS_JSON 白名单内。
// 没装 nuclei 时优雅降级并给安装提示。

import { spawn } from "node:child_process";
import { checkAuthorization } from "./api.js";

const SEV = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
function sevRank(s) { return SEV[s] ?? 0; }
function countBy(arr, key) { const m = {}; for (const x of arr) m[x[key]] = (m[x[key]] || 0) + 1; return m; }

// nuclei 的 info.severity:critical/high/medium/low/info/unknown → 我们的严重度
export function mapNucleiSeverity(s) {
  switch (String(s || "").toLowerCase()) {
    case "critical": return "CRITICAL";
    case "high": return "HIGH";
    case "medium": return "MEDIUM";
    case "low": return "LOW";
    case "info": return "LOW";
    default: return "UNKNOWN";
  }
}

// 把 nuclei 的 JSONL 文本归一化(纯函数,可单测)
export function normalizeNuclei(rawJsonl, target) {
  const findings = [];
  for (const line of String(rawJsonl || "").split(/\r?\n/)) {
    const t = line.trim();
    if (!t || !t.startsWith("{")) continue;
    let r;
    try { r = JSON.parse(t); } catch { continue; }
    const info = r.info || {};
    const classification = info.classification || {};
    const cves = [].concat(classification["cve-id"] || []).filter(Boolean);
    findings.push({
      rule: r["template-id"] || info.name || "nuclei",
      title: info.name || r["template-id"] || "Nuclei detection",
      severity: mapNucleiSeverity(info.severity),
      cve: cves[0] ? String(cves[0]).toUpperCase() : null,
      cwe: [].concat(classification["cwe-id"] || []).filter(Boolean),
      location: r["matched-at"] || r.host || target,
      type: r.type || null,
      evidence: {
        request: r["matched-at"] || r.host || "",
        matcher: r["matcher-name"] || null,
        extracted: Array.isArray(r["extracted-results"]) ? r["extracted-results"].slice(0, 3) : [],
      },
      reference: [].concat(info.reference || []).filter(Boolean).slice(0, 3),
      remediation: info.remediation || null,
    });
  }
  findings.sort((a, b) => sevRank(b.severity) - sevRank(a.severity));
  return {
    target, ok: true, engine: "nuclei",
    findings,
    summary: { total: findings.length, bySeverity: countBy(findings, "severity") },
  };
}

function which(cmd) {
  return new Promise((resolve) => {
    const p = spawn(process.platform === "win32" ? "where" : "which", [cmd], { stdio: ["ignore", "pipe", "ignore"] });
    let out = "";
    p.stdout.on("data", (d) => (out += d));
    p.on("close", (code) => resolve(code === 0 ? out.trim().split("\n")[0] : null));
    p.on("error", () => resolve(null));
  });
}

function run(cmd, args, timeoutMs = 300000) {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"] });
    let out = "", err = "";
    const timer = setTimeout(() => { p.kill("SIGKILL"); reject(new Error("nuclei 超时")); }, timeoutMs);
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));
    p.on("close", (code) => { clearTimeout(timer); resolve({ out, err, code }); });
    p.on("error", (e) => { clearTimeout(timer); reject(e); });
  });
}

// nuclei 可能"成功退出但其实没跑"(例如模板库没装)。这种情况绝不能报成"未发现问题"。
// 从 stderr 里识别致命错误(纯函数,可单测)。
export function detectNucleiFailure(stderr, code) {
  const s = String(stderr || "");
  if (/\[FTL\]/.test(s) || /no templates provided/i.test(s) || /could not find template/i.test(s)) {
    const line = (s.match(/\[FTL\][^\n]*/) || s.match(/\[ERR\][^\n]*/) || [])[0] || "nuclei 未能执行扫描";
    return line.replace(/\s+/g, " ").trim().slice(0, 240);
  }
  if (code != null && code !== 0) return `nuclei 退出码 ${code}`;
  return null;
}

// 入口:对一个已授权的 URL 跑 nuclei
export async function scanNuclei(targetUrl, { severity, templates, timeoutMs = 300000, env = process.env } = {}) {
  const gate = checkAuthorization(targetUrl, env);
  if (!gate.allowed) {
    return { target: targetUrl, ok: false, engine: "nuclei", gated: true, message: gate.reason, findings: [], summary: { total: 0, bySeverity: {} } };
  }

  const bin = await which("nuclei");
  if (!bin) {
    return {
      target: targetUrl, ok: false, engine: "nuclei",
      message:
        "未找到 nuclei。本能力依赖 ProjectDiscovery Nuclei。安装:\n" +
        "  brew install nuclei\n" +
        "  或 go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n" +
        "  文档:https://docs.projectdiscovery.io/tools/nuclei/install",
      findings: [], summary: { total: 0, bySeverity: {} },
    };
  }

  const args = ["-target", targetUrl, "-jsonl", "-silent", "-no-interactsh", "-disable-update-check"];
  if (severity) args.push("-severity", severity);
  if (templates) args.push("-t", templates);

  let res;
  try { res = await run(bin, args, timeoutMs); }
  catch (e) {
    return { target: targetUrl, ok: false, engine: "nuclei", message: `nuclei 执行失败:${e instanceof Error ? e.message : String(e)}`, findings: [], summary: { total: 0, bySeverity: {} } };
  }

  // 没有任何发现时,先确认 nuclei 真的跑起来了,否则如实报错(绝不把"没跑"说成"没问题")
  const failure = detectNucleiFailure(res.err, res.code);
  if (failure && !String(res.out || "").trim()) {
    return {
      target: targetUrl, ok: false, engine: "nuclei",
      message: `nuclei 未能完成扫描:${failure}\n提示:首次使用需先执行 nuclei -update-templates 安装模板库。`,
      findings: [], summary: { total: 0, bySeverity: {} },
    };
  }
  return normalizeNuclei(res.out, targetUrl);
}
