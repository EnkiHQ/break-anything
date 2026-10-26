import { spawn } from "node:child_process";

// 静态代码分析(SAST):封装 Semgrep。装了 semgrep 就能用,没装给安装提示。
// 把 Semgrep 的 JSON 归一化成 Break Anything 统一的发现结构。
// 默认规则集 p/security-audit(首次运行会从 Semgrep registry 拉取并缓存,需联网)。

export async function scanSast(path, { config = "p/security-audit" } = {}) {
  const semgrep = await which("semgrep");
  if (!semgrep) {
    return {
      target: path,
      ok: false,
      engine: "semgrep",
      message:
        "未找到 semgrep。SAST 依赖 Semgrep。安装:\n" +
        "  pipx install semgrep   (或 brew install semgrep)\n" +
        "  文档:https://semgrep.dev/docs/getting-started/",
      findings: [],
      summary: { total: 0, bySeverity: {} },
    };
  }

  let raw;
  try {
    raw = await run(semgrep, ["--json", "--quiet", "--config", config, "--timeout", "0", path]);
  } catch (err) {
    return {
      target: path,
      ok: false,
      engine: "semgrep",
      message: `semgrep 执行失败:${err instanceof Error ? err.message : String(err)}`,
      findings: [],
      summary: { total: 0, bySeverity: {} },
    };
  }
  return normalizeSemgrep(raw, path);
}

// 导出以便单测:把 semgrep JSON 文本归一化
export function normalizeSemgrep(rawJson, target) {
  let data;
  try { data = typeof rawJson === "string" ? JSON.parse(rawJson) : rawJson; }
  catch { return { target, ok: false, engine: "semgrep", message: "无法解析 semgrep 输出", findings: [], summary: { total: 0, bySeverity: {} } }; }

  const findings = [];
  for (const r of data.results || []) {
    const sev = mapSeverity(r.extra?.severity);
    const meta = r.extra?.metadata || {};
    findings.push({
      rule: shortRule(r.check_id),
      id: r.check_id,
      severity: sev,
      location: `${r.path}:${r.start?.line ?? "?"}`,
      message: (r.extra?.message || "").replace(/\s+/g, " ").trim(),
      cwe: toArray(meta.cwe),
      owasp: toArray(meta.owasp),
      confidence: meta.confidence || null,
      snippet: (r.extra?.lines || "").trim().slice(0, 200),
      references: toArray(meta.references).slice(0, 3),
    });
  }
  findings.sort((a, b) => sevRank(b.severity) - sevRank(a.severity));

  return {
    target,
    ok: true,
    engine: "semgrep",
    scanned: data.paths?.scanned?.length ?? undefined,
    errors: (data.errors || []).length,
    findings,
    summary: { total: findings.length, bySeverity: countBy(findings, "severity") },
  };
}

// Semgrep: ERROR / WARNING / INFO → 我们的严重度
function mapSeverity(s) {
  switch ((s || "").toUpperCase()) {
    case "ERROR": return "HIGH";
    case "WARNING": return "MEDIUM";
    case "INFO": return "LOW";
    default: return "UNKNOWN";
  }
}

function shortRule(id) {
  if (!id) return "rule";
  const parts = id.split(".");
  return parts.slice(-2).join(".");
}

function toArray(v) {
  if (v == null) return [];
  return Array.isArray(v) ? v : [v];
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

function run(cmd, args) {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    let err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));
    p.on("close", (code) => {
      // semgrep: 0 = 无发现, 1 = 有发现, 其它 = 错误
      if (code === 0 || code === 1 || out.trim().startsWith("{")) resolve(out);
      else reject(new Error(err.trim().slice(0, 300) || `exit ${code}`));
    });
    p.on("error", reject);
  });
}

const SEV = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
function sevRank(s) { return SEV[s] ?? 0; }
function countBy(arr, key) {
  const m = {};
  for (const x of arr) m[x[key]] = (m[x[key]] || 0) + 1;
  return m;
}
