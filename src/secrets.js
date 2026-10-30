import { readdir, readFile, stat } from "node:fs/promises";
import { spawn } from "node:child_process";
import path from "node:path";

// 密钥扫描:工作区文件 + 可选 git 历史。全部本地完成,不联网。
// 命中的密钥在输出里脱敏,只保留头尾几位。

const RULES = [
  { id: "aws-access-key-id", severity: "HIGH", re: /\bAKIA[0-9A-Z]{16}\b/ },
  { id: "aws-secret-access-key", severity: "CRITICAL", re: /aws_secret_access_key\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/i },
  { id: "github-token", severity: "HIGH", re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { id: "gitlab-pat", severity: "HIGH", re: /\bglpat-[A-Za-z0-9_-]{20,}\b/ },
  { id: "slack-token", severity: "HIGH", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { id: "google-api-key", severity: "HIGH", re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { id: "stripe-secret-key", severity: "CRITICAL", re: /\bsk_live_[0-9a-zA-Z]{24,}\b/ },
  { id: "openai-key", severity: "HIGH", re: /\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b/ },
  { id: "private-key", severity: "CRITICAL", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/ },
  { id: "jwt", severity: "MEDIUM", re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
  { id: "generic-assigned-secret", severity: "MEDIUM", re: /(?:password|passwd|secret|api[_-]?key|token)\s*[=:]\s*['"]([^'"\s]{12,})['"]/i },
];

const SKIP_DIR = new Set(["node_modules", ".git", "dist", "build", "vendor", ".venv", "venv", "__pycache__"]);
const SKIP_EXT = new Set([".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".zip", ".gz", ".lock", ".min.js", ".map"]);
const MAX_FILE_BYTES = 1_000_000;

export async function scanSecrets(targetPath, { history = false, verify = false } = {}) {
  const dir = await resolveDir(targetPath);
  const findings = [];

  // 1) 工作区文件
  const files = [];
  await collect(dir, files, 0);
  for (const f of files) {
    let text;
    try {
      const s = await stat(f);
      if (s.size > MAX_FILE_BYTES) continue;
      text = await readFile(f, "utf8");
    } catch { continue; }
    scanText(text, { location: path.relative(dir, f), source: "worktree" }, findings);
  }

  // 2) git 历史(可选)
  let historyScanned = false;
  if (history) {
    const hit = await scanGitHistory(dir, findings);
    historyScanned = hit.ok;
  }

  dedupe(findings);
  findings.sort((a, b) => sevRank(b.severity) - sevRank(a.severity));

  // 存活验证(可选,会联网)。无论开不开,都必须保证 __raw 不出现在返回值里。
  let verification = null;
  if (verify) {
    const { verifyFindings, summarizeVerification } = await import("./verify.js");
    await verifyFindings(findings);           // 内部用完即删 __raw
    verification = summarizeVerification(findings);
  } else {
    for (const f of findings) delete f.__raw;
  }

  return {
    target: dir,
    ok: true,
    historyScanned,
    verified: !!verify,
    findings,
    summary: {
      total: findings.length,
      bySeverity: countBy(findings, "severity"),
      inHistory: findings.filter((f) => f.source === "history").length,
      ...(verification ? { verification } : {}),
    },
  };
}

function scanText(text, meta, findings) {
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length > 500) continue; // 跳过超长压缩行
    for (const rule of RULES) {
      const m = rule.re.exec(line);
      if (!m) continue;
      const raw = m[1] || m[0];
      findings.push({
        rule: rule.id,
        severity: rule.severity,
        location: meta.location,
        line: meta.source === "worktree" ? i + 1 : null,
        source: meta.source,
        commit: meta.commit || null,
        match: redact(raw),
        // 原始值仅在开启 --verify 时于内存中短暂使用,验证完立即删除,绝不进入输出
        __raw: raw,
      });
    }
  }
}

function redact(s) {
  if (s.length <= 8) return "****";
  return `${s.slice(0, 4)}…${s.slice(-4)} (${s.length} chars)`;
}

// 用 git log -p 读历史 diff,有字节上限,防止超大仓库卡死
function scanGitHistory(dir, findings) {
  return new Promise((resolve) => {
    const child = spawn("git", ["-C", dir, "log", "-p", "--all", "-U0", "--no-color"], {
      stdio: ["ignore", "pipe", "ignore"],
    });
    let buf = "";
    let bytes = 0;
    let commit = null;
    const CAP = 8_000_000;
    child.stdout.on("data", (chunk) => {
      bytes += chunk.length;
      buf += chunk.toString("utf8");
      const lines = buf.split("\n");
      buf = lines.pop() || "";
      for (const line of lines) {
        const cm = line.match(/^commit ([0-9a-f]{7,40})/);
        if (cm) { commit = cm[1].slice(0, 10); continue; }
        if (line.startsWith("+") && !line.startsWith("+++")) {
          scanText(line.slice(1), { location: "(git history)", source: "history", commit }, findings);
        }
      }
      if (bytes > CAP) child.kill();
    });
    child.on("close", () => resolve({ ok: true }));
    child.on("error", () => resolve({ ok: false }));
  });
}

function dedupe(findings) {
  const seen = new Set();
  for (let i = findings.length - 1; i >= 0; i--) {
    const f = findings[i];
    const key = `${f.rule}|${f.match}|${f.source}|${f.location}`;
    if (seen.has(key)) findings.splice(i, 1);
    else seen.add(key);
  }
}

async function resolveDir(p) {
  const s = await stat(p);
  return s.isDirectory() ? p : path.dirname(p);
}

async function collect(dir, out, depth) {
  if (depth > 8 || out.length > 8000) return;
  let entries;
  try { entries = await readdir(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (SKIP_DIR.has(e.name) || e.name.startsWith(".")) continue;
      await collect(full, out, depth + 1);
    } else {
      const ext = path.extname(e.name).toLowerCase();
      if (SKIP_EXT.has(ext)) continue;
      out.push(full);
    }
  }
}

const SEV = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
function sevRank(s) { return SEV[s] ?? 0; }
function countBy(arr, key) {
  const m = {};
  for (const x of arr) m[x[key]] = (m[x[key]] || 0) + 1;
  return m;
}
