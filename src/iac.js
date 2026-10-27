// 基础设施即代码(IaC)配置扫描 —— 纯 Node 内置实现,零额外安装。
// 聚焦最常见、最高影响的错误配置:Dockerfile、Kubernetes 清单、Terraform(HCL)。
//
// 诚实边界:这是一组精选的高价值规则,不是 Checkov/Trivy/KICS 那样的完整策略即代码。
// 完整策略覆盖在路线图上(可选接入外部引擎)。每条发现都给出文件:行号 + 证据 + 修复建议。

import fs from "node:fs";
import path from "node:path";

const SEV = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
function sevRank(s) { return SEV[s] ?? 0; }
function countBy(arr, key) { const m = {}; for (const x of arr) m[x[key]] = (m[x[key]] || 0) + 1; return m; }

// ---- 文件归类(纯函数,可单测)----
export function classifyIac(filename, content = "") {
  const base = path.basename(filename).toLowerCase();
  if (base === "dockerfile" || base.startsWith("dockerfile.") || base.endsWith(".dockerfile")) return "dockerfile";
  if (base.endsWith(".tf")) return "terraform";
  if (base.endsWith(".yaml") || base.endsWith(".yml")) {
    if (/^\s*apiVersion:/m.test(content) && /^\s*kind:\s*\S/m.test(content)) return "kubernetes";
  }
  return null;
}

function finding(f) { return { kind: f.kind, rule: f.rule, severity: f.severity, title: f.title, cwe: f.cwe || null, location: f.location, evidence: f.evidence, remediation: f.remediation }; }
function lineAt(lines, idx, file) { return `${file}:${idx + 1}`; }
function snip(s) { return (s || "").trim().replace(/\s+/g, " ").slice(0, 120); }

// ---- Dockerfile(纯函数,可单测)----
export function scanDockerfile(content, file = "Dockerfile") {
  const lines = content.split(/\r?\n/);
  const out = [];
  let firstFrom = -1;
  let hasUser = false;

  lines.forEach((raw, i) => {
    const line = raw.trim();
    if (/^FROM\s+/i.test(line)) {
      if (firstFrom < 0) firstFrom = i;
      const img = (line.match(/^FROM\s+(\S+)/i) || [])[1] || "";
      if (/:latest$/i.test(img)) {
        out.push(finding({ kind: "dockerfile", rule: "docker-latest-tag", severity: "MEDIUM", cwe: "CWE-1104",
          title: "Base image pinned to :latest", location: lineAt(lines, i, file), evidence: snip(line),
          remediation: "Pin to an explicit version or a digest (image@sha256:...) for reproducible, auditable builds." }));
      }
    }
    if (/^USER\s+/i.test(line)) {
      hasUser = true;
      if (/^USER\s+root\b/i.test(line)) {
        out.push(finding({ kind: "dockerfile", rule: "docker-user-root", severity: "MEDIUM", cwe: "CWE-250",
          title: "Container explicitly runs as root", location: lineAt(lines, i, file), evidence: snip(line),
          remediation: "Create and switch to a non-root user (USER appuser) to limit blast radius." }));
      }
    }
    if (/(curl|wget)\s+[^\n|]*\|\s*(sudo\s+)?(sh|bash)\b/i.test(line)) {
      out.push(finding({ kind: "dockerfile", rule: "docker-remote-pipe-shell", severity: "HIGH", cwe: "CWE-494",
        title: "Remote script piped straight into a shell", location: lineAt(lines, i, file), evidence: snip(line),
        remediation: "Download, verify a checksum/signature, then execute — don't pipe network content into sh." }));
    }
    if (/^ADD\s+https?:\/\//i.test(line)) {
      out.push(finding({ kind: "dockerfile", rule: "docker-add-remote", severity: "MEDIUM", cwe: "CWE-494",
        title: "ADD fetches a remote URL", location: lineAt(lines, i, file), evidence: snip(line),
        remediation: "Prefer COPY for local files; for remote content, fetch and verify its integrity explicitly." }));
    }
    const sec = line.match(/^(ENV|ARG)\s+([A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY)[A-Z0-9_]*)\s*[= ]\s*(\S+)/i);
    if (sec && !/^\$\{?/.test(sec[3]) && !/^["']?\s*["']?$/.test(sec[3])) {
      out.push(finding({ kind: "dockerfile", rule: "docker-hardcoded-secret", severity: "HIGH", cwe: "CWE-798",
        title: `Hardcoded secret in ${sec[1].toUpperCase()} ${sec[2]}`, location: lineAt(lines, i, file),
        evidence: `${sec[1].toUpperCase()} ${sec[2]}=<redacted>`,
        remediation: "Never bake secrets into image layers (they persist in history). Inject at runtime via a secrets manager." }));
    }
  });

  if (firstFrom >= 0 && !hasUser) {
    out.push(finding({ kind: "dockerfile", rule: "docker-no-user", severity: "MEDIUM", cwe: "CWE-250",
      title: "No USER instruction — container runs as root", location: lineAt(lines, firstFrom, file),
      evidence: snip(lines[firstFrom]),
      remediation: "Add a non-root USER before the entrypoint so the process doesn't run with root privileges." }));
  }
  return out;
}

// ---- Kubernetes 清单(纯函数,可单测)----
const K8S_LINE_RULES = [
  { re: /\bprivileged:\s*true\b/, rule: "k8s-privileged", severity: "HIGH", cwe: "CWE-250",
    title: "Privileged container", rem: "Set privileged: false; grant only the specific capabilities actually needed." },
  { re: /\ballowPrivilegeEscalation:\s*true\b/, rule: "k8s-privilege-escalation", severity: "MEDIUM", cwe: "CWE-250",
    title: "allowPrivilegeEscalation enabled", rem: "Set allowPrivilegeEscalation: false in the container securityContext." },
  { re: /\bhostNetwork:\s*true\b/, rule: "k8s-host-network", severity: "HIGH", cwe: "CWE-668",
    title: "Pod shares the host network", rem: "Remove hostNetwork: true unless strictly required; it exposes the node network." },
  { re: /\bhostPID:\s*true\b/, rule: "k8s-host-pid", severity: "HIGH", cwe: "CWE-668",
    title: "Pod shares the host PID namespace", rem: "Remove hostPID: true to keep process isolation from the node." },
  { re: /\bhostIPC:\s*true\b/, rule: "k8s-host-ipc", severity: "HIGH", cwe: "CWE-668",
    title: "Pod shares the host IPC namespace", rem: "Remove hostIPC: true to keep IPC isolation from the node." },
  { re: /\brunAsNonRoot:\s*false\b/, rule: "k8s-run-as-root", severity: "MEDIUM", cwe: "CWE-250",
    title: "Container allowed to run as root", rem: "Set runAsNonRoot: true (and a non-zero runAsUser)." },
  { re: /^\s*-?\s*(SYS_ADMIN|NET_ADMIN|ALL)\s*$/, rule: "k8s-dangerous-capability", severity: "HIGH", cwe: "CWE-250",
    title: "Dangerous Linux capability added", rem: "Drop ALL capabilities and add back only the minimal set the workload needs." },
];

export function scanKubernetes(content, file = "manifest.yaml") {
  const lines = content.split(/\r?\n/);
  const out = [];
  lines.forEach((raw, i) => {
    const line = raw.replace(/#.*$/, "");
    for (const r of K8S_LINE_RULES) {
      if (r.re.test(line)) {
        out.push(finding({ kind: "kubernetes", rule: r.rule, severity: r.severity, cwe: r.cwe,
          title: r.title, location: lineAt(lines, i, file), evidence: snip(raw), remediation: r.rem }));
      }
    }
    const img = line.match(/^\s*-?\s*image:\s*["']?([^"'\s]+)["']?\s*$/);
    if (img && /:latest$/i.test(img[1])) {
      out.push(finding({ kind: "kubernetes", rule: "k8s-latest-tag", severity: "LOW", cwe: "CWE-1104",
        title: "Container image pinned to :latest", location: lineAt(lines, i, file), evidence: snip(raw),
        remediation: "Pin the image to an explicit version or digest for reproducible, rollback-able deploys." }));
    }
  });
  return out;
}

// ---- Terraform / HCL(纯函数,可单测)----
export function scanTerraform(content, file = "main.tf") {
  const lines = content.split(/\r?\n/);
  const out = [];
  lines.forEach((raw, i) => {
    const line = raw.replace(/#.*$|\/\/.*$/, "");
    if (/0\.0\.0\.0\/0/.test(line) && /cidr/i.test(line)) {
      out.push(finding({ kind: "terraform", rule: "tf-open-cidr", severity: "HIGH", cwe: "CWE-284",
        title: "CIDR open to the entire internet (0.0.0.0/0)", location: lineAt(lines, i, file), evidence: snip(raw),
        remediation: "Restrict the CIDR to known source ranges; 0.0.0.0/0 on an ingress rule exposes the resource publicly." }));
    }
    if (/\bacl\s*=\s*"public-read(-write)?"/i.test(line)) {
      out.push(finding({ kind: "terraform", rule: "tf-public-bucket", severity: "HIGH", cwe: "CWE-732",
        title: "Storage ACL is publicly readable", location: lineAt(lines, i, file), evidence: snip(raw),
        remediation: "Set the ACL to private and use signed URLs or explicit policies for controlled access." }));
    }
    if (/\bencrypted\s*=\s*false\b/i.test(line)) {
      out.push(finding({ kind: "terraform", rule: "tf-unencrypted", severity: "MEDIUM", cwe: "CWE-311",
        title: "Encryption at rest disabled", location: lineAt(lines, i, file), evidence: snip(raw),
        remediation: "Set encrypted = true (and provide a KMS key where applicable)." }));
    }
    const sec = line.match(/\b([a-z0-9_]*(?:password|secret|private_key|access_key|secret_key|token)[a-z0-9_]*)\s*=\s*"([^"]{3,})"/i);
    if (sec && !/\$\{/.test(sec[2]) && !/^var\./.test(sec[2])) {
      out.push(finding({ kind: "terraform", rule: "tf-hardcoded-secret", severity: "HIGH", cwe: "CWE-798",
        title: `Hardcoded secret in "${sec[1]}"`, location: lineAt(lines, i, file), evidence: `${sec[1]} = <redacted>`,
        remediation: "Reference a variable or a secrets manager (Vault / SSM / Secrets Manager) instead of a literal." }));
    }
  });
  return out;
}

const SCANNERS = { dockerfile: scanDockerfile, kubernetes: scanKubernetes, terraform: scanTerraform };
const SKIP_DIRS = new Set([".git", "node_modules", "vendor", ".terraform", "dist", "build", ".next", "__pycache__"]);
const MAX_FILES = 2000;
const MAX_BYTES = 1_000_000;

function walk(dir, acc) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (acc.length >= MAX_FILES) return;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) walk(full, acc); }
    else if (e.isFile()) acc.push(full);
  }
}

export async function scanIac(target) {
  let stat;
  try { stat = fs.statSync(target); }
  catch { return { target, ok: false, engine: "iac", message: `路径不存在:${target}`, findings: [], summary: { total: 0, bySeverity: {} } }; }

  const files = [];
  if (stat.isDirectory()) walk(target, files);
  else files.push(target);

  const findings = [];
  let scanned = 0;
  const byType = {};
  for (const f of files) {
    let content;
    try {
      if (fs.statSync(f).size > MAX_BYTES) continue;
      content = fs.readFileSync(f, "utf8");
    } catch { continue; }
    const kind = classifyIac(f, content);
    if (!kind) continue;
    scanned++;
    byType[kind] = (byType[kind] || 0) + 1;
    const rel = path.relative(stat.isDirectory() ? target : path.dirname(target), f) || path.basename(f);
    findings.push(...SCANNERS[kind](content, rel));
  }

  findings.sort((a, b) => sevRank(b.severity) - sevRank(a.severity));
  return {
    target, ok: true, engine: "iac",
    scanned, byType,
    findings,
    summary: { total: findings.length, bySeverity: countBy(findings, "severity") },
  };
}
