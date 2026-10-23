// 人类可读报告(终端)。不依赖任何第三方 UI 库。

const C = {
  reset: "\x1b[0m", bold: "\x1b[1m", dim: "\x1b[2m",
  red: "\x1b[31m", yellow: "\x1b[33m", green: "\x1b[32m", cyan: "\x1b[36m", gray: "\x1b[90m",
};

const SEV_COLOR = { CRITICAL: C.red, HIGH: C.red, MEDIUM: C.yellow, LOW: C.cyan, UNKNOWN: C.gray };
const REACH_LABEL = {
  imported: "reachable(已被引用)",
  direct: "direct(直接依赖)",
  transitive: "transitive(传递依赖)",
  unknown: "—",
};

export function renderHuman(result, { color = true } = {}) {
  const c = color ? C : new Proxy({}, { get: () => "" });
  const lines = [];

  if (!result.ok) {
    lines.push(`${c.yellow}${result.message}${c.reset}`);
    lines.push(`${c.gray}目标:${result.target}${c.reset}`);
    return lines.join("\n");
  }

  const srcDesc = result.sources.map((s) => `${s.ecosystem}:${s.packages}`).join("  ");
  lines.push(`${c.bold}Break Anything · 依赖扫描${c.reset}`);
  lines.push(`${c.gray}目标 ${result.target}  ·  已扫 ${result.scanned} 个包  ·  来源 ${srcDesc}${c.reset}`);
  lines.push("");

  if (!result.findings.length) {
    lines.push(`${c.green}✓ 未在已知漏洞库(OSV)中发现匹配的漏洞。${c.reset}`);
    lines.push(`${c.gray}  注意:这表示"未发现",不等于"安全"。${c.reset}`);
    return lines.join("\n");
  }

  for (const f of result.findings) {
    const sev = `${SEV_COLOR[f.severity] || ""}${f.severity.padEnd(8)}${c.reset}`;
    const idLabel = f.cve || f.id;
    const epss = f.epss != null ? `EPSS ${(f.epss * 100).toFixed(1)}%` : "EPSS —";
    const fix = f.fixedVersions.length ? `${c.green}修复→ ${f.fixedVersions.join(", ")}${c.reset}` : `${c.red}无修复版本${c.reset}`;
    lines.push(`${sev} ${c.bold}${f.package}@${f.version}${c.reset} ${c.gray}(${f.ecosystem})${c.reset}`);
    lines.push(`  ${c.cyan}${idLabel}${c.reset}  ·  ${REACH_LABEL[f.reachability]}  ·  ${epss}  ·  ${fix}`);
    if (f.summary) lines.push(`  ${c.gray}${f.summary.replace(/\s+/g, " ").slice(0, 120)}${c.reset}`);
    lines.push("");
  }

  const s = result.summary;
  const sevParts = Object.entries(s.bySeverity)
    .sort((a, b) => sevOrder(b[0]) - sevOrder(a[0]))
    .map(([k, v]) => `${k} ${v}`)
    .join("  ");
  lines.push(`${c.bold}小结${c.reset} 共 ${s.total} 条  ·  可达(已引用) ${s.reachable} 条  ·  ${sevParts}`);
  if (result.errors?.length) {
    lines.push(`${c.gray}（${result.errors.length} 个包查询失败,已跳过）${c.reset}`);
  }
  lines.push(`${c.gray}可达性为启发式(判断是否被引用),非漏洞函数被调用的证明。${c.reset}`);
  return lines.join("\n");
}

function sevOrder(k) {
  return { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 }[k] ?? 0;
}

// ---- 密钥扫描报告 ----
export function renderSecrets(result, { color = true } = {}) {
  const c = color ? C : new Proxy({}, { get: () => "" });
  const lines = [];
  lines.push(`${c.bold}Break Anything · 密钥扫描${c.reset}`);
  lines.push(`${c.gray}目标 ${result.target}  ·  历史扫描 ${result.historyScanned ? "开" : "关"}${c.reset}`);
  lines.push("");

  if (!result.findings.length) {
    lines.push(`${c.green}✓ 未发现疑似泄露的密钥。${c.reset}`);
    lines.push(`${c.gray}  注意:这表示"未发现",不等于"没有"。${c.reset}`);
    return lines.join("\n");
  }

  for (const f of result.findings) {
    const sev = `${SEV_COLOR[f.severity] || ""}${f.severity.padEnd(8)}${c.reset}`;
    const loc = f.source === "history"
      ? `${c.yellow}git 历史${c.reset} ${c.gray}@${f.commit}${c.reset}`
      : `${f.location}${f.line ? `:${f.line}` : ""}`;
    lines.push(`${sev} ${c.bold}${f.rule}${c.reset}`);
    lines.push(`  ${loc}  ·  ${c.gray}${f.match}${c.reset}`);
  }
  lines.push("");
  const s = result.summary;
  const parts = Object.entries(s.bySeverity).sort((a, b) => sevOrder(b[0]) - sevOrder(a[0])).map(([k, v]) => `${k} ${v}`).join("  ");
  lines.push(`${c.bold}小结${c.reset} 共 ${s.total} 条  ·  历史中 ${s.inHistory} 条  ·  ${parts}`);
  if (s.inHistory) lines.push(`${c.yellow}历史里的密钥即使已删除也可能仍然有效 —— 请轮换(rotate),不要只删提交。${c.reset}`);
  return lines.join("\n");
}

// ---- 镜像扫描报告 ----
export function renderImage(result, { color = true } = {}) {
  const c = color ? C : new Proxy({}, { get: () => "" });
  const lines = [];
  lines.push(`${c.bold}Break Anything · 镜像扫描${c.reset} ${c.gray}(${result.engine})${c.reset}`);

  if (!result.ok) {
    lines.push("");
    lines.push(`${c.yellow}${result.message}${c.reset}`);
    return lines.join("\n");
  }

  lines.push(`${c.gray}目标 ${result.target}${c.reset}`);
  lines.push("");
  if (!result.findings.length) {
    lines.push(`${c.green}✓ 未在镜像中发现已知漏洞。${c.reset}`);
    return lines.join("\n");
  }
  for (const f of result.findings.slice(0, 40)) {
    const sev = `${SEV_COLOR[f.severity] || ""}${f.severity.padEnd(8)}${c.reset}`;
    const fix = f.fixedVersions.length ? `${c.green}修复→ ${f.fixedVersions.join(", ")}${c.reset}` : `${c.red}无修复${c.reset}`;
    lines.push(`${sev} ${c.bold}${f.package}@${f.version}${c.reset} ${c.cyan}${f.cve || f.id}${c.reset}  ${fix}  ${c.gray}[${f.class}]${c.reset}`);
  }
  if (result.findings.length > 40) lines.push(`${c.gray}… 还有 ${result.findings.length - 40} 条,用 --json 查看全部${c.reset}`);
  lines.push("");
  const s = result.summary;
  const parts = Object.entries(s.bySeverity).sort((a, b) => sevOrder(b[0]) - sevOrder(a[0])).map(([k, v]) => `${k} ${v}`).join("  ");
  lines.push(`${c.bold}小结${c.reset} 共 ${s.total} 条  ·  可修复 ${s.fixable} 条  ·  ${parts}`);
  return lines.join("\n");
}
