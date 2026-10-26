// Human-readable terminal reports. No third-party UI deps.
// English by default; set BRK_LANG=zh for Chinese labels.

const LANG = (process.env.BRK_LANG || "en").toLowerCase().startsWith("zh") ? "zh" : "en";

const C = {
  reset: "\x1b[0m", bold: "\x1b[1m", dim: "\x1b[2m",
  red: "\x1b[31m", yellow: "\x1b[33m", green: "\x1b[32m", cyan: "\x1b[36m", gray: "\x1b[90m",
};

const SEV_COLOR = { CRITICAL: C.red, HIGH: C.red, MEDIUM: C.yellow, LOW: C.cyan, UNKNOWN: C.gray };

const T = {
  en: {
    depsTitle: "Break Anything · dependency scan",
    depsTarget: (t, n, s) => `target ${t}  ·  ${n} packages scanned  ·  ${s}`,
    depsClean: "✓ No matching vulnerabilities in the OSV database.",
    cleanNote: "  Note: this means \"none found\", not \"safe\".",
    reach: { imported: "reachable", direct: "direct dep", transitive: "transitive", unknown: "—" },
    epss: (v) => (v != null ? `EPSS ${(v * 100).toFixed(1)}%` : "EPSS —"),
    fix: (v) => `fix → ${v}`,
    noFix: "no fix available",
    summary: "summary",
    findings: "findings",
    reachable: "reachable",
    skipped: (n) => `(${n} packages failed to query, skipped)`,
    heuristic: "Reachability is a heuristic (is it imported), not proof the vulnerable code runs.",
    secretsTitle: "Break Anything · secret scan",
    secretsTarget: (t, on) => `target ${t}  ·  history scan ${on ? "on" : "off"}`,
    secretsClean: "✓ No leaked secrets found.",
    history: "git history",
    inHistory: "in history",
    rotate: "Secrets in history may still be live even after deletion — rotate them, don't just delete the commit.",
    imageTitle: "Break Anything · image scan",
    imageClean: "✓ No known vulnerabilities in the image.",
    more: (n) => `… ${n} more, use --json for the full list`,
    fixable: "fixable",
  },
  zh: {
    depsTitle: "Break Anything · 依赖扫描",
    depsTarget: (t, n, s) => `目标 ${t}  ·  已扫 ${n} 个包  ·  ${s}`,
    depsClean: "✓ 未在已知漏洞库(OSV)中发现匹配的漏洞。",
    cleanNote: "  注意:这表示\"未发现\",不等于\"安全\"。",
    reach: { imported: "可达(已被引用)", direct: "直接依赖", transitive: "传递依赖", unknown: "—" },
    epss: (v) => (v != null ? `EPSS ${(v * 100).toFixed(1)}%` : "EPSS —"),
    fix: (v) => `修复 → ${v}`,
    noFix: "无修复版本",
    summary: "小结",
    findings: "条",
    reachable: "可达",
    skipped: (n) => `(${n} 个包查询失败,已跳过)`,
    heuristic: "可达性为启发式(判断是否被引用),非漏洞函数被调用的证明。",
    secretsTitle: "Break Anything · 密钥扫描",
    secretsTarget: (t, on) => `目标 ${t}  ·  历史扫描 ${on ? "开" : "关"}`,
    secretsClean: "✓ 未发现疑似泄露的密钥。",
    history: "git 历史",
    inHistory: "历史中",
    rotate: "历史里的密钥即使已删除也可能仍然有效 —— 请轮换(rotate),不要只删提交。",
    imageTitle: "Break Anything · 镜像扫描",
    imageClean: "✓ 未在镜像中发现已知漏洞。",
    more: (n) => `… 还有 ${n} 条,用 --json 查看全部`,
    fixable: "可修复",
  },
}[LANG];

function palette(color) {
  return color ? C : new Proxy({}, { get: () => "" });
}

export function renderHuman(result, { color = true, top } = {}) {
  const c = palette(color);
  const lines = [];

  if (!result.ok) {
    lines.push(`${c.yellow}${result.message}${c.reset}`);
    lines.push(`${c.gray}${result.target}${c.reset}`);
    return lines.join("\n");
  }

  const srcDesc = result.sources.map((s) => `${s.ecosystem}:${s.packages}`).join("  ");
  lines.push(`${c.bold}${T.depsTitle}${c.reset}`);
  lines.push(`${c.gray}${T.depsTarget(result.target, result.scanned, srcDesc)}${c.reset}`);
  lines.push("");

  if (!result.findings.length) {
    lines.push(`${c.green}${T.depsClean}${c.reset}`);
    lines.push(`${c.gray}${T.cleanNote}${c.reset}`);
    return lines.join("\n");
  }

  const shown = top && result.findings.length > top ? result.findings.slice(0, top) : result.findings;
  for (const f of shown) {
    const sev = `${SEV_COLOR[f.severity] || ""}${f.severity.padEnd(8)}${c.reset}`;
    const idLabel = f.cve || f.id;
    const fix = f.fixedVersions.length
      ? `${c.green}${T.fix(f.fixedVersions.join(", "))}${c.reset}`
      : `${c.red}${T.noFix}${c.reset}`;
    lines.push(`${sev} ${c.bold}${f.package}@${f.version}${c.reset} ${c.gray}(${f.ecosystem})${c.reset}`);
    lines.push(`  ${c.cyan}${idLabel}${c.reset}  ·  ${T.reach[f.reachability]}  ·  ${T.epss(f.epss)}  ·  ${fix}`);
    if (f.summary) lines.push(`  ${c.gray}${f.summary.replace(/\s+/g, " ").slice(0, 120)}${c.reset}`);
    lines.push("");
  }
  if (shown.length < result.findings.length) {
    lines.push(`${c.gray}${T.more(result.findings.length - shown.length)}${c.reset}`);
    lines.push("");
  }

  const s = result.summary;
  const sevParts = Object.entries(s.bySeverity)
    .sort((a, b) => sevOrder(b[0]) - sevOrder(a[0]))
    .map(([k, v]) => `${k} ${v}`)
    .join("  ");
  lines.push(`${c.bold}${T.summary}${c.reset} ${s.total} ${T.findings}  ·  ${s.reachable} ${T.reachable}  ·  ${sevParts}`);
  if (result.errors?.length) lines.push(`${c.gray}${T.skipped(result.errors.length)}${c.reset}`);
  lines.push(`${c.gray}${T.heuristic}${c.reset}`);
  return lines.join("\n");
}

function sevOrder(k) {
  return { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 }[k] ?? 0;
}

// ---- secrets ----
export function renderSecrets(result, { color = true } = {}) {
  const c = palette(color);
  const lines = [];
  lines.push(`${c.bold}${T.secretsTitle}${c.reset}`);
  lines.push(`${c.gray}${T.secretsTarget(result.target, result.historyScanned)}${c.reset}`);
  lines.push("");

  if (!result.findings.length) {
    lines.push(`${c.green}${T.secretsClean}${c.reset}`);
    lines.push(`${c.gray}${T.cleanNote}${c.reset}`);
    return lines.join("\n");
  }

  for (const f of result.findings) {
    const sev = `${SEV_COLOR[f.severity] || ""}${f.severity.padEnd(8)}${c.reset}`;
    const loc = f.source === "history"
      ? `${c.yellow}${T.history}${c.reset} ${c.gray}@${f.commit}${c.reset}`
      : `${f.location}${f.line ? `:${f.line}` : ""}`;
    lines.push(`${sev} ${c.bold}${f.rule}${c.reset}`);
    lines.push(`  ${loc}  ·  ${c.gray}${f.match}${c.reset}`);
  }
  lines.push("");
  const s = result.summary;
  const parts = Object.entries(s.bySeverity).sort((a, b) => sevOrder(b[0]) - sevOrder(a[0])).map(([k, v]) => `${k} ${v}`).join("  ");
  lines.push(`${c.bold}${T.summary}${c.reset} ${s.total} ${T.findings}  ·  ${s.inHistory} ${T.inHistory}  ·  ${parts}`);
  if (s.inHistory) lines.push(`${c.yellow}${T.rotate}${c.reset}`);
  return lines.join("\n");
}

// ---- image ----
export function renderImage(result, { color = true } = {}) {
  const c = palette(color);
  const lines = [];
  lines.push(`${c.bold}${T.imageTitle}${c.reset} ${c.gray}(${result.engine})${c.reset}`);

  if (!result.ok) {
    lines.push("");
    lines.push(`${c.yellow}${result.message}${c.reset}`);
    return lines.join("\n");
  }

  lines.push(`${c.gray}${result.target}${c.reset}`);
  lines.push("");
  if (!result.findings.length) {
    lines.push(`${c.green}${T.imageClean}${c.reset}`);
    return lines.join("\n");
  }
  for (const f of result.findings.slice(0, 40)) {
    const sev = `${SEV_COLOR[f.severity] || ""}${f.severity.padEnd(8)}${c.reset}`;
    const fix = f.fixedVersions.length ? `${c.green}${T.fix(f.fixedVersions.join(", "))}${c.reset}` : `${c.red}${T.noFix}${c.reset}`;
    lines.push(`${sev} ${c.bold}${f.package}@${f.version}${c.reset} ${c.cyan}${f.cve || f.id}${c.reset}  ${fix}  ${c.gray}[${f.class}]${c.reset}`);
  }
  if (result.findings.length > 40) lines.push(`${c.gray}${T.more(result.findings.length - 40)}${c.reset}`);
  lines.push("");
  const s = result.summary;
  const parts = Object.entries(s.bySeverity).sort((a, b) => sevOrder(b[0]) - sevOrder(a[0])).map(([k, v]) => `${k} ${v}`).join("  ");
  lines.push(`${c.bold}${T.summary}${c.reset} ${s.total} ${T.findings}  ·  ${s.fixable} ${T.fixable}  ·  ${parts}`);
  return lines.join("\n");
}
