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
    reach: { called: "called", imported: "imported", direct: "direct dep", transitive: "transitive", unknown: "—" },
    epss: (v) => (v != null ? `EPSS ${(v * 100).toFixed(1)}%` : "EPSS —"),
    fix: (v) => `fix → ${v}`,
    noFix: "no fix available",
    summary: "summary",
    findings: "findings",
    reachable: "reachable",
    invoked: "called",
    kev: "KEV",
    kevRansom: "KEV · ransomware",
    kevNote: "KEV = CISA Known Exploited: attackers are using this in the wild right now. Fix these first.",
    skipped: (n) => `(${n} packages failed to query, skipped)`,
    heuristic: "Reachability is a heuristic: \"called\" means an imported symbol is invoked in your code — still not proof the specific vulnerable function runs.",
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
    sastTitle: "Break Anything · static code scan",
    sastClean: "✓ No issues found by the static-analysis rules.",
    apiTitle: "Break Anything · API security scan (DAST)",
    apiClean: "✓ No access-control or header issues found.",
    iacTitle: "Break Anything · infrastructure-as-code scan",
    iacClean: "✓ No misconfigurations found by the IaC rules.",
    iacScanned: (n, t) => `${n} IaC files scanned${t ? `  ·  ${t}` : ""}`,
    fixTitle: "Break Anything · fix plan",
    fixClean: "✓ Nothing to fix — no vulnerable dependencies found.",
    fixHead: (u, v) => `${u} package${u === 1 ? "" : "s"} to upgrade  ·  resolves ${v} ${v === 1 ? "vulnerability" : "vulnerabilities"}`,
    fixResolves: (n) => `resolves ${n} ${n === 1 ? "CVE" : "CVEs"}`,
    fixNoFixHead: "No upstream fix available",
    fixNoFixHint: "Pin and mitigate, or move to a maintained fork. Hand these to Patch Anything.",
    fixValidate: "Upgrade targets are minimal safe-version suggestions — validate with your tests.",
  },
  zh: {
    depsTitle: "Break Anything · 依赖扫描",
    depsTarget: (t, n, s) => `目标 ${t}  ·  已扫 ${n} 个包  ·  ${s}`,
    depsClean: "✓ 未在已知漏洞库(OSV)中发现匹配的漏洞。",
    cleanNote: "  注意:这表示\"未发现\",不等于\"安全\"。",
    reach: { called: "被调用", imported: "已引用", direct: "直接依赖", transitive: "传递依赖", unknown: "—" },
    epss: (v) => (v != null ? `EPSS ${(v * 100).toFixed(1)}%` : "EPSS —"),
    fix: (v) => `修复 → ${v}`,
    noFix: "无修复版本",
    summary: "小结",
    findings: "条",
    reachable: "可达",
    invoked: "被调用",
    kev: "KEV在野利用",
    kevRansom: "KEV·勒索",
    kevNote: "KEV = CISA 已知被在野利用:攻击者此刻正在打它。优先修这些。",
    skipped: (n) => `(${n} 个包查询失败,已跳过)`,
    heuristic: "可达性为启发式:「被调用」指导入的符号在你代码里被调用——仍不等于公告里那个具体脆弱函数被执行。",
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
    sastTitle: "Break Anything · 静态代码扫描",
    sastClean: "✓ 静态分析规则未发现问题。",
    apiTitle: "Break Anything · API 安全扫描(DAST)",
    apiClean: "✓ 未发现越权/鉴权/响应头问题。",
    iacTitle: "Break Anything · 基础设施即代码(IaC)扫描",
    iacClean: "✓ IaC 规则未发现错误配置。",
    iacScanned: (n, t) => `已扫 ${n} 个 IaC 文件${t ? `  ·  ${t}` : ""}`,
    fixTitle: "Break Anything · 修复计划",
    fixClean: "✓ 没有要修的——未发现有漏洞的依赖。",
    fixHead: (u, v) => `${u} 个包待升级  ·  可消除 ${v} 个漏洞`,
    fixResolves: (n) => `消除 ${n} 个 CVE`,
    fixNoFixHead: "无上游修复版本",
    fixNoFixHint: "锁版本并做缓解,或迁移到维护中的 fork。可把这些交给 Patch Anything。",
    fixValidate: "升级目标是「尽量小的安全版本」建议,请用你的测试验证兼容性。",
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
    const kevBadge = f.kev ? ` ${c.red}${c.bold}[${f.kevRansomware ? T.kevRansom : T.kev}]${c.reset}` : "";
    lines.push(`${sev} ${c.bold}${f.package}@${f.version}${c.reset} ${c.gray}(${f.ecosystem})${c.reset}${kevBadge}`);
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
  const reachPart = `${s.reachable} ${T.reachable}` + (s.called ? ` (${s.called} ${T.invoked})` : "");
  const kevPart = s.kev ? `  ·  ${c.red}${s.kev} ${T.kev}${c.reset}` : "";
  lines.push(`${c.bold}${T.summary}${c.reset} ${s.total} ${T.findings}  ·  ${reachPart}${kevPart}  ·  ${sevParts}`);
  if (result.errors?.length) lines.push(`${c.gray}${T.skipped(result.errors.length)}${c.reset}`);
  if (s.kev) lines.push(`${c.red}${T.kevNote}${c.reset}`);
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

// ---- SAST ----
export function renderSast(result, { color = true, top } = {}) {
  const c = palette(color);
  const lines = [];
  lines.push(`${c.bold}${T.sastTitle}${c.reset} ${c.gray}(${result.engine})${c.reset}`);

  if (!result.ok) {
    lines.push("");
    lines.push(`${c.yellow}${result.message}${c.reset}`);
    return lines.join("\n");
  }

  lines.push(`${c.gray}${result.target}${c.reset}`);
  lines.push("");
  if (!result.findings.length) {
    lines.push(`${c.green}${T.sastClean}${c.reset}`);
    return lines.join("\n");
  }

  const shown = top && result.findings.length > top ? result.findings.slice(0, top) : result.findings;
  for (const f of shown) {
    const sev = `${SEV_COLOR[f.severity] || ""}${f.severity.padEnd(8)}${c.reset}`;
    const tags = [f.cwe[0], f.owasp[0]].filter(Boolean).join(" · ");
    lines.push(`${sev} ${c.bold}${f.rule}${c.reset} ${c.gray}${tags}${c.reset}`);
    lines.push(`  ${c.cyan}${f.location}${c.reset}  ${c.gray}${f.message.slice(0, 100)}${c.reset}`);
    if (f.snippet) lines.push(`  ${c.gray}${f.snippet.slice(0, 90)}${c.reset}`);
    lines.push("");
  }
  if (shown.length < result.findings.length) {
    lines.push(`${c.gray}${T.more(result.findings.length - shown.length)}${c.reset}`);
    lines.push("");
  }

  const s = result.summary;
  const parts = Object.entries(s.bySeverity).sort((a, b) => sevOrder(b[0]) - sevOrder(a[0])).map(([k, v]) => `${k} ${v}`).join("  ");
  lines.push(`${c.bold}${T.summary}${c.reset} ${s.total} ${T.findings}  ·  ${parts}`);
  return lines.join("\n");
}

// ---- IaC ----
export function renderIac(result, { color = true, top } = {}) {
  const c = palette(color);
  const lines = [];
  lines.push(`${c.bold}${T.iacTitle}${c.reset}`);

  if (!result.ok) {
    lines.push("");
    lines.push(`${c.yellow}${result.message}${c.reset}`);
    return lines.join("\n");
  }

  const types = Object.entries(result.byType || {}).map(([k, v]) => `${k} ${v}`).join("  ");
  lines.push(`${c.gray}${result.target}  ·  ${T.iacScanned(result.scanned, types)}${c.reset}`);
  lines.push("");
  if (!result.findings.length) {
    lines.push(`${c.green}${T.iacClean}${c.reset}`);
    lines.push(`${c.gray}${T.cleanNote}${c.reset}`);
    return lines.join("\n");
  }

  const shown = top && result.findings.length > top ? result.findings.slice(0, top) : result.findings;
  for (const f of shown) {
    const sev = `${SEV_COLOR[f.severity] || ""}${f.severity.padEnd(8)}${c.reset}`;
    const tags = [f.kind, f.cwe].filter(Boolean).join(" · ");
    lines.push(`${sev} ${c.bold}${f.title}${c.reset} ${c.gray}${tags}${c.reset}`);
    lines.push(`  ${c.cyan}${f.location}${c.reset}`);
    if (f.evidence) lines.push(`  ${c.gray}${f.evidence}${c.reset}`);
    lines.push("");
  }
  if (shown.length < result.findings.length) {
    lines.push(`${c.gray}${T.more(result.findings.length - shown.length)}${c.reset}`);
    lines.push("");
  }

  const s = result.summary;
  const parts = Object.entries(s.bySeverity).sort((a, b) => sevOrder(b[0]) - sevOrder(a[0])).map(([k, v]) => `${k} ${v}`).join("  ");
  lines.push(`${c.bold}${T.summary}${c.reset} ${s.total} ${T.findings}  ·  ${parts}`);
  return lines.join("\n");
}

// ---- API / DAST ----
export function renderApi(result, { color = true } = {}) {
  const c = palette(color);
  const lines = [];
  lines.push(`${c.bold}${T.apiTitle}${c.reset}`);

  if (!result.ok) {
    lines.push("");
    lines.push(`${c.yellow}${result.message}${c.reset}`);
    return lines.join("\n");
  }

  lines.push(`${c.gray}${result.target}${c.reset}`);
  lines.push("");
  if (!result.findings.length) {
    lines.push(`${c.green}${T.apiClean}${c.reset}`);
    return lines.join("\n");
  }

  for (const f of result.findings) {
    const sev = `${SEV_COLOR[f.severity] || ""}${f.severity.padEnd(8)}${c.reset}`;
    lines.push(`${sev} ${c.bold}${f.title}${c.reset} ${c.gray}${f.cwe} · ${f.owasp}${c.reset}`);
    lines.push(`  ${c.cyan}${f.location}${c.reset}`);
    const e = f.evidence;
    if (e) {
      lines.push(`  ${c.gray}证据: ${e.request}${e.as ? ` (${e.as})` : ""}${e.status ? ` → ${e.status}` : ""} ${e.note || ""}${c.reset}`);
      if (e.bodySnippet) lines.push(`  ${c.red}泄露内容: ${e.bodySnippet}${c.reset}`);
    }
    lines.push("");
  }

  const s = result.summary;
  const parts = Object.entries(s.bySeverity).sort((a, b) => sevOrder(b[0]) - sevOrder(a[0])).map(([k, v]) => `${k} ${v}`).join("  ");
  lines.push(`${c.bold}${T.summary}${c.reset} ${s.total} ${T.findings}  ·  ${parts}`);
  return lines.join("\n");
}

// ---- Fix plan ----
export function renderFix(result, { color = true } = {}) {
  const c = palette(color);
  const lines = [];
  lines.push(`${c.bold}${T.fixTitle}${c.reset}`);

  if (!result.ok) {
    lines.push("");
    lines.push(`${c.yellow}${result.message}${c.reset}`);
    return lines.join("\n");
  }

  const s = result.summary;
  if (!s.upgradeCount && !s.noFixCount) {
    lines.push(`${c.gray}${result.target}${c.reset}`);
    lines.push("");
    lines.push(`${c.green}${T.fixClean}${c.reset}`);
    return lines.join("\n");
  }

  lines.push(`${c.gray}${result.target}  ·  ${T.fixHead(s.upgradeCount, s.resolvedVulns)}${c.reset}`);
  lines.push("");

  result.upgrades.forEach((u, i) => {
    const reachLabel = T.reach[reachName(u.maxReach)] || "";
    const tag = `${reachLabel} · ${u.maxSeverity}`;
    const sevc = SEV_COLOR[u.maxSeverity] || "";
    const kevBadge = u.kev ? ` ${c.red}${c.bold}[${T.kev}]${c.reset}` : "";
    lines.push(`${c.bold}${i + 1}.${c.reset} ${sevc}[${tag}]${c.reset}${kevBadge} ${c.bold}${u.package}${c.reset} ${u.from} ${c.gray}→${c.reset} ${c.green}${u.to}${c.reset}  ${c.gray}${T.fixResolves(u.resolves)}${c.reset}`);
    lines.push(`   ${c.cyan}${u.command}${c.reset}`);
  });

  if (result.noFix.length) {
    lines.push("");
    lines.push(`${c.bold}${c.yellow}${T.fixNoFixHead}${c.reset}`);
    for (const n of result.noFix) {
      const sev = `${SEV_COLOR[n.severity] || ""}${n.severity.padEnd(8)}${c.reset}`;
      const kevBadge = n.kev ? ` ${c.red}${c.bold}[${T.kev}]${c.reset}` : "";
      lines.push(`  ${sev} ${c.bold}${n.package}@${n.version}${c.reset} ${c.cyan}${n.cve}${c.reset} ${c.gray}(${T.reach[n.reachability] || n.reachability})${c.reset}${kevBadge}`);
    }
    lines.push(`  ${c.gray}${T.fixNoFixHint}${c.reset}`);
  }

  lines.push("");
  lines.push(`${c.gray}${T.fixValidate}${c.reset}`);
  return lines.join("\n");
}

function reachName(rank) {
  return { 4: "called", 3: "imported", 2: "direct", 1: "transitive" }[rank] || "unknown";
}

// ---- SBOM diff ----
export function renderSbomDiff(d, { color = true } = {}) {
  const c = palette(color);
  const zh = LANG === "zh";
  const lines = [];
  lines.push(`${c.bold}Break Anything · ${zh ? "SBOM 变更比对" : "SBOM diff"}${c.reset}`);
  lines.push("");
  const s = d.summary;
  if (!s.added && !s.removed && !s.changed) {
    lines.push(`${c.green}${zh ? "✓ 依赖组成无变化。" : "✓ No dependency changes."}${c.reset}`);
    return lines.join("\n");
  }
  for (const a of d.added) lines.push(`${c.green}+ ${zh ? "新增" : "added  "} ${a.name}@${a.version}${c.reset}`);
  for (const r of d.removed) lines.push(`${c.red}- ${zh ? "移除" : "removed"} ${r.name}@${r.version}${c.reset}`);
  for (const ch of d.changed) lines.push(`${c.yellow}~ ${zh ? "变更" : "changed"} ${ch.name} ${ch.from} ${c.gray}→${c.reset}${c.yellow} ${ch.to}${c.reset}`);
  lines.push("");
  lines.push(`${c.bold}${zh ? "小结" : "summary"}${c.reset} ${zh ? "新增" : "added"} ${s.added}  ·  ${zh ? "移除" : "removed"} ${s.removed}  ·  ${zh ? "变更" : "changed"} ${s.changed}`);
  return lines.join("\n");
}

// ---- CI 聚合 ----
export function renderCi(result, { color = true } = {}) {
  const c = palette(color);
  const zh = LANG === "zh";
  const lines = [];
  lines.push(`${c.bold}Break Anything · ${zh ? "CI 安全门禁" : "CI security gate"}${c.reset}`);
  lines.push(`${c.gray}${result.target}${c.reset}`);
  lines.push("");

  const label = { deps: zh ? "依赖" : "deps", secrets: zh ? "密钥" : "secrets", iac: "iac", sast: zh ? "代码(SAST)" : "sast" };
  for (const [key, cat] of Object.entries(result.categories)) {
    const name = (label[key] || key).padEnd(12);
    if (!cat || cat.ok === false) {
      lines.push(`  ${c.gray}• ${name} ${zh ? "跳过" : "skipped"}${cat && cat.message ? ` (${cat.message.split("\n")[0].slice(0, 60)})` : ""}${c.reset}`);
      continue;
    }
    const fs = cat.findings || [];
    const worst = fs.reduce((m, f) => Math.max(m, sevOrder(f.severity)), 0);
    const dot = fs.length === 0 ? c.green : (worst >= 3 ? c.red : c.yellow);
    lines.push(`  ${dot}●${c.reset} ${name} ${fs.length} ${zh ? "条发现" : "findings"}`);
  }

  lines.push("");
  const s = result.summary;
  const sevParts = Object.entries(s.bySeverity).sort((a, b) => sevOrder(b[0]) - sevOrder(a[0])).map(([k, v]) => `${k} ${v}`).join("  ");
  lines.push(`${c.bold}${zh ? "合计" : "total"}${c.reset} ${s.total} ${zh ? "条" : "findings"}${sevParts ? `  ·  ${sevParts}` : ""}`);
  lines.push("");

  if (result.policy && result.policy.suppressed) {
    lines.push(`${c.gray}${result.policy.suppressed} ${zh ? "条被策略忽略" : "suppressed by policy"}${result.policy.source ? ` (${result.policy.source.split("/").pop()})` : ""}${c.reset}`);
    lines.push("");
  }

  const g = result.gate;
  if (g.passed) {
    lines.push(`${c.green}${c.bold}✓ ${zh ? "门禁通过" : "GATE PASSED"}${c.reset} ${c.gray}(${zh ? "阈值" : "fail-on"} ${g.failOn})${c.reset}`);
  } else {
    lines.push(`${c.red}${c.bold}✗ ${zh ? "门禁失败" : "GATE FAILED"}${c.reset} ${c.gray}(${zh ? "阈值" : "fail-on"} ${g.failOn})${c.reset}`);
    for (const r of g.reasons) lines.push(`  ${c.red}- ${r}${c.reset}`);
  }
  return lines.join("\n");
}

// ---- Nuclei ----
export function renderNuclei(result, { color = true, top } = {}) {
  const c = palette(color);
  const zh = LANG === "zh";
  const lines = [];
  lines.push(`${c.bold}Break Anything · ${zh ? "Nuclei 模板扫描" : "Nuclei template scan"}${c.reset} ${c.gray}(nuclei)${c.reset}`);

  if (!result.ok) {
    lines.push("");
    lines.push(`${c.yellow}${result.message}${c.reset}`);
    return lines.join("\n");
  }

  lines.push(`${c.gray}${result.target}${c.reset}`);
  lines.push("");
  if (!result.findings.length) {
    lines.push(`${c.green}${zh ? "✓ Nuclei 模板未发现问题。" : "✓ No findings from the Nuclei templates."}${c.reset}`);
    lines.push(`${c.gray}${T.cleanNote}${c.reset}`);
    return lines.join("\n");
  }

  const shown = top && result.findings.length > top ? result.findings.slice(0, top) : result.findings;
  for (const f of shown) {
    const sev = `${SEV_COLOR[f.severity] || ""}${f.severity.padEnd(8)}${c.reset}`;
    const tags = [f.cve, ...(f.cwe || [])].filter(Boolean).join(" · ");
    lines.push(`${sev} ${c.bold}${f.title}${c.reset}${tags ? ` ${c.gray}${tags}${c.reset}` : ""}`);
    lines.push(`  ${c.cyan}${f.rule}${c.reset}  ${c.gray}${f.location}${c.reset}`);
    if (f.evidence && f.evidence.extracted && f.evidence.extracted.length) {
      lines.push(`  ${c.red}${zh ? "提取到" : "extracted"}: ${f.evidence.extracted.join(", ").slice(0, 120)}${c.reset}`);
    }
    lines.push("");
  }
  if (shown.length < result.findings.length) {
    lines.push(`${c.gray}${T.more(result.findings.length - shown.length)}${c.reset}`);
    lines.push("");
  }

  const s = result.summary;
  const parts = Object.entries(s.bySeverity).sort((a, b) => sevOrder(b[0]) - sevOrder(a[0])).map(([k, v]) => `${k} ${v}`).join("  ");
  lines.push(`${c.bold}${T.summary}${c.reset} ${s.total} ${T.findings}  ·  ${parts}`);
  return lines.join("\n");
}
