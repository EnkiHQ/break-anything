// Go 符号级可达性:封装官方 govulncheck。
//
// 这是目前唯一"货真价实"的调用链可达性来源:Go 的 OSV 公告带脆弱符号,
// govulncheck 会做真正的调用图分析,告诉你**公告里那个具体函数**是否在你代码的调用链上,
// 并给出从入口到脆弱函数的调用路径。
//
// 分级(govulncheck 的语义,比我们通用的 import 启发式强一个量级):
//   called   —— 脆弱函数确实被调用(带调用路径作为证据)
//   imported —— 脆弱包被导入,但没调用到脆弱函数
//   required —— 只是依赖图里有这个模块
// 没装 govulncheck 时优雅降级并给安装提示。

import { spawn } from "node:child_process";

const SEV = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
function sevRank(s) { return SEV[s] ?? 0; }
function countBy(arr, key) { const m = {}; for (const x of arr) m[x[key]] = (m[x[key]] || 0) + 1; return m; }

const REACH_ORDER = { called: 3, imported: 2, required: 1, unknown: 0 };
export function govulnReachRank(r) { return REACH_ORDER[r] ?? 0; }

// 按 govulncheck 的 trace 判定可达层级(纯函数,可单测)。
// trace[0] 是最深的那一帧:带 function 说明定位到了脆弱符号调用;只有 package 说明仅导入;只有 module 说明仅依赖。
export function classifyGovulnTrace(trace) {
  if (!Array.isArray(trace) || !trace.length) return "required";
  const deepest = trace[0] || {};
  if (deepest.function) return "called";
  if (deepest.package) return "imported";
  return "required";
}

// 把 trace 转成"入口 → 脆弱函数"的可读调用路径(纯函数,可单测)
export function formatCallPath(trace) {
  if (!Array.isArray(trace) || !trace.length) return [];
  const frames = trace
    .filter((f) => f && (f.function || f.package))
    .map((f) => {
      const fn = f.function ? `${f.package || f.module || ""}.${f.function}` : (f.package || f.module || "");
      const pos = f.position && f.position.filename
        ? `${f.position.filename}:${f.position.line || 0}`
        : null;
      return { symbol: fn, at: pos };
    });
  return frames.slice().reverse(); // govulncheck 从脆弱函数向外排,反转成入口在前
}

// 归一化 govulncheck 的 JSON 流(纯函数,可单测)。
// 输出里每条发现带 reachability 与 callPath(called 时就是"证明")。
export function normalizeGovulncheck(rawJson, target) {
  const text = String(rawJson || "");
  const osvById = new Map();
  const findings = [];

  // govulncheck -json 输出的是一串 JSON 对象(可能美化换行),用括号配平切分
  for (const obj of splitJsonObjects(text)) {
    if (obj.osv) {
      const o = obj.osv;
      const aliases = Array.isArray(o.aliases) ? o.aliases : [];
      osvById.set(o.id, {
        id: o.id,
        cve: aliases.find((a) => /^CVE-/i.test(a)) || null,
        summary: o.summary || (o.details ? String(o.details).slice(0, 160) : ""),
        severity: deriveSeverity(o),
        references: (o.references || []).map((r) => r.url).filter(Boolean).slice(0, 3),
      });
    }
    if (obj.finding) {
      const f = obj.finding;
      const reach = classifyGovulnTrace(f.trace);
      const meta = osvById.get(f.osv) || { id: f.osv, cve: null, summary: "", severity: "UNKNOWN", references: [] };
      const path = formatCallPath(f.trace);
      const deepest = (f.trace && f.trace[0]) || {};
      findings.push({
        id: meta.id,
        cve: meta.cve,
        package: deepest.package || deepest.module || "",
        module: deepest.module || "",
        version: deepest.version || "",
        severity: meta.severity,
        reachability: reach,
        vulnerableSymbol: deepest.function ? `${deepest.package || ""}.${deepest.function}` : null,
        callPath: path,
        fixedVersions: f.fixed_version ? [String(f.fixed_version).replace(/^v/, "")] : [],
        summary: meta.summary,
        references: meta.references,
      });
    }
  }

  // 同一漏洞可能有多条 trace(required/imported/called),只保留最强的那条
  const best = new Map();
  for (const f of findings) {
    const key = `${f.id}|${f.module}`;
    const prev = best.get(key);
    if (!prev || govulnReachRank(f.reachability) > govulnReachRank(prev.reachability)) best.set(key, f);
  }
  const merged = [...best.values()].sort(
    (a, b) => govulnReachRank(b.reachability) - govulnReachRank(a.reachability) || sevRank(b.severity) - sevRank(a.severity),
  );

  return {
    target, ok: true, engine: "govulncheck",
    findings: merged,
    summary: {
      total: merged.length,
      called: merged.filter((f) => f.reachability === "called").length,
      imported: merged.filter((f) => f.reachability === "imported").length,
      bySeverity: countBy(merged, "severity"),
    },
  };
}

function deriveSeverity(osv) {
  const label = osv.database_specific && osv.database_specific.severity;
  if (typeof label === "string" && label) return label.toUpperCase();
  const cvss = (osv.severity || []).find((s) => /CVSS/i.test(s.type || ""));
  if (cvss && cvss.score) {
    const n = Number(cvss.score);
    if (!Number.isNaN(n)) {
      if (n >= 9) return "CRITICAL";
      if (n >= 7) return "HIGH";
      if (n >= 4) return "MEDIUM";
      if (n > 0) return "LOW";
    }
  }
  return "UNKNOWN";
}

// 从拼接的 JSON 文本里切出顶层对象(容忍美化换行与对象间空白)
export function splitJsonObjects(text) {
  const out = [];
  let depth = 0, start = -1, inStr = false, esc = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inStr) {
      if (esc) esc = false;
      else if (ch === "\\") esc = true;
      else if (ch === '"') inStr = false;
      continue;
    }
    if (ch === '"') { inStr = true; continue; }
    if (ch === "{") { if (depth === 0) start = i; depth++; continue; }
    if (ch === "}") {
      depth--;
      if (depth === 0 && start >= 0) {
        try { out.push(JSON.parse(text.slice(start, i + 1))); } catch { /* 跳过坏片段 */ }
        start = -1;
      }
    }
  }
  return out;
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

function run(cmd, args, cwd, timeoutMs) {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, args, { cwd, stdio: ["ignore", "pipe", "pipe"] });
    let out = "", err = "";
    const timer = setTimeout(() => { p.kill("SIGKILL"); reject(new Error("govulncheck 超时")); }, timeoutMs);
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));
    p.on("close", (code) => { clearTimeout(timer); resolve({ out, err, code }); });
    p.on("error", (e) => { clearTimeout(timer); reject(e); });
  });
}

// 入口:对一个 Go 模块目录做符号级可达性分析
export async function scanGoReachability(targetPath, { timeoutMs = 300000 } = {}) {
  const bin = await which("govulncheck");
  if (!bin) {
    return {
      target: targetPath, ok: false, engine: "govulncheck",
      message:
        "未找到 govulncheck。Go 符号级可达性依赖官方 govulncheck。安装:\n" +
        "  go install golang.org/x/vuln/cmd/govulncheck@latest\n" +
        "  文档:https://go.dev/doc/tutorial/govulncheck",
      findings: [], summary: { total: 0, called: 0, imported: 0, bySeverity: {} },
    };
  }

  let res;
  try { res = await run(bin, ["-json", "./..."], targetPath, timeoutMs); }
  catch (e) {
    return { target: targetPath, ok: false, engine: "govulncheck", message: `govulncheck 执行失败:${e instanceof Error ? e.message : String(e)}`, findings: [], summary: { total: 0, called: 0, imported: 0, bySeverity: {} } };
  }

  // 和 nuclei 一样的诚实原则:没真正跑起来时如实报错,不把"没跑"说成"没问题"
  if (!String(res.out || "").trim()) {
    const why = (String(res.err || "").match(/[^\n]*(no such file|not a module|go\.mod|cannot find|error)[^\n]*/i) || [])[0];
    return {
      target: targetPath, ok: false, engine: "govulncheck",
      message: `govulncheck 未产出结果${why ? `:${why.trim().slice(0, 200)}` : "(目标可能不是 Go 模块)"}`,
      findings: [], summary: { total: 0, called: 0, imported: 0, bySeverity: {} },
    };
  }

  const result = normalizeGovulncheck(res.out, targetPath);

  // Go 的 vulndb 不提供严重度,用 EPSS(被利用概率)+ CISA KEV(在野利用)按 CVE 富化,让排序真正可用
  const cves = result.findings.map((f) => f.cve).filter(Boolean);
  if (cves.length) {
    const [{ enrichEpss }, { enrichKev }] = await Promise.all([import("./epss.js"), import("./kev.js")]);
    const [epss, kev] = await Promise.all([enrichEpss(cves), enrichKev(cves)]);
    for (const f of result.findings) {
      const ep = f.cve ? epss.get(f.cve) : null;
      const kv = f.cve ? kev.get(String(f.cve).toUpperCase()) : null;
      f.epss = ep ? ep.epss : null;
      f.kev = !!kv;
      f.kevRansomware = kv ? kv.ransomware : false;
    }
    // 排序:被调用优先 → KEV → EPSS(Go 没有严重度可用)
    result.findings.sort(
      (a, b) =>
        govulnReachRank(b.reachability) - govulnReachRank(a.reachability) ||
        (b.kev ? 1 : 0) - (a.kev ? 1 : 0) ||
        (b.epss ?? 0) - (a.epss ?? 0),
    );
    result.summary.kev = result.findings.filter((f) => f.kev).length;
  }
  return result;
}
