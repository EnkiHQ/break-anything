import { readdir, readFile } from "node:fs/promises";
import path from "node:path";

// 可达性初判(启发式,非证明),从弱到强:
//   called    —— 源码从该包 import 了某符号,且该符号在你的代码里被「调用」了 → 最强信号
//   imported  —— 源码 import/require 了这个包,但没看到调用(可能是副作用导入或仅类型导入)
//   direct    —— 清单里声明为直接依赖,但没在源码里发现引用
//   transitive—— 既非直接依赖、也没在源码里发现引用(传递依赖)
// 诚实边界:`called` 表示「导入的符号被调用」,仍不等于「公告里那个具体的脆弱函数被执行」。
// 调用检测目前覆盖 JS/TS(.js/.mjs/.cjs/.jsx/.ts/.tsx/.vue);PHP/Python 只做到 import 粒度。

const SOURCE_EXT = new Set([".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".php", ".py", ".go", ".rs", ".rb"]);
const JS_EXT = new Set([".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue"]);
const SKIP_DIR = new Set(["node_modules", ".git", "dist", "build", "vendor", ".venv", "venv", "__pycache__"]);

function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }

// ---- 新:带调用分析的用法扫描 ----
// 返回 Map(name -> { imported: boolean, called: boolean })
export async function analyzeUsage(dir, packageNames) {
  const usage = new Map();
  for (const n of packageNames) usage.set(n, { imported: false, called: false });

  const files = [];
  await collect(dir, files, 0);
  const meta = packageNames.map((name) => ({ name, importedRe: importRegex(name) }));

  for (const f of files) {
    let text;
    try { text = await readFile(f, "utf8"); } catch { continue; }
    const isJs = JS_EXT.has(path.extname(f));
    for (const m of meta) {
      const u = usage.get(m.name);
      if (u.called) continue;                 // 已是最强信号,跳过
      if (!text.includes(m.name)) continue;    // 便宜的预筛

      if (!u.imported && m.importedRe.test(text)) u.imported = true;

      if (isJs) {
        const bindings = extractBindings(text, m.name);
        if (bindings.size) {
          u.imported = true;
          if (isCalled(text, bindings)) u.called = true;
        }
      }
    }
  }
  return usage;
}

// 从一段源码里,抽取「从指定包导入」的本地绑定名(纯函数,可单测)
export function extractBindings(text, name) {
  const esc = escapeRe(name);
  const q = `['"\`]${esc}['"\`]`;
  const bindings = new Set();
  let m;

  // const X = require('name')
  const reqDefault = new RegExp(`(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*require\\(\\s*${q}\\s*\\)`, "g");
  while ((m = reqDefault.exec(text))) bindings.add(m[1]);

  // const { a, b: c } = require('name')
  const reqDestr = new RegExp(`(?:const|let|var)\\s*\\{([^}]*)\\}\\s*=\\s*require\\(\\s*${q}\\s*\\)`, "g");
  while ((m = reqDestr.exec(text))) parseBindingList(m[1]).forEach((b) => bindings.add(b));

  // import <clause> from 'name'
  const impStmt = new RegExp(`import\\s+([^;\\n]*?)\\s+from\\s*${q}`, "g");
  while ((m = impStmt.exec(text))) {
    const clause = m[1].trim();
    const ns = clause.match(/\*\s+as\s+([A-Za-z_$][\w$]*)/);
    if (ns) bindings.add(ns[1]);
    const brace = clause.match(/\{([^}]*)\}/);
    if (brace) parseBindingList(brace[1]).forEach((b) => bindings.add(b));
    // 默认导入:clause 开头不是 { 也不是 * 的那个标识符
    if (!clause.startsWith("{") && !clause.startsWith("*")) {
      const def = clause.match(/^([A-Za-z_$][\w$]*)/);
      if (def) bindings.add(def[1]);
    }
  }
  return bindings;
}

// 解析 { ... } 内的绑定列表:a / a as b / a: b;跳过 TS 纯类型导入(type a)
function parseBindingList(s) {
  const out = [];
  for (let part of s.split(",")) {
    part = part.trim();
    if (!part || /^type\s+/.test(part)) continue;
    let m;
    if ((m = part.match(/\bas\s+([A-Za-z_$][\w$]*)/))) out.push(m[1]);
    else if ((m = part.match(/:\s*([A-Za-z_$][\w$]*)/))) out.push(m[1]);
    else if ((m = part.match(/^([A-Za-z_$][\w$]*)/))) out.push(m[1]);
  }
  return out;
}

// 这些绑定里,是否有被「调用」的:b(... / new b(... / b.foo(... / b?.foo(...(纯函数,可单测)
// 用 (?<![\w$.]) 排除 `obj.b(` 这类他人成员调用,降低误报。
export function isCalled(text, bindings) {
  for (const b of bindings) {
    const e = escapeRe(b);
    const re = new RegExp(`(?<![\\w$.])(?:new\\s+)?${e}\\s*(?:\\(|\\??\\.\\s*[\\w$]+\\s*\\()`);
    if (re.test(text)) return true;
  }
  return false;
}

async function collect(dir, out, depth) {
  if (depth > 8 || out.length > 5000) return;
  let entries;
  try { entries = await readdir(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (e.name.startsWith(".") && e.name !== ".") continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (SKIP_DIR.has(e.name)) continue;
      await collect(full, out, depth + 1);
    } else if (SOURCE_EXT.has(path.extname(e.name))) {
      out.push(full);
    }
  }
}

function importRegex(name) {
  const esc = escapeRe(name);
  // 命中 import 'x' / from 'x' / require('x') / use X\...(PHP) / import x(py)
  return new RegExp(
    `(require\\(\\s*['"\`]${esc}|from\\s+['"\`]${esc}|import\\s+['"\`]${esc}|import\\s+[^'"\`\\n]*['"\`]${esc})`,
    "m",
  );
}

// ---- 分类 ----
// 旧:基于 imported 集合(保留以兼容既有调用/测试)
export function classify(pkg, imported) {
  if (imported.has(pkg.name)) return "imported";
  if (pkg.direct) return "direct";
  return "transitive";
}

// 新:基于 analyzeUsage 的 Map
export function classifyUsage(pkg, usage) {
  const u = usage.get(pkg.name);
  if (u && u.called) return "called";
  if (u && u.imported) return "imported";
  if (pkg.direct) return "direct";
  return "transitive";
}

const REACH_ORDER = { called: 4, imported: 3, direct: 2, transitive: 1 };
export function reachRank(label) {
  return REACH_ORDER[label] ?? 0;
}
