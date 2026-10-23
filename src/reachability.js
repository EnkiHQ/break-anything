import { readdir, readFile } from "node:fs/promises";
import path from "node:path";

// 可达性初判(启发式,非证明):
//   imported  —— 源码里确实 import/require 了这个包 → 最高优先级
//   direct    —— 清单里声明为直接依赖,但没在源码里发现引用
//   transitive—— 既非直接依赖、也没在源码里发现引用(传递依赖)
// 诚实地标注这是启发式:它判断"是否被引用",不等于"漏洞函数被调用"。

const SOURCE_EXT = new Set([".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".php", ".py"]);
const SKIP_DIR = new Set(["node_modules", ".git", "dist", "build", "vendor", ".venv", "venv", "__pycache__"]);

export async function buildReachability(dir, packageNames) {
  const imported = new Set();
  const files = [];
  await collect(dir, files, 0);

  // npm 包可能是 scope 形式 @scope/name;只取用于匹配的词根
  const patterns = packageNames.map((name) => ({ name, re: importRegex(name) }));

  for (const f of files) {
    let text;
    try { text = await readFile(f, "utf8"); } catch { continue; }
    for (const { name, re } of patterns) {
      if (imported.has(name)) continue;
      if (re.test(text)) imported.add(name);
    }
  }
  return imported;
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
  const esc = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  // 命中 import 'x' / from 'x' / require('x') / use X\...(PHP) / import x(py)
  return new RegExp(
    `(require\\(\\s*['"\`]${esc}|from\\s+['"\`]${esc}|import\\s+['"\`]${esc}|import\\s+[^'"\`\\n]*['"\`]${esc})`,
    "m",
  );
}

export function classify(pkg, imported) {
  if (imported.has(pkg.name)) return "imported";
  if (pkg.direct) return "direct";
  return "transitive";
}

const REACH_ORDER = { imported: 3, direct: 2, transitive: 1 };
export function reachRank(label) {
  return REACH_ORDER[label] ?? 0;
}
