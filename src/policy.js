// 策略 / 基线:让 ci 门禁可被团队配置。
// 读 .break-anything.json(或 --policy 指定的文件),支持:
//   { "failOn": "high", "skip": ["sast"], "ignore": ["CVE-2021-23337", { "id": "docker-no-user", "reason": "基础镜像已加固" }] }
// ignore 命中的发现从门禁与计数里移除(标记为已抑制)。纯逻辑可单测,文件读取单独封装。

import { readFile, stat } from "node:fs/promises";
import path from "node:path";

export const POLICY_FILENAME = ".break-anything.json";
export const DEFAULT_POLICY = { failOn: "HIGH", skip: [], ignore: [] };

// 把 ignore 配置(字符串或 {id} 对象混用)归一化成 id 的 Set(纯函数)
export function normalizeIgnore(ignore) {
  const out = new Set();
  for (const item of ignore || []) {
    if (typeof item === "string" && item.trim()) out.add(item.trim());
    else if (item && typeof item === "object" && typeof item.id === "string" && item.id.trim()) out.add(item.id.trim());
  }
  return out;
}

// 一条发现是否被 ignore 命中:比对它的 cve / id / rule(纯函数,可单测)
export function isIgnored(finding, ignoreSet) {
  if (!ignoreSet || ignoreSet.size === 0) return false;
  for (const key of [finding.cve, finding.id, finding.rule]) {
    if (key && ignoreSet.has(String(key))) return true;
  }
  return false;
}

// 对 ci 的 categories 应用 ignore 过滤;返回新 categories + 抑制计数(纯函数,可单测)
export function applyPolicy(categories, policy = {}) {
  const ignoreSet = normalizeIgnore(policy.ignore);
  const out = {};
  let suppressed = 0;
  for (const [key, cat] of Object.entries(categories)) {
    if (!cat || !cat.ok || !Array.isArray(cat.findings)) { out[key] = cat; continue; }
    const kept = [];
    for (const f of cat.findings) {
      if (isIgnored(f, ignoreSet)) suppressed++;
      else kept.push(f);
    }
    out[key] = { ...cat, findings: kept };
  }
  return { categories: out, suppressed };
}

// 合并:文件策略为底,命令行/显式覆盖在上(纯函数)
export function mergePolicy(filePolicy = {}, overrides = {}) {
  const base = { ...DEFAULT_POLICY, ...filePolicy };
  const merged = { ...base };
  if (overrides.failOn) merged.failOn = overrides.failOn;
  // skip 取并集
  const skip = new Set([...(base.skip || []), ...(overrides.skip || [])]);
  merged.skip = [...skip];
  // ignore 取并集(保留原始条目,normalizeIgnore 时再归一)
  merged.ignore = [...(base.ignore || []), ...(overrides.ignore || [])];
  merged.failOn = String(merged.failOn || "HIGH").toUpperCase();
  return merged;
}

// 从 categories 收集所有发现的稳定 id(cve / id / rule),去重(纯函数,可单测)
export function collectFindingIds(categories) {
  const ids = new Set();
  for (const cat of Object.values(categories || {})) {
    if (!cat || !cat.ok || !Array.isArray(cat.findings)) continue;
    for (const f of cat.findings) {
      const id = f.cve || f.id || f.rule;
      if (id) ids.add(String(id));
    }
  }
  return [...ids];
}

// 基线:把当前全部发现并入现有策略的 ignore(保留已有条目,新项带日期理由)(纯函数,可单测)
export function buildBaseline(categories, existing = {}, { now } = {}) {
  const have = normalizeIgnore(existing.ignore);
  const date = (now || new Date().toISOString()).slice(0, 10);
  const ignore = [...(existing.ignore || [])];
  let added = 0;
  for (const id of collectFindingIds(categories)) {
    if (!have.has(id)) { ignore.push({ id, reason: `baselined ${date}` }); added++; }
  }
  return {
    policy: {
      failOn: String(existing.failOn || "HIGH").toUpperCase(),
      skip: existing.skip || [],
      ignore,
    },
    added,
  };
}

// 读取策略文件:给目录则找 .break-anything.json;给文件则直接读。找不到返回 null(尽力而为)
export async function loadPolicy(targetPath) {
  let file = targetPath;
  try {
    const s = await stat(targetPath);
    if (s.isDirectory()) file = path.join(targetPath, POLICY_FILENAME);
  } catch { /* 路径不存在时按文件名处理 */ }

  try {
    const text = await readFile(file, "utf8");
    const json = JSON.parse(text);
    return { file, policy: json };
  } catch {
    return null;
  }
}
