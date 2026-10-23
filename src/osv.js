import { fetchJson, mapPool } from "./http.js";

const OSV_QUERY = "https://api.osv.dev/v1/query";

// 对单个「包@版本」查询 OSV 已知漏洞
async function queryOne(pkg) {
  const data = await fetchJson(OSV_QUERY, {
    method: "POST",
    body: { version: pkg.version, package: { name: pkg.name, ecosystem: pkg.ecosystem } },
  });
  const vulns = Array.isArray(data.vulns) ? data.vulns : [];
  return vulns.map((v) => normalizeVuln(v, pkg));
}

// 把 OSV 的原始漏洞记录归一化成我们统一的发现结构
function normalizeVuln(v, pkg) {
  const aliases = Array.isArray(v.aliases) ? v.aliases : [];
  const cve = aliases.find((a) => /^CVE-/i.test(a)) || null;
  return {
    id: v.id,
    cve,
    aliases,
    summary: v.summary || (v.details ? v.details.slice(0, 160) : ""),
    severity: extractSeverity(v),
    fixedVersions: extractFixedVersions(v, pkg),
    references: (v.references || []).map((r) => r.url).slice(0, 5),
  };
}

// 严重度:优先用 database_specific.severity(GHSA 的 HIGH/MODERATE…),否则从 CVSS 推
function extractSeverity(v) {
  const label = v.database_specific?.severity;
  if (typeof label === "string" && label) return label.toUpperCase();
  const cvss = (v.severity || []).find((s) => /CVSS/i.test(s.type));
  if (cvss?.score) {
    const base = parseBaseFromVector(cvss.score);
    if (base != null) return scoreToLabel(base);
  }
  return "UNKNOWN";
}

function parseBaseFromVector(vectorOrScore) {
  const num = Number(vectorOrScore);
  if (!Number.isNaN(num)) return num;
  return null; // 不在 MVP 里完整解析 CVSS 向量
}

function scoreToLabel(base) {
  if (base >= 9) return "CRITICAL";
  if (base >= 7) return "HIGH";
  if (base >= 4) return "MEDIUM";
  if (base > 0) return "LOW";
  return "UNKNOWN";
}

// 从 affected[].ranges[].events[] 里抽出匹配本包的「fixed」版本
function extractFixedVersions(v, pkg) {
  const out = new Set();
  for (const aff of v.affected || []) {
    if (aff.package?.name !== pkg.name) continue;
    if (aff.package?.ecosystem && pkg.ecosystem && aff.package.ecosystem !== pkg.ecosystem) continue;
    for (const range of aff.ranges || []) {
      for (const ev of range.events || []) {
        if (ev.fixed) out.add(ev.fixed);
      }
    }
  }
  return [...out];
}

const SEVERITY_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
export function severityRank(label) {
  return SEVERITY_ORDER[label] ?? 0;
}

// 批量查询:对一组包并发查 OSV,返回「有漏洞的包 + 其漏洞列表」
export async function scanPackages(packages, { concurrency = 8 } = {}) {
  const results = await mapPool(packages, concurrency, async (pkg) => {
    const vulns = await queryOne(pkg);
    return { pkg, vulns };
  });
  const findings = [];
  const errors = [];
  results.forEach((r, i) => {
    if (r?.__error) {
      errors.push({ pkg: packages[i], error: r.__error });
      return;
    }
    if (r.vulns.length) findings.push(r);
  });
  return { findings, errors };
}
