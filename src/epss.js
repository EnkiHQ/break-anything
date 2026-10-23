import { fetchJson } from "./http.js";

// EPSS:给定一批 CVE,返回 { CVE -> { epss, percentile } }(尽力而为,失败则空)
export async function enrichEpss(cves) {
  const unique = [...new Set(cves.filter(Boolean))];
  if (!unique.length) return new Map();
  const out = new Map();
  // FIRST.org 支持逗号分隔批量查询,分批避免 URL 过长
  const batches = chunk(unique, 50);
  for (const batch of batches) {
    try {
      const url = `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(batch.join(","))}`;
      const data = await fetchJson(url, { timeoutMs: 10000 });
      for (const row of data.data || []) {
        out.set(row.cve, { epss: Number(row.epss), percentile: Number(row.percentile) });
      }
    } catch {
      // EPSS 是增益信息,拿不到就跳过,不影响主流程
    }
  }
  return out;
}

function chunk(arr, n) {
  const out = [];
  for (let i = 0; i < arr.length; i += n) out.push(arr.slice(i, i + n));
  return out;
}
