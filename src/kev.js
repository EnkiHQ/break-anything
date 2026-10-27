import { fetchJson } from "./http.js";

// CISA KEV(Known Exploited Vulnerabilities,已知被在野利用的漏洞目录)。
// 这是权威的「现在正被攻击者利用」信号 —— 比 EPSS 的概率更硬:它是事实,不是预测。
// 数据源是 CISA 官方免费目录(每日更新)。拿不到时降级为空,不影响主流程。

const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

let cache = null; // 进程内缓存:Map(CVE -> { dateAdded, ransomware, name })

// 把 CISA KEV 目录 JSON 归一化成 Map(纯函数,可单测)
export function indexKev(catalog) {
  const map = new Map();
  const list = (catalog && catalog.vulnerabilities) || [];
  for (const v of list) {
    if (!v || !v.cveID) continue;
    map.set(v.cveID.toUpperCase(), {
      dateAdded: v.dateAdded || null,
      ransomware: /^known$/i.test((v.knownRansomwareCampaignUse || "").trim()),
      name: v.vulnerabilityName || null,
    });
  }
  return map;
}

// 给一批 CVE,返回 Map(CVE -> kev 信息);只包含命中 KEV 的。尽力而为。
export async function enrichKev(cves) {
  const unique = [...new Set((cves || []).filter(Boolean).map((c) => c.toUpperCase()))];
  if (!unique.length) return new Map();

  let index = cache;
  if (!index) {
    try {
      const catalog = await fetchJson(KEV_URL, { timeoutMs: 15000 });
      index = cache = indexKev(catalog);
    } catch {
      return new Map(); // 拿不到目录就当作无 KEV 信息
    }
  }

  const out = new Map();
  for (const cve of unique) {
    const hit = index.get(cve);
    if (hit) out.set(cve, hit);
  }
  return out;
}

// 仅供测试:重置缓存
export function _resetKevCache() { cache = null; }
