// 运行时 API 安全探测(DAST)——目前聚焦 OWASP API Top 10 的头号:
// 越权访问(BOLA/IDOR)+ 缺失鉴权 + 安全响应头。
//
// 安全红线:这是会向目标发真实请求的"动态能力",默认关闭。
// 必须同时满足 BRK_DYNAMIC_ENABLED=true 且目标在 BRK_AUTHORIZED_TARGETS_JSON 白名单内。
// 只测你拥有或已获书面授权的目标。

// ---- 授权闸门(纯函数,可单测)----
export function checkAuthorization(baseUrl, env = process.env) {
  if (env.BRK_DYNAMIC_ENABLED !== "true") {
    return { allowed: false, reason: "动态能力默认关闭。设 BRK_DYNAMIC_ENABLED=true 才能对运行中的目标测试。" };
  }
  let allow = [];
  try { allow = JSON.parse(env.BRK_AUTHORIZED_TARGETS_JSON || "[]"); } catch { allow = []; }
  if (!Array.isArray(allow) || !allow.some((a) => typeof a === "string" && baseUrl.startsWith(a))) {
    return { allowed: false, reason: "目标不在授权白名单内。把它加入 BRK_AUTHORIZED_TARGETS_JSON(JSON 数组)。" };
  }
  return { allowed: true };
}

// ---- IDOR 判定(纯函数,可单测)----
// A 用自己的凭据去访问 B 拥有的资源;若拿到 200 且内容正是 B 的私有数据(与 B 自查一致、
// 又不同于 A 自己的),即为越权。
export function decideIdor({ crossStatus, crossBody, truthBody, baselineBody }) {
  if (crossStatus !== 200) return { idor: false };
  const norm = (s) => (s || "").trim();
  const leakedBsData = norm(crossBody) === norm(truthBody) && norm(truthBody).length > 0;
  const differsFromOwn = norm(crossBody) !== norm(baselineBody);
  return { idor: leakedBsData && differsFromOwn };
}

const SECURITY_HEADERS = [
  ["content-security-policy", "MEDIUM"],
  ["strict-transport-security", "LOW"],
  ["x-content-type-options", "LOW"],
  ["x-frame-options", "LOW"],
  ["referrer-policy", "LOW"],
];

async function fetchRaw(url, headers = {}, timeoutMs = 10000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { headers, redirect: "manual", signal: controller.signal });
    const body = await res.text().catch(() => "");
    return { status: res.status, headers: res.headers, body };
  } catch (e) {
    return { error: e instanceof Error ? e.message : String(e) };
  } finally {
    clearTimeout(timer);
  }
}

function redactHeaders(h = {}) {
  const out = {};
  for (const [k, v] of Object.entries(h)) {
    out[k] = /authorization|cookie|token|key|secret/i.test(k) ? "<redacted>" : v;
  }
  return out;
}

// config: { baseUrl, accounts: { A:{headers,ownedId}, B:{headers,ownedId} }, idorPaths: ["/orders/{id}"] }
export async function scanApi(config, env = process.env) {
  const baseUrl = (config.baseUrl || "").replace(/\/$/, "");
  const gate = checkAuthorization(baseUrl, env);
  if (!gate.allowed) {
    return { target: baseUrl, ok: false, engine: "dast", gated: true, message: gate.reason, findings: [], summary: { total: 0, bySeverity: {} } };
  }

  const findings = [];
  const A = config.accounts?.A;
  const B = config.accounts?.B;
  const paths = config.idorPaths || [];

  // 1) 越权(IDOR/BOLA)+ 缺失鉴权
  if (A && B) {
    for (const tmpl of paths) {
      const urlOwn = baseUrl + tmpl.replace(/\{id\}|:id/g, encodeURIComponent(A.ownedId));
      const urlB = baseUrl + tmpl.replace(/\{id\}|:id/g, encodeURIComponent(B.ownedId));
      const [baseline, truth, cross, noauth] = await Promise.all([
        fetchRaw(urlOwn, A.headers), fetchRaw(urlB, B.headers), fetchRaw(urlB, A.headers), fetchRaw(urlB, {}),
      ]);
      if (cross.error || baseline.error || truth.error) continue;

      const verdict = decideIdor({ crossStatus: cross.status, crossBody: cross.body, truthBody: truth.body, baselineBody: baseline.body });
      if (verdict.idor) {
        findings.push({
          rule: "bola-idor", severity: "HIGH",
          title: "Broken Object Level Authorization (IDOR)",
          cwe: "CWE-639", owasp: "API1:2023 - BOLA",
          location: `GET ${tmpl}`,
          evidence: {
            request: `GET ${urlB}`, as: "account A's credentials", headers: redactHeaders(A.headers),
            status: cross.status, note: "returned account B's private resource",
            bodySnippet: (cross.body || "").replace(/\s+/g, " ").slice(0, 160),
          },
          remediation: "Enforce an ownership check server-side: the authenticated subject must own the requested object.",
        });
      }
      if (noauth.status === 200 && (noauth.body || "").trim()) {
        findings.push({
          rule: "missing-auth", severity: "HIGH",
          title: "Missing authentication on resource",
          cwe: "CWE-306", owasp: "API2:2023 - Broken Authentication",
          location: `GET ${tmpl}`,
          evidence: { request: `GET ${urlB}`, as: "no credentials", status: 200, note: "resource returned without any auth" },
          remediation: "Require and verify authentication before returning the resource.",
        });
      }
    }
  }

  // 2) 安全响应头
  const root = await fetchRaw(baseUrl + "/", (A && A.headers) || {});
  if (!root.error && root.headers) {
    for (const [h, sev] of SECURITY_HEADERS) {
      if (!root.headers.get(h)) {
        findings.push({
          rule: `missing-header:${h}`, severity: sev,
          title: `Missing security header: ${h}`, cwe: "CWE-693", owasp: "API8:2023 - Security Misconfiguration",
          location: "response headers", evidence: { request: `GET ${baseUrl}/`, note: `${h} not set` },
          remediation: `Set the ${h} response header.`,
        });
      }
    }
  }

  findings.sort((a, b) => sevRank(b.severity) - sevRank(a.severity));
  return {
    target: baseUrl, ok: true, engine: "dast",
    tested: { idorPaths: paths.length, accounts: A && B ? 2 : 0 },
    findings,
    summary: { total: findings.length, bySeverity: countBy(findings, "severity") },
  };
}

const SEV = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
function sevRank(s) { return SEV[s] ?? 0; }
function countBy(arr, key) { const m = {}; for (const x of arr) m[x[key]] = (m[x[key]] || 0) + 1; return m; }
