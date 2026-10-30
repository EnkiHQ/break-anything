// 密钥存活验证:判断挖到的密钥"现在是否还能用"。
// 这是从"有空去轮换"到"立刻停机处理"的分界线。
//
// 安全设计:
//   - 默认关闭,必须显式 --verify 开启(会向凭据所属厂商发一次请求)。
//   - 只调**只读的身份查询**端点(等价于"我是谁"),绝不做任何写操作。
//   - 密钥只在内存里用于构造请求头,绝不写入输出、日志或报告。
//   - 诚实边界:不是所有类型都能验证(例如仅有 AWS Access Key ID、没有 Secret Key 时
//     在密码学上就无法验证),这类如实标为 unsupported,不假装"已确认安全"。

const UA = "break-anything (+https://github.com/EnkiHQ/break-anything)";

// 各类型的只读身份端点。inspectBody 用于"HTTP 200 但业务层说无效"的接口(如 Slack)。
export const VERIFIERS = {
  "github-token": {
    label: "GitHub",
    build: (s) => ({ url: "https://api.github.com/user", headers: { authorization: `Bearer ${s}`, accept: "application/vnd.github+json" } }),
  },
  "gitlab-pat": {
    label: "GitLab",
    build: (s) => ({ url: "https://gitlab.com/api/v4/user", headers: { "private-token": s } }),
  },
  "openai-key": {
    label: "OpenAI",
    build: (s) => ({ url: "https://api.openai.com/v1/models", headers: { authorization: `Bearer ${s}` } }),
  },
  "stripe-secret-key": {
    label: "Stripe",
    build: (s) => ({ url: "https://api.stripe.com/v1/account", headers: { authorization: `Bearer ${s}` } }),
  },
  "slack-token": {
    label: "Slack",
    build: (s) => ({ url: "https://slack.com/api/auth.test", method: "POST", headers: { authorization: `Bearer ${s}` } }),
    // Slack 对无效 token 也回 200,要看 body 里的 ok 字段
    inspectBody: (text) => {
      try { return JSON.parse(text).ok === true ? "active" : "inactive"; } catch { return "unknown"; }
    },
  },
};

// 为什么某些类型无法验证(如实告知,而不是悄悄跳过)
export const UNVERIFIABLE_REASON = {
  "aws-access-key-id": "仅有 Access Key ID、缺少 Secret Key,无法签名请求(密码学上不可验证)",
  "aws-secret-access-key": "需要与之配对的 Access Key ID 才能签名验证",
  "private-key": "私钥需要知道对应的服务/主机才能验证",
  "jwt": "可本地解析过期时间,但签发方是否仍接受无法远程确认",
  "google-api-key": "Google API Key 的有效性取决于启用了哪些服务,无通用只读端点",
  "generic-assigned-secret": "通用模式命中,类型未知,无法确定验证端点",
};

export function isVerifiable(ruleId) {
  return Object.prototype.hasOwnProperty.call(VERIFIERS, ruleId);
}

// 把 HTTP 状态码翻译成存活结论(纯函数,可单测)
export function interpretStatus(status) {
  if (status === 200 || status === 201) return "active";
  if (status === 401 || status === 403) return "inactive";
  if (status === 404) return "unknown";
  if (status === 429) return "unknown";   // 被限流,不能断言
  if (status >= 500) return "unknown";    // 对方故障,不能断言
  return "unknown";
}

// 汇总一批验证结果(纯函数,可单测)
export function summarizeVerification(findings) {
  const out = { active: 0, inactive: 0, unknown: 0, unsupported: 0 };
  for (const f of findings || []) {
    const v = f.verification && f.verification.status;
    if (v && Object.prototype.hasOwnProperty.call(out, v)) out[v]++;
  }
  return out;
}

async function probe({ url, method = "GET", headers = {} }, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { method, headers: { ...headers, "user-agent": UA }, signal: controller.signal, redirect: "manual" });
    const text = await res.text().catch(() => "");
    return { status: res.status, text };
  } finally {
    clearTimeout(timer);
  }
}

// 验证单个密钥。secret 只用于构造请求头,不会出现在返回值里。
export async function verifySecret(ruleId, secret, { timeoutMs = 10000 } = {}) {
  if (!isVerifiable(ruleId)) {
    return { status: "unsupported", reason: UNVERIFIABLE_REASON[ruleId] || "该类型没有可用的只读验证端点" };
  }
  const v = VERIFIERS[ruleId];
  try {
    const { status, text } = await probe(v.build(secret), timeoutMs);
    let verdict = interpretStatus(status);
    if (verdict === "active" && v.inspectBody) verdict = v.inspectBody(text);
    return { status: verdict, provider: v.label, httpStatus: status };
  } catch (e) {
    return { status: "unknown", provider: v.label, error: e instanceof Error ? e.message : String(e) };
  }
}

// 对一批发现做验证(并发受限)。findings 里的 __raw 用完即删,保证不外泄。
export async function verifyFindings(findings, { concurrency = 4, timeoutMs = 10000 } = {}) {
  const list = findings || [];
  let next = 0;
  const workers = new Array(Math.min(concurrency, list.length || 1)).fill(0).map(async () => {
    while (true) {
      const i = next++;
      if (i >= list.length) break;
      const f = list[i];
      const raw = f.__raw;
      if (!raw) { f.verification = { status: "unsupported", reason: "未保留原始值,无法验证" }; continue; }
      f.verification = await verifySecret(f.rule, raw, { timeoutMs });
    }
  });
  await Promise.all(workers);
  for (const f of list) delete f.__raw; // 原始密钥即刻清除,绝不进入输出
  return list;
}
