// 带超时的 fetch 封装,所有外部请求都走这里
export async function fetchJson(url, { method = "GET", body, timeoutMs = 15000, headers = {} } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method,
      signal: controller.signal,
      headers: {
        "accept": "application/json",
        ...(body ? { "content-type": "application/json" } : {}),
        "user-agent": "break-anything/0.1 (+https://github.com/EnkiHQ/break-anything)",
        ...headers,
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`HTTP ${res.status} ${res.statusText} for ${url}${text ? ` — ${text.slice(0, 200)}` : ""}`);
    }
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

// 简单并发池:对一组 item 以受限并发执行 worker,保序返回结果
export async function mapPool(items, concurrency, worker) {
  const results = new Array(items.length);
  let next = 0;
  const runners = new Array(Math.min(concurrency, items.length)).fill(0).map(async () => {
    while (true) {
      const i = next++;
      if (i >= items.length) break;
      try {
        results[i] = await worker(items[i], i);
      } catch (err) {
        results[i] = { __error: err instanceof Error ? err.message : String(err) };
      }
    }
  });
  await Promise.all(runners);
  return results;
}
