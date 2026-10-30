// 环境自检:把"你现在能跑哪些能力、还缺什么"一次说清。
// 能力与引擎的映射是纯数据 + 纯函数,可单测;探测二进制与网络的部分单独封装。

import { spawn } from "node:child_process";

// 可选外部引擎(内置能力不列在这里)
export const ENGINES = [
  { bin: "trivy", powers: ["image"], install: "brew install trivy", docs: "https://trivy.dev/latest/getting-started/installation/" },
  { bin: "semgrep", powers: ["sast"], install: "pipx install semgrep(或 brew install semgrep)", docs: "https://semgrep.dev/docs/getting-started/" },
  { bin: "nuclei", powers: ["nuclei"], install: "brew install nuclei", docs: "https://docs.projectdiscovery.io/tools/nuclei/install" },
  { bin: "govulncheck", powers: ["goreach"], install: "go install golang.org/x/vuln/cmd/govulncheck@latest", docs: "https://go.dev/doc/tutorial/govulncheck" },
];

// 全部能力,以及各自是否内置
export const CAPABILITIES = [
  { name: "deps", builtin: true, note: "依赖漏洞(12 个生态)" },
  { name: "secrets", builtin: true, note: "密钥泄露(含 git 历史)" },
  { name: "iac", builtin: true, note: "IaC 错误配置(5 种格式)" },
  { name: "api", builtin: true, note: "API 越权探测(动态,需授权)", dynamic: true },
  { name: "fix", builtin: true, note: "修复计划" },
  { name: "sbom", builtin: true, note: "CycloneDX SBOM" },
  { name: "ci", builtin: true, note: "聚合安全门禁" },
  { name: "image", builtin: false, engine: "trivy", note: "容器镜像 CVE" },
  { name: "sast", builtin: false, engine: "semgrep", note: "静态代码分析" },
  { name: "nuclei", builtin: false, engine: "nuclei", note: "约 14000 条社区模板(动态,需授权)", dynamic: true },
  { name: "goreach", builtin: false, engine: "govulncheck", note: "Go 符号级可达性(真调用图)" },
];

// 给定「已安装引擎集合」,算出每个能力的状态(纯函数,可单测)
export function assessCapabilities(installed) {
  const have = installed instanceof Set ? installed : new Set(installed || []);
  return CAPABILITIES.map((c) => ({
    ...c,
    available: c.builtin || have.has(c.engine),
    missingEngine: c.builtin || have.has(c.engine) ? null : c.engine,
  }));
}

// 动态能力的授权闸门状态(纯函数,可单测)
export function assessDynamicGate(env = process.env) {
  const enabled = env.BRK_DYNAMIC_ENABLED === "true";
  let targets = [];
  try { targets = JSON.parse(env.BRK_AUTHORIZED_TARGETS_JSON || "[]"); } catch { targets = []; }
  if (!Array.isArray(targets)) targets = [];
  return { enabled, targets, ready: enabled && targets.length > 0 };
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

// 探测所有可选引擎,返回 { bin -> path|null }
export async function detectEngines() {
  const entries = await Promise.all(ENGINES.map(async (e) => [e.bin, await which(e.bin)]));
  return Object.fromEntries(entries);
}

export async function runDoctor({ env = process.env } = {}) {
  const [maj, min] = process.versions.node.split(".").map(Number);
  const nodeOk = maj > 18 || (maj === 18 && min >= 17);

  let osv = { ok: false, error: null };
  try {
    const { fetchJson } = await import("./http.js");
    await fetchJson("https://api.osv.dev/v1/query", {
      method: "POST",
      body: { version: "4.17.4", package: { name: "lodash", ecosystem: "npm" } },
      timeoutMs: 8000,
    });
    osv.ok = true;
  } catch (e) { osv.error = e instanceof Error ? e.message : String(e); }

  const enginePaths = await detectEngines();
  const installed = new Set(Object.entries(enginePaths).filter(([, p]) => p).map(([b]) => b));
  const capabilities = assessCapabilities(installed);
  const gate = assessDynamicGate(env);

  return {
    node: { version: process.versions.node, ok: nodeOk },
    osv,
    engines: ENGINES.map((e) => ({ ...e, path: enginePaths[e.bin] || null, installed: !!enginePaths[e.bin] })),
    capabilities,
    dynamicGate: gate,
    summary: {
      available: capabilities.filter((c) => c.available).length,
      total: capabilities.length,
      missingEngines: ENGINES.filter((e) => !enginePaths[e.bin]).map((e) => e.bin),
    },
  };
}
