#!/usr/bin/env node
import { scanDependencies } from "../src/scan.js";
import { renderHuman } from "../src/report.js";

const VERSION = "0.2.0";

const HELP = `Break Anything (brk) v${VERSION}
点你的 Agent 指向你拥有或已授权的软件,找到漏洞、证明它、修好它。

用法:
  brk deps [path]        扫描依赖 lockfile 的已知漏洞(默认当前目录)
  brk secrets [path]     扫描泄露的密钥(工作区,--history 加扫 git 历史)
  brk image <ref>        扫描容器镜像的已知漏洞(需 trivy)
  brk sast [path]        静态代码分析找漏洞(需 semgrep)
  brk mcp                以 MCP server 模式启动(供 Agent 调用)
  brk doctor             检查运行环境与网络连通性
  brk setup              打印把 Break Anything 接入 Agent 的 MCP 配置
  brk --help             显示本帮助
  brk --version          显示版本

通用选项:
  --json                 输出 JSON(用于脚本 / Agent)
  --no-color             关闭彩色输出
deps 选项:
  --no-reachability      跳过源码可达性初判
secrets 选项:
  --history              加扫 git 历史中的密钥

范围声明:只对你拥有、或已获得明确授权的目标使用。详见 DISCLAIMER.md。
`;

function parseFlags(argv) {
  const flags = {};
  const positional = [];
  for (const a of argv) {
    if (a === "--json") flags.json = true;
    else if (a === "--no-reachability") flags.reachability = false;
    else if (a === "--no-color") flags.color = false;
    else if (a.startsWith("--") && a.includes("=")) { const [k, v] = a.slice(2).split("="); flags[k] = v; }
    else if (a.startsWith("--")) flags[a.slice(2)] = true;
    else positional.push(a);
  }
  return { flags, positional };
}

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);

  if (!cmd || cmd === "--help" || cmd === "-h" || cmd === "help") {
    process.stdout.write(HELP);
    return;
  }
  if (cmd === "--version" || cmd === "-v") {
    process.stdout.write(VERSION + "\n");
    return;
  }

  if (cmd === "mcp") {
    const { startMcpServer } = await import("../src/mcp.js");
    await startMcpServer();
    return; // 保持进程存活
  }

  if (cmd === "deps") {
    const { flags, positional } = parseFlags(rest);
    const target = positional[0] || process.cwd();
    const result = await scanDependencies(target, {
      reachability: flags.reachability !== false,
    });
    if (flags.json) {
      process.stdout.write(JSON.stringify(result, null, 2) + "\n");
    } else {
      const color = flags.color !== false && process.stdout.isTTY;
      process.stdout.write(renderHuman(result, { color, top: flags.top ? Number(flags.top) : undefined }) + "\n");
    }
    // 有高危且可达的发现时用非零退出码,方便接 CI
    const hasReachableHigh = result.findings?.some(
      (f) => f.reachability === "imported" && (f.severity === "CRITICAL" || f.severity === "HIGH"),
    );
    process.exitCode = hasReachableHigh ? 1 : 0;
    return;
  }

  if (cmd === "secrets") {
    const { flags, positional } = parseFlags(rest);
    const target = positional[0] || process.cwd();
    const { scanSecrets } = await import("../src/secrets.js");
    const { renderSecrets } = await import("../src/report.js");
    const result = await scanSecrets(target, { history: !!flags.history });
    if (flags.json) {
      process.stdout.write(JSON.stringify(result, null, 2) + "\n");
    } else {
      const color = flags.color !== false && process.stdout.isTTY;
      process.stdout.write(renderSecrets(result, { color }) + "\n");
    }
    process.exitCode = result.findings.length ? 1 : 0;
    return;
  }

  if (cmd === "image") {
    const { flags, positional } = parseFlags(rest);
    const ref = positional[0];
    if (!ref) {
      process.stderr.write("用法:brk image <镜像引用>,例如 brk image nginx:1.21\n");
      process.exitCode = 2;
      return;
    }
    const { scanImage } = await import("../src/image.js");
    const { renderImage } = await import("../src/report.js");
    const result = await scanImage(ref);
    if (flags.json) {
      process.stdout.write(JSON.stringify(result, null, 2) + "\n");
    } else {
      const color = flags.color !== false && process.stdout.isTTY;
      process.stdout.write(renderImage(result, { color }) + "\n");
    }
    const hasHigh = result.findings?.some((f) => f.severity === "CRITICAL" || f.severity === "HIGH");
    process.exitCode = hasHigh ? 1 : 0;
    return;
  }

  if (cmd === "sast") {
    const { flags, positional } = parseFlags(rest);
    const target = positional[0] || process.cwd();
    const { scanSast } = await import("../src/sast.js");
    const { renderSast } = await import("../src/report.js");
    const result = await scanSast(target, flags.config ? { config: flags.config } : {});
    if (flags.json) {
      process.stdout.write(JSON.stringify(result, null, 2) + "\n");
    } else {
      const color = flags.color !== false && process.stdout.isTTY;
      process.stdout.write(renderSast(result, { color, top: flags.top ? Number(flags.top) : undefined }) + "\n");
    }
    const hasHigh = result.findings?.some((f) => f.severity === "CRITICAL" || f.severity === "HIGH");
    process.exitCode = hasHigh ? 1 : 0;
    return;
  }

  if (cmd === "doctor") {
    await doctor();
    return;
  }

  if (cmd === "setup") {
    printSetup();
    return;
  }

  process.stderr.write(`未知命令:${cmd}\n\n${HELP}`);
  process.exitCode = 2;
}

async function doctor() {
  const out = [];
  const [maj] = process.versions.node.split(".").map(Number);
  out.push(`Node.js ${process.versions.node} ${maj >= 18 ? "✓" : "✗ 需要 >= 18.17"}`);
  try {
    const { fetchJson } = await import("../src/http.js");
    await fetchJson("https://api.osv.dev/v1/query", {
      method: "POST",
      body: { version: "4.17.4", package: { name: "lodash", ecosystem: "npm" } },
      timeoutMs: 8000,
    });
    out.push("OSV API 可达 ✓");
  } catch (e) {
    out.push(`OSV API 不可达 ✗ (${e instanceof Error ? e.message : e})`);
  }
  process.stdout.write(out.join("\n") + "\n");
}

function printSetup() {
  const config = {
    mcpServers: {
      "break-anything": { command: "npx", args: ["-y", "break-anything", "mcp"] },
    },
  };
  process.stdout.write(
    "把下面的配置加入你的 MCP 客户端(Claude Code / Cursor / Codex 等):\n\n" +
      JSON.stringify(config, null, 2) +
      "\n\n然后重启 Agent,对它说:用 Break Anything 扫描我的项目依赖。\n",
  );
}

main().catch((err) => {
  process.stderr.write(`错误:${err instanceof Error ? err.stack || err.message : String(err)}\n`);
  process.exitCode = 1;
});
