#!/usr/bin/env node
import { scanDependencies } from "../src/scan.js";
import { renderHuman } from "../src/report.js";

const VERSION = "0.17.0";

const HELP = `Break Anything (brk) v${VERSION}
点你的 Agent 指向你拥有或已授权的软件,找到漏洞、证明它、修好它。

用法:
  brk deps [path]        扫描依赖的已知漏洞(npm/PHP/Python/Go/Rust/Ruby/Java/.NET,默认当前目录)
  brk secrets [path]     扫描泄露的密钥(工作区,--history 加扫 git 历史)
  brk image <ref>        扫描容器镜像的已知漏洞(需 trivy)
  brk sast [path]        静态代码分析找漏洞(需 semgrep)
  brk iac [path]         扫描 IaC 错误配置(Dockerfile/Kubernetes/Terraform,内置,免安装)
  brk api <baseUrl>      对运行中的 API 做越权(IDOR)/鉴权检测(动态,默认关闭,需授权)
  brk fix [path]         把依赖扫描结果变成按优先级排序的修复计划(含升级命令)
  brk sbom [path]        生成 CycloneDX SBOM(--out 写文件,--diff 旧SBOM 比对变更)
  brk ci [path]          一条命令跑完 deps+secrets+iac+sast,聚合成一份报告 + 一个门禁退出码
  brk mcp                以 MCP server 模式启动(供 Agent 调用)
  brk doctor             检查运行环境与网络连通性
  brk setup              自动把 Break Anything 注册进本机各家 Agent(--dry-run 预演,--print 仅打印配置)
  brk --help             显示本帮助
  brk --version          显示版本

通用选项:
  --json                 输出 JSON(用于脚本 / Agent)
  --sarif                输出 SARIF 2.1.0(deps/sast/iac/secrets,喂给 GitHub 代码扫描)
  --no-color             关闭彩色输出
deps 选项:
  --no-reachability      跳过源码可达性初判
secrets 选项:
  --history              加扫 git 历史中的密钥
ci 选项:
  --fail-on=<sev>        门禁阈值 critical|high|medium|low(默认 high)
  --skip=a,b             跳过某些类别(deps,secrets,iac,sast)
  --policy=<file>        指定策略文件(默认读目标目录下 .break-anything.json)
  --baseline             把当前全部发现写进策略 ignore,门禁此后只卡新增
  --sarif                把全部类别合并成一份 SARIF 输出
  策略文件 .break-anything.json:{ "failOn", "skip":[], "ignore":[CVE/规则ID…] }

范围声明:只对你拥有、或已获得明确授权的目标使用。详见 DISCLAIMER.md。
`;

// 这些 flag 接受一个值,支持 --key=value 与 --key value 两种写法
const VALUE_FLAGS = new Set(["config", "top", "from", "diff", "out", "fail-on", "skip", "policy"]);

function parseFlags(argv) {
  const flags = {};
  const positional = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--json") flags.json = true;
    else if (a === "--no-reachability") flags.reachability = false;
    else if (a === "--no-color") flags.color = false;
    else if (a.startsWith("--") && a.includes("=")) { const [k, v] = a.slice(2).split("="); flags[k] = v; }
    else if (a.startsWith("--")) {
      const k = a.slice(2);
      if (VALUE_FLAGS.has(k) && i + 1 < argv.length && !argv[i + 1].startsWith("--")) {
        flags[k] = argv[++i];
      } else {
        flags[k] = true;
      }
    } else positional.push(a);
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
    if (flags.sarif) {
      const { toSarif } = await import("../src/sarif.js");
      process.stdout.write(JSON.stringify(toSarif("deps", result), null, 2) + "\n");
    } else if (flags.json) {
      process.stdout.write(JSON.stringify(result, null, 2) + "\n");
    } else {
      const color = flags.color !== false && process.stdout.isTTY;
      process.stdout.write(renderHuman(result, { color, top: flags.top ? Number(flags.top) : undefined }) + "\n");
    }
    // 有高危且可达(被调用/已引用)的发现时用非零退出码,方便接 CI
    const hasReachableHigh = result.findings?.some(
      (f) => (f.reachability === "called" || f.reachability === "imported") && (f.severity === "CRITICAL" || f.severity === "HIGH"),
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
    if (flags.sarif) {
      const { toSarif } = await import("../src/sarif.js");
      process.stdout.write(JSON.stringify(toSarif("secrets", result), null, 2) + "\n");
    } else if (flags.json) {
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
    if (flags.sarif) {
      const { toSarif } = await import("../src/sarif.js");
      process.stdout.write(JSON.stringify(toSarif("sast", result), null, 2) + "\n");
    } else if (flags.json) {
      process.stdout.write(JSON.stringify(result, null, 2) + "\n");
    } else {
      const color = flags.color !== false && process.stdout.isTTY;
      process.stdout.write(renderSast(result, { color, top: flags.top ? Number(flags.top) : undefined }) + "\n");
    }
    const hasHigh = result.findings?.some((f) => f.severity === "CRITICAL" || f.severity === "HIGH");
    process.exitCode = hasHigh ? 1 : 0;
    return;
  }

  if (cmd === "iac") {
    const { flags, positional } = parseFlags(rest);
    const target = positional[0] || process.cwd();
    const { scanIac } = await import("../src/iac.js");
    const { renderIac } = await import("../src/report.js");
    const result = await scanIac(target);
    if (flags.sarif) {
      const { toSarif } = await import("../src/sarif.js");
      process.stdout.write(JSON.stringify(toSarif("iac", result), null, 2) + "\n");
    } else if (flags.json) {
      process.stdout.write(JSON.stringify(result, null, 2) + "\n");
    } else {
      const color = flags.color !== false && process.stdout.isTTY;
      process.stdout.write(renderIac(result, { color, top: flags.top ? Number(flags.top) : undefined }) + "\n");
    }
    const hasHigh = result.findings?.some((f) => f.severity === "CRITICAL" || f.severity === "HIGH");
    process.exitCode = hasHigh ? 1 : 0;
    return;
  }

  if (cmd === "api") {
    const { flags, positional } = parseFlags(rest);
    const base = positional[0];
    if (!base) { process.stderr.write("用法:brk api <baseUrl> [--config accounts.json]\n"); process.exitCode = 2; return; }
    let cfg = { baseUrl: base, accounts: {}, idorPaths: [] };
    if (flags.config) {
      const fs = await import("node:fs/promises");
      try { const j = JSON.parse(await fs.readFile(flags.config, "utf8")); cfg = { ...j, baseUrl: base }; }
      catch (e) { process.stderr.write(`读取 --config 失败:${e instanceof Error ? e.message : e}\n`); process.exitCode = 2; return; }
    }
    const { scanApi } = await import("../src/api.js");
    const { renderApi } = await import("../src/report.js");
    const result = await scanApi(cfg);
    if (flags.json) {
      process.stdout.write(JSON.stringify(result, null, 2) + "\n");
    } else {
      const color = flags.color !== false && process.stdout.isTTY;
      process.stdout.write(renderApi(result, { color }) + "\n");
    }
    const hasHigh = result.findings?.some((f) => f.severity === "CRITICAL" || f.severity === "HIGH");
    process.exitCode = hasHigh ? 1 : 0;
    return;
  }

  if (cmd === "fix") {
    const { flags, positional } = parseFlags(rest);
    const target = positional[0] || process.cwd();
    const { fixDependencies } = await import("../src/fix.js");
    const { renderFix } = await import("../src/report.js");
    let opts = { reachability: flags.reachability !== false };
    if (flags.from) {
      const fs = await import("node:fs/promises");
      try {
        const j = JSON.parse(await fs.readFile(flags.from, "utf8"));
        opts.findings = Array.isArray(j) ? j : j.findings;
      } catch (e) {
        process.stderr.write(`读取 --from 失败:${e instanceof Error ? e.message : e}\n`);
        process.exitCode = 2;
        return;
      }
    }
    const result = await fixDependencies(target, opts);
    if (flags.json) {
      process.stdout.write(JSON.stringify(result, null, 2) + "\n");
    } else {
      const color = flags.color !== false && process.stdout.isTTY;
      process.stdout.write(renderFix(result, { color }) + "\n");
    }
    process.exitCode = result.summary?.upgradeCount || result.summary?.noFixCount ? 1 : 0;
    return;
  }

  if (cmd === "sbom") {
    const { flags, positional } = parseFlags(rest);
    const target = positional[0] || process.cwd();
    const { generateSbom, diffSbom } = await import("../src/sbom.js");
    const { renderSbomDiff } = await import("../src/report.js");
    const res = await generateSbom(target);
    if (!res.ok) { process.stderr.write(res.message + "\n"); process.exitCode = 2; return; }

    if (flags.diff) {
      const fs = await import("node:fs/promises");
      let oldBom;
      try { oldBom = JSON.parse(await fs.readFile(flags.diff, "utf8")); }
      catch (e) { process.stderr.write(`读取 --diff 失败:${e instanceof Error ? e.message : e}\n`); process.exitCode = 2; return; }
      const d = diffSbom(oldBom, res.bom);
      if (flags.json) process.stdout.write(JSON.stringify(d, null, 2) + "\n");
      else { const color = flags.color !== false && process.stdout.isTTY; process.stdout.write(renderSbomDiff(d, { color }) + "\n"); }
      process.exitCode = d.summary.added || d.summary.removed || d.summary.changed ? 1 : 0;
      return;
    }

    const json = JSON.stringify(res.bom, null, 2);
    if (flags.out) {
      const fs = await import("node:fs/promises");
      await fs.writeFile(flags.out, json + "\n");
      process.stderr.write(`已写入 ${res.componentCount} 个组件的 CycloneDX SBOM → ${flags.out}\n`);
    } else {
      process.stdout.write(json + "\n");
    }
    return;
  }

  if (cmd === "ci") {
    const { flags, positional } = parseFlags(rest);
    const target = positional[0] || process.cwd();
    const skipFlag = typeof flags.skip === "string" ? flags.skip.split(",").map((s) => s.trim()).filter(Boolean) : [];
    const { runCi } = await import("../src/ci.js");
    const { loadPolicy, mergePolicy } = await import("../src/policy.js");
    const loaded = await loadPolicy(flags.policy || target);
    const policy = mergePolicy(loaded?.policy || {}, {
      failOn: flags["fail-on"] ? String(flags["fail-on"]).toUpperCase() : undefined,
      skip: skipFlag,
    });
    if (flags.baseline) {
      // 基线模式:扫出当前全部发现(不套用 ignore),写进策略文件,让门禁此后只卡新增
      const { buildBaseline } = await import("../src/policy.js");
      const scan = await runCi(target, { failOn: policy.failOn, skip: policy.skip, ignore: [] });
      const { policy: baselined, added } = buildBaseline(scan.categories, loaded?.policy || { failOn: policy.failOn, skip: policy.skip });
      const fs = await import("node:fs/promises");
      const pathMod = await import("node:path");
      const outFile = typeof flags.baseline === "string" ? flags.baseline
        : (flags.policy || pathMod.join(target, ".break-anything.json"));
      await fs.writeFile(outFile, JSON.stringify(baselined, null, 2) + "\n");
      process.stdout.write(`已基线化 ${added} 条当前发现 → ${outFile}\n现在起 brk ci 只会对“新增”发现触发门禁。\n`);
      return;
    }

    const result = await runCi(target, { failOn: policy.failOn, skip: policy.skip, ignore: policy.ignore });
    if (loaded) result.policy.source = loaded.file;
    if (flags.sarif) {
      const { toSarifMulti } = await import("../src/sarif.js");
      const entries = Object.entries(result.categories).map(([kind, res]) => ({ kind, result: res }));
      process.stdout.write(JSON.stringify(toSarifMulti(entries), null, 2) + "\n");
    } else if (flags.json) {
      process.stdout.write(JSON.stringify(result, null, 2) + "\n");
    } else {
      const { renderCi } = await import("../src/report.js");
      const color = flags.color !== false && process.stdout.isTTY;
      process.stdout.write(renderCi(result, { color }) + "\n");
    }
    process.exitCode = result.gate.passed ? 0 : 1;
    return;
  }

  if (cmd === "doctor") {
    await doctor();
    return;
  }

  if (cmd === "setup") {
    const { flags } = parseFlags(rest);
    const { runSetup, manualConfig } = await import("../src/setup.js");
    if (flags.print) {
      process.stdout.write(
        "把下面的配置加入你的 MCP 客户端,然后重启 Agent:\n\n" +
          JSON.stringify(manualConfig, null, 2) + "\n",
      );
      return;
    }
    const dry = !!flags["dry-run"];
    const { results, absent, anyPresent } = await runSetup({ dryRun: dry });
    process.stdout.write(`Break Anything · setup${dry ? " (dry run)" : ""}\n\n`);
    if (!anyPresent) {
      process.stdout.write(
        "未检测到受支持的 Agent。把下面的配置手动加入你的 MCP 客户端:\n\n" +
          JSON.stringify(manualConfig, null, 2) + "\n",
      );
      return;
    }
    const label = {
      created: "✓ 已注册(新建配置)", updated: "✓ 已注册", already: "• 已存在,无需改动",
      "would-create": "将新建并注册", "would-update": "将注册",
      skipped: "⚠ 跳过", error: "✗ 出错",
    };
    for (const r of results) {
      process.stdout.write(`  ${label[r.status] || r.status}  ${r.agent.name}\n`);
      process.stdout.write(`      ${r.agent.file}\n`);
      if (r.backup) process.stdout.write(`      已备份原配置 → ${r.backup}\n`);
      if (r.reason) process.stdout.write(`      ${r.reason}\n`);
    }
    if (absent.length) process.stdout.write(`\n未检测到(已跳过):${absent.map((a) => a.name).join("、")}\n`);
    if (!dry) process.stdout.write(`\n重启你的 Agent,然后对它说:"用 Break Anything 扫描我的项目"。\n`);
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

main().catch((err) => {
  process.stderr.write(`错误:${err instanceof Error ? err.stack || err.message : String(err)}\n`);
  process.exitCode = 1;
});
