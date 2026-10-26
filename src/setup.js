import { readFile, writeFile, mkdir, copyFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";

// 一行把 Break Anything 的 MCP server 注册进本机各家编码 Agent。
// 原则:只探测已安装的 Agent;先备份;只增/改 break-anything 这一个条目,绝不动别的;
// 幂等、可重复运行;坏配置文件只跳过不破坏。

const SERVER_NAME = "break-anything";
const ENTRY = { command: "npx", args: ["-y", "break-anything", "mcp"] };

// 各家 Agent 的配置文件与"已安装"标记目录(覆盖 macOS / Windows / Linux)
export function agents(home = os.homedir(), platform = process.platform, env = process.env) {
  const appData = env.APPDATA || path.join(home, "AppData", "Roaming");
  const claudeDesktop =
    platform === "darwin" ? path.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
    : platform === "win32" ? path.join(appData, "Claude", "claude_desktop_config.json")
    : path.join(home, ".config", "Claude", "claude_desktop_config.json");
  return [
    { id: "claude-desktop", name: "Claude Desktop", file: claudeDesktop, format: "json", markers: [path.dirname(claudeDesktop)] },
    { id: "claude-code", name: "Claude Code", file: path.join(home, ".claude.json"), format: "json", markers: [path.join(home, ".claude.json"), path.join(home, ".claude")] },
    { id: "cursor", name: "Cursor", file: path.join(home, ".cursor", "mcp.json"), format: "json", markers: [path.join(home, ".cursor")] },
    { id: "windsurf", name: "Windsurf", file: path.join(home, ".codeium", "windsurf", "mcp_config.json"), format: "json", markers: [path.join(home, ".codeium", "windsurf"), path.join(home, ".codeium")] },
    { id: "gemini", name: "Gemini CLI", file: path.join(home, ".gemini", "settings.json"), format: "json", markers: [path.join(home, ".gemini")] },
    { id: "codex", name: "Codex", file: path.join(home, ".codex", "config.toml"), format: "toml", markers: [path.join(home, ".codex")] },
  ];
}

function isPresent(agent) {
  return existsSync(agent.file) || agent.markers.some((m) => existsSync(m));
}

// ---- 纯函数(便于单测)----

// JSON:把 break-anything 合并进 mcpServers,保留其它所有内容
export function mergeMcpJson(obj) {
  const next = obj && typeof obj === "object" ? { ...obj } : {};
  next.mcpServers = { ...(next.mcpServers || {}) };
  next.mcpServers[SERVER_NAME] = { ...ENTRY };
  return next;
}

// TOML:是否已有我们的 section
export function tomlHasServer(text) {
  return /\[mcp_servers\.break-anything\]/.test(text || "");
}

// TOML:追加我们的 section(不解析整个文件,只安全追加)
export function appendTomlServer(text) {
  const block =
    `\n[mcp_servers.${SERVER_NAME}]\n` +
    `command = "npx"\n` +
    `args = ["-y", "break-anything", "mcp"]\n`;
  const base = text && !text.endsWith("\n") ? text + "\n" : text || "";
  return base + block;
}

// ---- 应用到单个 Agent ----
async function applyOne(agent, { dryRun }) {
  const existed = existsSync(agent.file);
  let backup = null;

  if (agent.format === "json") {
    let obj = {};
    if (existed) {
      const raw = await readFile(agent.file, "utf8");
      try { obj = raw.trim() ? JSON.parse(raw) : {}; }
      catch { return { agent, status: "skipped", reason: "现有配置不是合法 JSON,未改动(请手动添加)" }; }
      if (obj.mcpServers && obj.mcpServers[SERVER_NAME]) {
        // 已存在且一致则跳过;否则更新
        const cur = JSON.stringify(obj.mcpServers[SERVER_NAME]);
        if (cur === JSON.stringify(ENTRY)) return { agent, status: "already" };
      }
    }
    const next = mergeMcpJson(obj);
    if (dryRun) return { agent, status: existed ? "would-update" : "would-create" };
    await mkdir(path.dirname(agent.file), { recursive: true });
    if (existed) { backup = agent.file + ".bak"; await copyFile(agent.file, backup); }
    await writeFile(agent.file, JSON.stringify(next, null, 2) + "\n");
    return { agent, status: existed ? "updated" : "created", backup };
  }

  // toml (Codex)
  let text = existed ? await readFile(agent.file, "utf8") : "";
  if (tomlHasServer(text)) return { agent, status: "already" };
  if (dryRun) return { agent, status: existed ? "would-update" : "would-create" };
  await mkdir(path.dirname(agent.file), { recursive: true });
  if (existed) { backup = agent.file + ".bak"; await copyFile(agent.file, backup); }
  await writeFile(agent.file, appendTomlServer(text));
  return { agent, status: existed ? "updated" : "created", backup };
}

// ---- 入口 ----
export async function runSetup({ dryRun = false, home, platform, env } = {}) {
  const all = agents(home, platform, env);
  const present = all.filter(isPresent);
  const absent = all.filter((a) => !isPresent(a));
  const results = [];
  for (const a of present) {
    try { results.push(await applyOne(a, { dryRun })); }
    catch (e) { results.push({ agent: a, status: "error", reason: e instanceof Error ? e.message : String(e) }); }
  }
  return { results, absent, anyPresent: present.length > 0 };
}

export const manualConfig = {
  mcpServers: { [SERVER_NAME]: ENTRY },
};
