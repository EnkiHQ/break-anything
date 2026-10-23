import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { scanDependencies } from "./scan.js";
import { scanSecrets } from "./secrets.js";
import { scanImage } from "./image.js";

const TOOLS = [
  {
    name: "deps_scan",
    description:
      "Scan a project's dependency lockfiles (npm package-lock.json, PHP composer.lock, " +
      "Python requirements.txt) for known vulnerabilities via OSV. Returns findings ranked by " +
      "severity, reachability (is the package actually imported in the project source), and EPSS " +
      "exploit probability, with fix versions. Point this only at code you own or are authorized " +
      "to test.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Absolute path to the project directory (or a lockfile) to scan.",
        },
        reachability: {
          type: "boolean",
          description: "Compute import-based reachability heuristic from project source. Default true.",
        },
      },
      required: ["path"],
    },
  },
  {
    name: "secrets_scan",
    description:
      "Scan a project for leaked secrets (API keys, tokens, private keys) in the working tree " +
      "and, optionally, the full git history. Matches are redacted in the output. Runs locally. " +
      "Point this only at repositories you own or are authorized to test.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Absolute path to the repository to scan." },
        history: { type: "boolean", description: "Also scan git history (git log -p). Default false." },
      },
      required: ["path"],
    },
  },
  {
    name: "image_scan",
    description:
      "Scan a container image for known vulnerabilities using Trivy. Returns OS and application " +
      "package CVEs ranked by severity, with fix versions. Requires Trivy to be installed. " +
      "Scan only images you own or are authorized to test.",
    inputSchema: {
      type: "object",
      properties: {
        ref: { type: "string", description: "Image reference, e.g. nginx:1.21 or my-service:latest." },
      },
      required: ["ref"],
    },
  },
];

export async function startMcpServer() {
  const server = new Server(
    { name: "break-anything", version: "0.1.0" },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: args = {} } = req.params;
    try {
      let result;
      if (name === "deps_scan") {
        if (!strArg(args.path)) return bad("缺少必填参数 path。");
        result = await scanDependencies(args.path, { reachability: args.reachability !== false });
      } else if (name === "secrets_scan") {
        if (!strArg(args.path)) return bad("缺少必填参数 path。");
        result = await scanSecrets(args.path, { history: !!args.history });
      } else if (name === "image_scan") {
        if (!strArg(args.ref)) return bad("缺少必填参数 ref。");
        result = await scanImage(args.ref);
      } else {
        return bad(`Unknown tool: ${name}`);
      }
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { isError: true, content: [{ type: "text", text: `扫描失败:${msg}` }] };
    }
  });

  function strArg(v) { return typeof v === "string" && v.length > 0; }
  function bad(text) { return { isError: true, content: [{ type: "text", text }] }; }

  const transport = new StdioServerTransport();
  await server.connect(transport);
  // stdio 模式下不要往 stdout 写任何非协议内容;日志走 stderr
  process.stderr.write("break-anything MCP server 已启动(stdio)。\n");
}
