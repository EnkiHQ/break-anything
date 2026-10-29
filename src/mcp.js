import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { scanDependencies } from "./scan.js";
import { scanSecrets } from "./secrets.js";
import { scanImage } from "./image.js";
import { scanSast } from "./sast.js";
import { scanApi } from "./api.js";
import { scanIac } from "./iac.js";
import { fixDependencies } from "./fix.js";
import { generateSbom } from "./sbom.js";
import { runCi } from "./ci.js";

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
  {
    name: "sast_scan",
    description:
      "Static application security testing (SAST) on a source tree using Semgrep. Finds injection, " +
      "broken access control, insecure deserialization, SSRF, hardcoded secrets and more, each with " +
      "file/line, CWE/OWASP tags, and the offending snippet. Requires Semgrep to be installed. " +
      "Scan only code you own or are authorized to test.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Absolute path to the source tree to scan." },
        config: { type: "string", description: "Semgrep ruleset (default p/security-audit)." },
      },
      required: ["path"],
    },
  },
  {
    name: "ci_scan",
    description:
      "Run a full repository security gate in one call: dependencies (SCA), secrets, IaC, and SAST, " +
      "aggregated into one result with a pass/fail gate. The gate fails on reachable or known-exploited " +
      "(KEV) dependency vulns, any leaked secret, and IaC/code issues at or above the failOn severity " +
      "(default HIGH). Returns per-category findings, a combined summary, and the gate verdict with reasons.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Absolute path to the project to scan." },
        failOn: { type: "string", description: "Gate threshold: critical|high|medium|low. Default high." },
        skip: { type: "array", items: { type: "string" }, description: "Categories to skip: deps, secrets, iac, sast." },
        ignore: { type: "array", items: { type: "string" }, description: "Finding IDs to suppress (CVE, rule id). Also read from .break-anything.json." },
      },
      required: ["path"],
    },
  },
  {
    name: "sbom_generate",
    description:
      "Generate a CycloneDX 1.5 SBOM (software bill of materials) for a project across all supported " +
      "ecosystems (npm, PyPI, Composer, Go, Rust, Ruby, Maven, NuGet). Each component has a package " +
      "URL (purl). Pure, local, no network. Use it to archive, audit, or diff dependency composition.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Absolute path to the project to generate an SBOM for." },
      },
      required: ["path"],
    },
  },
  {
    name: "fix_plan",
    description:
      "Turn dependency findings into a prioritized, actionable remediation plan. Scans the project " +
      "(or accepts findings directly), groups CVEs by package, computes the minimal safe upgrade " +
      "that resolves the most CVEs per package, and orders the work by reachability (called first) " +
      "then severity — with the exact upgrade command per ecosystem (npm/pip/composer). Packages " +
      "with no upstream fix are listed separately with mitigation guidance. Targets are minimal " +
      "safe-version suggestions to validate with your tests.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Absolute path to the project to scan and plan fixes for." },
        reachability: { type: "boolean", description: "Compute reachability while scanning. Default true." },
      },
      required: ["path"],
    },
  },
  {
    name: "iac_scan",
    description:
      "Scan infrastructure-as-code for high-impact misconfigurations: Dockerfiles (root user, " +
      ":latest, piped remote shell, baked-in secrets), Kubernetes manifests (privileged containers, " +
      "host namespaces, dangerous capabilities), and Terraform (world-open CIDRs, public buckets, " +
      "disabled encryption, hardcoded secrets). Built in, no external engine required. Each finding " +
      "has file/line, CWE, evidence, and a fix. Scan only code you own or are authorized to test.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Absolute path to the directory (or a single IaC file) to scan." },
      },
      required: ["path"],
    },
  },
  {
    name: "api_scan",
    description:
      "Dynamic probe of a running HTTP API for broken object-level authorization (IDOR/BOLA), " +
      "missing authentication, and missing security headers — returns the reproducing request as " +
      "proof. DYNAMIC, OFF BY DEFAULT: requires BRK_DYNAMIC_ENABLED=true and the target listed in " +
      "BRK_AUTHORIZED_TARGETS_JSON. Only test APIs you own or are authorized to test.",
    inputSchema: {
      type: "object",
      properties: {
        baseUrl: { type: "string", description: "Base URL of the API, e.g. http://localhost:4000" },
        accounts: {
          type: "object",
          description: "Two accounts you control: { \"A\": {\"headers\": {\"Authorization\": \"Bearer ...\"}, \"ownedId\": \"1\"}, \"B\": {...} }",
        },
        idorPaths: {
          type: "array",
          items: { type: "string" },
          description: "Path templates with {id}, e.g. [\"/orders/{id}\"].",
        },
      },
      required: ["baseUrl"],
    },
  },
];

export async function startMcpServer() {
  const server = new Server(
    { name: "break-anything", version: "0.20.0" },
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
      } else if (name === "sast_scan") {
        if (!strArg(args.path)) return bad("缺少必填参数 path。");
        result = await scanSast(args.path, args.config ? { config: args.config } : {});
      } else if (name === "iac_scan") {
        if (!strArg(args.path)) return bad("缺少必填参数 path。");
        result = await scanIac(args.path);
      } else if (name === "fix_plan") {
        if (!strArg(args.path)) return bad("缺少必填参数 path。");
        result = await fixDependencies(args.path, { reachability: args.reachability !== false });
      } else if (name === "sbom_generate") {
        if (!strArg(args.path)) return bad("缺少必填参数 path。");
        result = await generateSbom(args.path);
      } else if (name === "ci_scan") {
        if (!strArg(args.path)) return bad("缺少必填参数 path。");
        result = await runCi(args.path, {
          failOn: (typeof args.failOn === "string" ? args.failOn : "HIGH").toUpperCase(),
          skip: Array.isArray(args.skip) ? args.skip : [],
          ignore: Array.isArray(args.ignore) ? args.ignore : [],
        });
      } else if (name === "api_scan") {
        if (!strArg(args.baseUrl)) return bad("缺少必填参数 baseUrl。");
        result = await scanApi({ baseUrl: args.baseUrl, accounts: args.accounts || {}, idorPaths: args.idorPaths || [] });
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
