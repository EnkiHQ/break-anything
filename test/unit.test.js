import { test } from "node:test";
import assert from "node:assert/strict";
import { normalizeTrivy } from "../src/image.js";
import { normalizeSemgrep } from "../src/sast.js";
import { severityRank } from "../src/osv.js";
import { classify, reachRank } from "../src/reachability.js";
import { mergeMcpJson, tomlHasServer, appendTomlServer } from "../src/setup.js";

// 这些都是纯函数测试,不触网,适合 CI。

test("severityRank 排序正确", () => {
  assert.ok(severityRank("CRITICAL") > severityRank("HIGH"));
  assert.ok(severityRank("HIGH") > severityRank("MEDIUM"));
  assert.ok(severityRank("MEDIUM") > severityRank("LOW"));
  assert.ok(severityRank("LOW") > severityRank("UNKNOWN"));
  assert.equal(severityRank("garbage"), 0);
});

test("reachRank:imported > direct > transitive", () => {
  assert.ok(reachRank("imported") > reachRank("direct"));
  assert.ok(reachRank("direct") > reachRank("transitive"));
});

test("classify:源码引用了就是 imported", () => {
  const imported = new Set(["lodash"]);
  assert.equal(classify({ name: "lodash", direct: true }, imported), "imported");
  assert.equal(classify({ name: "minimist", direct: true }, imported), "direct");
  assert.equal(classify({ name: "left-pad", direct: false }, imported), "transitive");
});

test("normalizeTrivy:把 trivy JSON 归一化成统一发现结构", () => {
  const sample = {
    Results: [
      {
        Target: "nginx:1.21 (debian 11)",
        Class: "os-pkgs",
        Vulnerabilities: [
          {
            PkgName: "openssl",
            InstalledVersion: "1.1.1k",
            VulnerabilityID: "CVE-2022-0778",
            Severity: "HIGH",
            FixedVersion: "1.1.1n",
            Title: "infinite loop",
          },
          {
            PkgName: "zlib1g",
            InstalledVersion: "1.2.11",
            VulnerabilityID: "CVE-2018-25032",
            Severity: "MEDIUM",
            FixedVersion: "",
          },
        ],
      },
    ],
  };
  const r = normalizeTrivy(sample, "nginx:1.21");
  assert.equal(r.ok, true);
  assert.equal(r.summary.total, 2);
  assert.equal(r.summary.fixable, 1);
  // 高危应排在前
  assert.equal(r.findings[0].severity, "HIGH");
  assert.equal(r.findings[0].cve, "CVE-2022-0778");
  assert.deepEqual(r.findings[0].fixedVersions, ["1.1.1n"]);
});

test("normalizeTrivy:坏输入不抛异常", () => {
  const r = normalizeTrivy("not json", "x");
  assert.equal(r.ok, false);
  assert.equal(r.findings.length, 0);
});

test("normalizeSemgrep:把 semgrep JSON 归一化并映射严重度", () => {
  const sample = {
    results: [
      {
        check_id: "javascript.express.security.audit.xss.direct-response-write",
        path: "src/app.js",
        start: { line: 42 },
        extra: {
          severity: "ERROR",
          message: "Detected directly writing user input to the response (XSS).",
          lines: "res.send(req.query.name)",
          metadata: { cwe: ["CWE-79: Cross-site Scripting"], owasp: ["A03:2021 - Injection"], confidence: "HIGH" },
        },
      },
      {
        check_id: "python.lang.security.audit.weak-hash",
        path: "util/hash.py",
        start: { line: 7 },
        extra: { severity: "WARNING", message: "MD5 is weak", lines: "hashlib.md5(x)", metadata: {} },
      },
    ],
    paths: { scanned: ["src/app.js", "util/hash.py"] },
    errors: [],
  };
  const r = normalizeSemgrep(sample, "./");
  assert.equal(r.ok, true);
  assert.equal(r.summary.total, 2);
  assert.equal(r.findings[0].severity, "HIGH"); // ERROR -> HIGH, 排在前
  assert.equal(r.findings[0].cwe[0], "CWE-79: Cross-site Scripting");
  assert.equal(r.findings[1].severity, "MEDIUM"); // WARNING -> MEDIUM
  assert.equal(r.findings[0].rule, "xss.direct-response-write");
});

test("normalizeSemgrep:坏输入不抛异常", () => {
  const r = normalizeSemgrep("not json", "x");
  assert.equal(r.ok, false);
  assert.equal(r.findings.length, 0);
});

test("mergeMcpJson:保留原有服务,加入 break-anything", () => {
  const existing = { mcpServers: { other: { command: "x" } }, somethingElse: 1 };
  const out = mergeMcpJson(existing);
  assert.equal(out.somethingElse, 1); // 不动无关字段
  assert.deepEqual(out.mcpServers.other, { command: "x" }); // 不动别的 server
  assert.deepEqual(out.mcpServers["break-anything"], { command: "npx", args: ["-y", "break-anything", "mcp"] });
  // 不改原对象
  assert.equal(existing.mcpServers["break-anything"], undefined);
});

test("mergeMcpJson:空/无输入也能建出结构", () => {
  assert.ok(mergeMcpJson(undefined).mcpServers["break-anything"]);
  assert.ok(mergeMcpJson({}).mcpServers["break-anything"]);
});

test("TOML:检测与追加 section(幂等)", () => {
  assert.equal(tomlHasServer('[mcp_servers.other]\n'), false);
  const once = appendTomlServer('[mcp_servers.other]\ncommand = "x"\n');
  assert.equal(tomlHasServer(once), true);
  assert.match(once, /\[mcp_servers\.break-anything\]/);
  assert.match(once, /command = "npx"/);
});

// ---- API / DAST 授权闸门与 IDOR 判定(纯函数,不触网)----
import { checkAuthorization, decideIdor } from "../src/api.js";

test("checkAuthorization:默认关闭(未开 BRK_DYNAMIC_ENABLED)", () => {
  const g = checkAuthorization("http://localhost:4000", {});
  assert.equal(g.allowed, false);
  assert.match(g.reason, /默认关闭/);
});

test("checkAuthorization:开了开关但目标不在白名单", () => {
  const g = checkAuthorization("http://evil.example", {
    BRK_DYNAMIC_ENABLED: "true",
    BRK_AUTHORIZED_TARGETS_JSON: JSON.stringify(["http://localhost:4000"]),
  });
  assert.equal(g.allowed, false);
  assert.match(g.reason, /白名单/);
});

test("checkAuthorization:开关 + 目标在白名单 → 放行", () => {
  const g = checkAuthorization("http://localhost:4000/orders/2", {
    BRK_DYNAMIC_ENABLED: "true",
    BRK_AUTHORIZED_TARGETS_JSON: JSON.stringify(["http://localhost:4000"]),
  });
  assert.equal(g.allowed, true);
});

test("checkAuthorization:白名单 JSON 坏了不抛异常,按未授权处理", () => {
  const g = checkAuthorization("http://localhost:4000", {
    BRK_DYNAMIC_ENABLED: "true",
    BRK_AUTHORIZED_TARGETS_JSON: "{ not json",
  });
  assert.equal(g.allowed, false);
});

test("decideIdor:拿到 B 的私有数据且不同于 A 自己的 → 判为越权", () => {
  const v = decideIdor({
    crossStatus: 200,
    crossBody: '{"id":2,"owner":"bob","total":999}',
    truthBody: '{"id":2,"owner":"bob","total":999}',
    baselineBody: '{"id":1,"owner":"alice","total":10}',
  });
  assert.equal(v.idor, true);
});

test("decideIdor:跨账户被拒(非 200)→ 不是越权", () => {
  const v = decideIdor({
    crossStatus: 403,
    crossBody: "forbidden",
    truthBody: '{"id":2,"owner":"bob"}',
    baselineBody: '{"id":1,"owner":"alice"}',
  });
  assert.equal(v.idor, false);
});

test("decideIdor:返回的内容和 B 自查不一致 → 不判为越权(避免误报)", () => {
  const v = decideIdor({
    crossStatus: 200,
    crossBody: '{"error":"not found"}',
    truthBody: '{"id":2,"owner":"bob"}',
    baselineBody: '{"id":1,"owner":"alice"}',
  });
  assert.equal(v.idor, false);
});

test("decideIdor:空响应体不算泄露", () => {
  const v = decideIdor({ crossStatus: 200, crossBody: "", truthBody: "", baselineBody: "" });
  assert.equal(v.idor, false);
});

// ---- IaC 配置扫描(纯函数,不触文件系统)----
import { classifyIac, scanDockerfile, scanKubernetes, scanTerraform } from "../src/iac.js";

test("classifyIac:按文件名/内容归类", () => {
  assert.equal(classifyIac("Dockerfile", ""), "dockerfile");
  assert.equal(classifyIac("api.dockerfile", ""), "dockerfile");
  assert.equal(classifyIac("main.tf", ""), "terraform");
  assert.equal(classifyIac("deploy.yaml", "apiVersion: apps/v1\nkind: Deployment\n"), "kubernetes");
  assert.equal(classifyIac("random.yaml", "foo: bar\n"), null); // 无 apiVersion/kind 不当 k8s
  assert.equal(classifyIac("notes.txt", ""), null);
});

test("scanDockerfile:root + latest + 管道执行 + 硬编码密钥", () => {
  const df = [
    "FROM node:latest",
    "RUN curl https://get.example.sh | sh",
    "ENV API_KEY=sk-abc123def456",
    'CMD ["node","app.js"]',
  ].join("\n");
  const out = scanDockerfile(df, "Dockerfile");
  const rules = out.map((f) => f.rule);
  assert.ok(rules.includes("docker-latest-tag"));
  assert.ok(rules.includes("docker-remote-pipe-shell"));
  assert.ok(rules.includes("docker-hardcoded-secret"));
  assert.ok(rules.includes("docker-no-user")); // 没有 USER → 以 root 运行
  // 密钥值被脱敏,不回显
  const secret = out.find((f) => f.rule === "docker-hardcoded-secret");
  assert.ok(!secret.evidence.includes("sk-abc123def456"));
});

test("scanDockerfile:固定版本 + 非 root 用户 → 干净", () => {
  const df = "FROM node:18.19.0\nUSER appuser\nCMD [\"node\",\"app.js\"]\n";
  const out = scanDockerfile(df, "Dockerfile");
  assert.equal(out.length, 0);
});

test("scanKubernetes:privileged / hostNetwork / 危险 capability", () => {
  const y = [
    "apiVersion: v1",
    "kind: Pod",
    "spec:",
    "  hostNetwork: true",
    "  containers:",
    "    - image: nginx:latest",
    "      securityContext:",
    "        privileged: true",
    "        capabilities:",
    "          add:",
    "            - SYS_ADMIN",
  ].join("\n");
  const out = scanKubernetes(y, "pod.yaml");
  const rules = out.map((f) => f.rule);
  assert.ok(rules.includes("k8s-privileged"));
  assert.ok(rules.includes("k8s-host-network"));
  assert.ok(rules.includes("k8s-dangerous-capability"));
  assert.ok(rules.includes("k8s-latest-tag"));
});

test("scanTerraform:开放 CIDR / 公开桶 / 硬编码密钥,且忽略变量引用", () => {
  const tf = [
    'resource "aws_security_group" "x" {',
    "  ingress { cidr_blocks = [\"0.0.0.0/0\"] }",
    "}",
    'resource "aws_s3_bucket" "b" { acl = "public-read" }',
    '  db_password = "hunter2plaintext"',
    '  api_token   = var.api_token',
  ].join("\n");
  const out = scanTerraform(tf, "main.tf");
  const rules = out.map((f) => f.rule);
  assert.ok(rules.includes("tf-open-cidr"));
  assert.ok(rules.includes("tf-public-bucket"));
  assert.ok(rules.includes("tf-hardcoded-secret"));
  // var.* 引用不算硬编码
  assert.equal(out.filter((f) => f.rule === "tf-hardcoded-secret").length, 1);
  const secret = out.find((f) => f.rule === "tf-hardcoded-secret");
  assert.ok(!secret.evidence.includes("hunter2plaintext"));
});
