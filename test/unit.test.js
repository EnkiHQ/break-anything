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

// ---- 深度可达性:绑定抽取 + 调用检测(纯函数,不触文件系统)----
import { extractBindings, isCalled, classifyUsage } from "../src/reachability.js";

test("extractBindings:require 默认导入与解构", () => {
  const b1 = extractBindings("const _ = require('lodash')", "lodash");
  assert.ok(b1.has("_"));
  const b2 = extractBindings("const { merge, get: g } = require('lodash')", "lodash");
  assert.ok(b2.has("merge"));
  assert.ok(b2.has("g")); // 重命名取本地名
});

test("extractBindings:ESM 默认 / 命名 / 命名空间 / 重命名", () => {
  assert.ok(extractBindings("import _ from 'lodash'", "lodash").has("_"));
  assert.ok(extractBindings("import * as _ from 'lodash'", "lodash").has("_"));
  const named = extractBindings("import { merge as m, get } from 'lodash'", "lodash");
  assert.ok(named.has("m"));
  assert.ok(named.has("get"));
});

test("extractBindings:TS 纯类型导入不计入可调用绑定", () => {
  const b = extractBindings("import { type Opts, build } from 'pkg'", "pkg");
  assert.ok(b.has("build"));
  assert.ok(!b.has("Opts"));
});

test("extractBindings:只抽取来自该包的绑定,不串包", () => {
  const text = "import { merge } from 'lodash'\nimport { danger } from 'evil-pkg'";
  const b = extractBindings(text, "lodash");
  assert.ok(b.has("merge"));
  assert.ok(!b.has("danger"));
});

test("isCalled:直接调用 / 成员调用 / new 调用 → true", () => {
  assert.equal(isCalled("const r = merge(a, b)", new Set(["merge"])), true);
  assert.equal(isCalled("_.chain(x).value()", new Set(["_"])), true);
  assert.equal(isCalled("const c = new Client()", new Set(["Client"])), true);
  assert.equal(isCalled("obj?.foo(); _?.get(x)", new Set(["_"])), true);
});

test("isCalled:仅导入未调用 → false,且不被他人成员调用误报", () => {
  assert.equal(isCalled("export { merge }", new Set(["merge"])), false);
  // other.merge( 是别的对象的方法,不应算作 merge 这个绑定被调用
  assert.equal(isCalled("other.merge(a, b)", new Set(["merge"])), false);
});

test("classifyUsage:called > imported > direct > transitive", () => {
  const u = new Map([
    ["a", { imported: true, called: true }],
    ["b", { imported: true, called: false }],
  ]);
  assert.equal(classifyUsage({ name: "a", direct: true }, u), "called");
  assert.equal(classifyUsage({ name: "b", direct: true }, u), "imported");
  assert.equal(classifyUsage({ name: "c", direct: true }, u), "direct");
  assert.equal(classifyUsage({ name: "d", direct: false }, u), "transitive");
});

// ---- 修复计划(纯函数,不触网/文件)----
import { compareVersions, pickUpgradeTarget, planFix } from "../src/fix.js";

test("compareVersions:数字段比较,忽略预发布", () => {
  assert.equal(compareVersions("4.17.4", "4.17.21") < 0, true);
  assert.equal(compareVersions("1.2.6", "1.2.6"), 0);
  assert.equal(compareVersions("2.0.0", "1.9.9") > 0, true);
  assert.equal(compareVersions("1.2.0-beta", "1.2.0") === 0, true); // 忽略 -beta
});

test("pickUpgradeTarget:取能覆盖所有 CVE 的最小安全版本", () => {
  const findings = [
    { fixedVersions: ["4.17.11"] },
    { fixedVersions: ["4.17.21"] },
    { fixedVersions: ["4.17.12"] },
  ];
  // 升到 4.17.21 才能覆盖全部 → 取各 CVE 最近安全版本里的最大者
  assert.equal(pickUpgradeTarget("4.17.4", findings), "4.17.21");
});

test("pickUpgradeTarget:多分支修复选最接近当前且更高的", () => {
  const findings = [{ fixedVersions: ["1.2.6", "0.2.4"] }];
  assert.equal(pickUpgradeTarget("1.2.0", findings), "1.2.6"); // 0.2.4 比当前低,忽略
});

test("planFix:按可达性→严重度排序,给出升级命令", () => {
  const findings = [
    { package: "minimist", version: "1.2.0", ecosystem: "npm", reachability: "imported", severity: "CRITICAL", epss: 0.04, cve: "CVE-2021-44906", fixedVersions: ["1.2.6"] },
    { package: "lodash", version: "4.17.4", ecosystem: "npm", reachability: "called", severity: "HIGH", epss: 0.21, cve: "CVE-2021-23337", fixedVersions: ["4.17.21"] },
    { package: "lodash", version: "4.17.4", ecosystem: "npm", reachability: "called", severity: "CRITICAL", epss: 0.05, cve: "CVE-2019-10744", fixedVersions: ["4.17.12"] },
  ];
  const plan = planFix(findings);
  assert.equal(plan.upgrades.length, 2);
  // lodash 被调用 → 排在 minimist(仅引用)前面,即使 minimist 也是 CRITICAL
  assert.equal(plan.upgrades[0].package, "lodash");
  assert.equal(plan.upgrades[0].to, "4.17.21"); // 覆盖两个 CVE 的最小版本
  assert.equal(plan.upgrades[0].resolves, 2);
  assert.equal(plan.upgrades[0].command, "npm install lodash@4.17.21");
  assert.equal(plan.summary.resolvedVulns, 3);
});

test("planFix:无修复版本的单列到 noFix", () => {
  const findings = [
    { package: "ghost", version: "1.0.0", ecosystem: "npm", reachability: "called", severity: "HIGH", cve: "CVE-2030-0001", fixedVersions: [] },
  ];
  const plan = planFix(findings);
  assert.equal(plan.upgrades.length, 0);
  assert.equal(plan.noFix.length, 1);
  assert.equal(plan.noFix[0].package, "ghost");
  assert.equal(plan.summary.noFixCount, 1);
});

test("planFix:pip 与 composer 的升级命令", () => {
  const plan = planFix([
    { package: "flask", version: "0.12", ecosystem: "PyPI", reachability: "direct", severity: "HIGH", cve: "x", fixedVersions: ["1.0"] },
    { package: "monolog/monolog", version: "1.0.0", ecosystem: "Packagist", reachability: "direct", severity: "MEDIUM", cve: "y", fixedVersions: ["1.25.0"] },
  ]);
  const byPkg = Object.fromEntries(plan.upgrades.map((u) => [u.package, u.command]));
  assert.equal(byPkg["flask"], 'pip install "flask==1.0"');
  assert.equal(byPkg["monolog/monolog"], "composer require monolog/monolog:1.25.0");
});

// ---- CISA KEV 富化(纯函数,不触网)----
import { indexKev } from "../src/kev.js";

test("indexKev:把 CISA 目录归一化为 Map,识别勒索软件标记", () => {
  const catalog = {
    vulnerabilities: [
      { cveID: "CVE-2021-44228", vulnerabilityName: "Log4Shell", dateAdded: "2021-12-10", knownRansomwareCampaignUse: "Known" },
      { cveID: "cve-2017-0144", vulnerabilityName: "EternalBlue", dateAdded: "2022-02-10", knownRansomwareCampaignUse: "Unknown" },
      { vendorProject: "x" }, // 无 cveID → 跳过
    ],
  };
  const m = indexKev(catalog);
  assert.equal(m.size, 2);
  assert.equal(m.get("CVE-2021-44228").ransomware, true);
  assert.equal(m.get("CVE-2017-0144").ransomware, false); // 大小写归一
  assert.equal(m.get("CVE-2017-0144").dateAdded, "2022-02-10");
});

test("indexKev:坏/空输入不抛异常", () => {
  assert.equal(indexKev(null).size, 0);
  assert.equal(indexKev({}).size, 0);
  assert.equal(indexKev({ vulnerabilities: "nope" }).size, 0);
});

test("planFix:KEV 在野利用项优先于同可达性的非 KEV 项", () => {
  const findings = [
    { package: "a", version: "1.0.0", ecosystem: "npm", reachability: "imported", severity: "HIGH", kev: false, cve: "CVE-A", fixedVersions: ["1.1.0"] },
    { package: "b", version: "1.0.0", ecosystem: "npm", reachability: "imported", severity: "HIGH", kev: true, cve: "CVE-B", fixedVersions: ["1.1.0"] },
  ];
  const plan = planFix(findings);
  // 同为 imported+HIGH,但 b 是 KEV → 排前面
  assert.equal(plan.upgrades[0].package, "b");
  assert.equal(plan.upgrades[0].kev, true);
  assert.equal(plan.summary.kevCount, 1);
});

// ---- 新生态 lockfile 解析(纯函数,不触文件系统)----
import { parseGoModText, parseCargoLockText, parseCargoTomlDirect, parseGemfileLockText } from "../src/lockfiles.js";

test("parseGoModText:require 块 + 单行,去 v 前缀,indirect 归为非直接", () => {
  const text = [
    "module example.com/app",
    "go 1.21",
    "require (",
    "\tgithub.com/gin-gonic/gin v1.6.0",
    "\tgolang.org/x/text v0.3.0 // indirect",
    ")",
    "require github.com/pkg/errors v0.9.1",
  ].join("\n");
  const { packages, direct } = parseGoModText(text);
  const byName = Object.fromEntries(packages.map((p) => [p.name, p.version]));
  assert.equal(byName["github.com/gin-gonic/gin"], "1.6.0"); // 去掉了 v
  assert.equal(byName["golang.org/x/text"], "0.3.0");
  assert.equal(byName["github.com/pkg/errors"], "0.9.1");
  assert.ok(direct.has("github.com/gin-gonic/gin"));
  assert.ok(direct.has("github.com/pkg/errors"));
  assert.ok(!direct.has("golang.org/x/text")); // indirect
});

test("parseCargoLockText + parseCargoTomlDirect", () => {
  const lock = [
    '[[package]]',
    'name = "smallvec"',
    'version = "0.6.13"',
    '',
    '[[package]]',
    'name = "libc"',
    'version = "0.2.100"',
  ].join("\n");
  const { packages } = parseCargoLockText(lock);
  const byName = Object.fromEntries(packages.map((p) => [p.name, p.version]));
  assert.equal(byName["smallvec"], "0.6.13");
  assert.equal(byName["libc"], "0.2.100");

  const toml = '[package]\nname = "app"\n\n[dependencies]\nsmallvec = "0.6"\nserde = { version = "1" }\n';
  const direct = parseCargoTomlDirect(toml);
  assert.ok(direct.has("smallvec"));
  assert.ok(direct.has("serde"));
  assert.ok(!direct.has("name")); // [package] 段里的 name 不算依赖
});

test("parseGemfileLockText:specs 为包,DEPENDENCIES 为直接依赖", () => {
  const text = [
    "GEM",
    "  remote: https://rubygems.org/",
    "  specs:",
    "    actionpack (5.0.0)",
    "      actionview (= 5.0.0)",
    "    rack (2.0.1)",
    "",
    "PLATFORMS",
    "  ruby",
    "",
    "DEPENDENCIES",
    "  rails",
    "  rack (~> 2.0)",
  ].join("\n");
  const { packages, direct } = parseGemfileLockText(text);
  const byName = Object.fromEntries(packages.map((p) => [p.name, p.version]));
  assert.equal(byName["actionpack"], "5.0.0");
  assert.equal(byName["rack"], "2.0.1");
  assert.ok(!("actionview" in byName)); // 6 空格的子依赖约束不算解析出的包
  assert.ok(direct.has("rack"));
  assert.ok(direct.has("rails"));
  assert.ok(!direct.has("actionpack")); // 不在 DEPENDENCIES 里
});

// ---- Maven / NuGet lockfile 解析(纯函数)----
import { parsePomXml, parseNugetLock } from "../src/lockfiles.js";

test("parsePomXml:解析依赖,groupId:artifactId 命名,${属性} 版本解析", () => {
  const pom = [
    "<project>",
    "  <properties>",
    "    <jackson.version>2.9.8</jackson.version>",
    "  </properties>",
    "  <dependencies>",
    "    <dependency>",
    "      <groupId>com.fasterxml.jackson.core</groupId>",
    "      <artifactId>jackson-databind</artifactId>",
    "      <version>${jackson.version}</version>",
    "    </dependency>",
    "    <dependency>",
    "      <groupId>org.apache.commons</groupId>",
    "      <artifactId>commons-text</artifactId>",
    "      <version>1.9</version>",
    "    </dependency>",
    "    <dependency>",
    "      <groupId>managed</groupId>",
    "      <artifactId>no-version</artifactId>",
    "    </dependency>",
    "  </dependencies>",
    "</project>",
  ].join("\n");
  const { packages, direct } = parsePomXml(pom);
  const byName = Object.fromEntries(packages.map((p) => [p.name, p.version]));
  assert.equal(byName["com.fasterxml.jackson.core:jackson-databind"], "2.9.8"); // ${jackson.version} 已解析
  assert.equal(byName["org.apache.commons:commons-text"], "1.9");
  assert.ok(!("managed:no-version" in byName)); // 无版本 → 跳过
  assert.ok(direct.has("org.apache.commons:commons-text"));
});

test("parseNugetLock:取 resolved 版本,type=Direct 为直接依赖", () => {
  const lock = {
    version: 1,
    dependencies: {
      "net6.0": {
        "Newtonsoft.Json": { type: "Direct", requested: "[12.0.1, )", resolved: "12.0.1" },
        "System.Text.Encodings.Web": { type: "Transitive", resolved: "4.5.0" },
      },
    },
  };
  const { packages, direct } = parseNugetLock(lock);
  const byName = Object.fromEntries(packages.map((p) => [p.name, p.version]));
  assert.equal(byName["Newtonsoft.Json"], "12.0.1");
  assert.equal(byName["System.Text.Encodings.Web"], "4.5.0");
  assert.ok(direct.has("Newtonsoft.Json"));
  assert.ok(!direct.has("System.Text.Encodings.Web")); // Transitive
});

test("parseNugetLock:坏输入不抛异常", () => {
  assert.deepEqual(parseNugetLock("not json").packages, []);
  assert.deepEqual(parseNugetLock({}).packages, []);
});

// ---- SBOM(CycloneDX)生成与比对(纯函数)----
import { purlFor, buildSbom, diffSbom } from "../src/sbom.js";

test("purlFor:各生态的 package URL", () => {
  assert.equal(purlFor("npm", "lodash", "4.17.4"), "pkg:npm/lodash@4.17.4");
  assert.equal(purlFor("npm", "@babel/core", "7.0.0"), "pkg:npm/%40babel/core@7.0.0");
  assert.equal(purlFor("PyPI", "Flask_Thing", "1.0"), "pkg:pypi/flask-thing@1.0");
  assert.equal(purlFor("Packagist", "monolog/monolog", "2.0"), "pkg:composer/monolog/monolog@2.0");
  assert.equal(purlFor("Go", "github.com/gin-gonic/gin", "1.6.0"), "pkg:golang/github.com/gin-gonic/gin@1.6.0");
  assert.equal(purlFor("crates.io", "time", "0.1.44"), "pkg:cargo/time@0.1.44");
  assert.equal(purlFor("RubyGems", "rack", "2.0.5"), "pkg:gem/rack@2.0.5");
  assert.equal(purlFor("Maven", "com.fasterxml.jackson.core:jackson-databind", "2.9.8"), "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.8");
  assert.equal(purlFor("NuGet", "Newtonsoft.Json", "12.0.1"), "pkg:nuget/Newtonsoft.Json@12.0.1");
});

test("buildSbom:CycloneDX 结构、去重、排序", () => {
  const sources = [
    { ecosystem: "npm", packages: [
      { name: "lodash", version: "4.17.4", ecosystem: "npm", direct: true },
      { name: "lodash", version: "4.17.4", ecosystem: "npm", direct: true }, // 重复
      { name: "minimist", version: "1.2.0", ecosystem: "npm", direct: false },
    ] },
  ];
  const bom = buildSbom(sources, { name: "demo", now: "2026-01-01T00:00:00Z", serialNumber: "urn:uuid:fixed" });
  assert.equal(bom.bomFormat, "CycloneDX");
  assert.equal(bom.specVersion, "1.5");
  assert.equal(bom.serialNumber, "urn:uuid:fixed");
  assert.equal(bom.components.length, 2); // 去重
  assert.equal(bom.components[0].purl, "pkg:npm/lodash@4.17.4");
  assert.equal(bom.metadata.component.name, "demo");
  // 传递依赖标注 scope=optional
  const mm = bom.components.find((c) => c.name === "minimist");
  assert.equal(mm.scope, "optional");
});

test("diffSbom:新增 / 移除 / 版本变化", () => {
  const oldBom = buildSbom([{ ecosystem: "npm", packages: [
    { name: "lodash", version: "4.17.4", ecosystem: "npm", direct: true },
    { name: "left-pad", version: "1.0.0", ecosystem: "npm", direct: true },
  ] }], { serialNumber: "urn:uuid:a", now: "x" });
  const newBom = buildSbom([{ ecosystem: "npm", packages: [
    { name: "lodash", version: "4.17.21", ecosystem: "npm", direct: true }, // 变更
    { name: "express", version: "4.18.0", ecosystem: "npm", direct: true }, // 新增
  ] }], { serialNumber: "urn:uuid:b", now: "y" });
  const d = diffSbom(oldBom, newBom);
  assert.deepEqual(d.summary, { added: 1, removed: 1, changed: 1 });
  assert.equal(d.added[0].name, "express");
  assert.equal(d.removed[0].name, "left-pad");
  assert.equal(d.changed[0].name, "lodash");
  assert.equal(d.changed[0].from, "4.17.4");
  assert.equal(d.changed[0].to, "4.17.21");
});

// ---- SARIF 2.1.0 输出(纯函数)----
import { toSarif, buildSarif, splitLocation } from "../src/sarif.js";

test("splitLocation:拆分 file:line 并相对化", () => {
  assert.deepEqual(splitLocation("src/app.js:42"), { uri: "src/app.js", line: 42 });
  assert.deepEqual(splitLocation("/root/proj/src/a.py:7", "/root/proj"), { uri: "src/a.py", line: 7 });
  assert.deepEqual(splitLocation("Dockerfile"), { uri: "Dockerfile", line: undefined });
});

test("buildSarif:结构、规则去重、severity→level 映射", () => {
  const sarif = buildSarif([
    { ruleId: "R1", name: "r1", level: "error", securitySeverity: "8.0", message: "m1", locations: [{ uri: "a.js", line: 3 }] },
    { ruleId: "R1", name: "r1", level: "error", message: "m2", locations: [{ uri: "b.js", line: 5 }] },
    { ruleId: "R2", name: "r2", level: "warning", message: "m3", locations: [{ uri: "c.js" }] },
  ]);
  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs[0].tool.driver.name, "break-anything");
  assert.equal(sarif.runs[0].tool.driver.rules.length, 2); // R1 去重
  assert.equal(sarif.runs[0].results.length, 3);
  assert.equal(sarif.runs[0].results[0].level, "error");
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine, 3);
  // 无 line 的不带 region
  assert.equal(sarif.runs[0].results[2].locations[0].physicalLocation.region, undefined);
  // security-severity 落到规则 properties
  const r1 = sarif.runs[0].tool.driver.rules.find((r) => r.id === "R1");
  assert.equal(r1.properties["security-severity"], "8.0");
});

test("toSarif:deps 发现 → 以 lockfile 为位置,CVE 为 ruleId", () => {
  const result = {
    target: "/proj",
    sources: [{ ecosystem: "npm", file: "/proj/package-lock.json", packages: 1 }],
    findings: [
      { package: "lodash", version: "4.17.4", ecosystem: "npm", severity: "HIGH", cve: "CVE-2021-23337", reachability: "called", epss: 0.21, kev: false, fixedVersions: ["4.17.21"], summary: "cmd injection" },
    ],
  };
  const sarif = toSarif("deps", result);
  const res = sarif.runs[0].results[0];
  assert.equal(res.ruleId, "CVE-2021-23337");
  assert.equal(res.level, "error");
  assert.equal(res.locations[0].physicalLocation.artifactLocation.uri, "package-lock.json"); // 相对化
  assert.equal(res.properties.reachability, "called");
});

test("toSarif:sast / iac / secrets 映射到正确位置与 level", () => {
  const sast = toSarif("sast", { target: "/p", findings: [
    { id: "js.xss", rule: "xss", severity: "HIGH", location: "/p/src/app.js:10", message: "XSS", cwe: ["CWE-79"], owasp: [], references: ["https://x"] },
  ] });
  assert.equal(sast.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, "src/app.js");
  assert.equal(sast.runs[0].results[0].locations[0].physicalLocation.region.startLine, 10);

  const iac = toSarif("iac", { target: "/p", findings: [
    { kind: "dockerfile", rule: "docker-no-user", severity: "MEDIUM", title: "runs as root", location: "Dockerfile:1", cwe: "CWE-250", remediation: "add USER" },
  ] });
  assert.equal(iac.runs[0].results[0].level, "warning");
  assert.match(iac.runs[0].results[0].message.text, /add USER/);

  const secrets = toSarif("secrets", { findings: [
    { rule: "aws-access-key-id", severity: "HIGH", source: "worktree", location: "config.js", line: 3 },
    { rule: "github-token", severity: "HIGH", source: "history", commit: "abc123" },
  ] });
  assert.equal(secrets.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, "config.js");
  assert.match(secrets.runs[0].results[1].locations[0].physicalLocation.artifactLocation.uri, /git-history@abc123/);
});

// ---- CI 聚合门禁(纯函数)----
import { evaluateGate, aggregate } from "../src/ci.js";
import { toSarifMulti } from "../src/sarif.js";

test("evaluateGate:可达高危 + KEV + 密钥 + IaC 高危 都触发失败", () => {
  const categories = {
    deps: { ok: true, findings: [
      { severity: "HIGH", reachability: "called", kev: false },
      { severity: "CRITICAL", reachability: "transitive", kev: true }, // 不可达但 KEV
      { severity: "LOW", reachability: "called", kev: false },         // 低于阈值
    ] },
    secrets: { ok: true, findings: [{ rule: "aws-access-key-id" }] },
    iac: { ok: true, findings: [{ severity: "HIGH" }, { severity: "LOW" }] },
    sast: { ok: false, message: "no semgrep", findings: [] }, // 跳过的不计入
  };
  const g = evaluateGate(categories, { failOn: "HIGH" });
  assert.equal(g.passed, false);
  assert.ok(g.reasons.some((r) => /reachable HIGH\+ dependency/.test(r)));
  assert.ok(g.reasons.some((r) => /KEV/.test(r)));
  assert.ok(g.reasons.some((r) => /leaked secret/.test(r)));
  assert.ok(g.reasons.some((r) => /IaC/.test(r)));
});

test("evaluateGate:只有低于阈值的发现 → 通过", () => {
  const g = evaluateGate({
    deps: { ok: true, findings: [{ severity: "MEDIUM", reachability: "called", kev: false }] },
    iac: { ok: true, findings: [{ severity: "LOW" }] },
  }, { failOn: "HIGH" });
  assert.equal(g.passed, true);
  assert.equal(g.reasons.length, 0);
});

test("evaluateGate:不可达的高危不触发(但 KEV 永远触发)", () => {
  const g = evaluateGate({
    deps: { ok: true, findings: [{ severity: "CRITICAL", reachability: "transitive", kev: false }] },
  }, { failOn: "HIGH" });
  assert.equal(g.passed, true);
});

test("aggregate:汇总总数、按严重度、按类别计数(含跳过)", () => {
  const a = aggregate({
    deps: { ok: true, findings: [{ severity: "HIGH" }, { severity: "LOW" }] },
    secrets: { ok: true, findings: [{ severity: "CRITICAL" }] },
    sast: { ok: false, message: "no semgrep", findings: [] },
  });
  assert.equal(a.total, 3);
  assert.deepEqual(a.bySeverity, { HIGH: 1, LOW: 1, CRITICAL: 1 });
  assert.deepEqual(a.counts.deps, { findings: 2 });
  assert.equal(a.counts.sast.skipped, true);
});

test("toSarifMulti:合并多类发现为一份 SARIF", () => {
  const entries = [
    { kind: "iac", result: { target: "/p", ok: true, findings: [
      { kind: "dockerfile", rule: "docker-no-user", severity: "MEDIUM", title: "root", location: "Dockerfile:1", cwe: "CWE-250", remediation: "add USER" },
    ] } },
    { kind: "secrets", result: { ok: true, findings: [
      { rule: "aws-access-key-id", severity: "HIGH", source: "worktree", location: "a.txt", line: 2 },
    ] } },
    { kind: "sast", result: { ok: false, findings: [] } }, // 跳过
  ];
  const sarif = toSarifMulti(entries);
  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs[0].results.length, 2);
  const ruleIds = sarif.runs[0].tool.driver.rules.map((r) => r.id);
  assert.ok(ruleIds.includes("docker-no-user"));
  assert.ok(ruleIds.includes("aws-access-key-id"));
});

// ---- 策略 / 基线(纯函数)----
import { normalizeIgnore, isIgnored, applyPolicy, mergePolicy } from "../src/policy.js";

test("normalizeIgnore:字符串与 {id} 对象混用都归一为 id 集合", () => {
  const s = normalizeIgnore(["CVE-1", { id: "docker-no-user", reason: "已加固" }, "", { reason: "无 id" }, 123]);
  assert.equal(s.has("CVE-1"), true);
  assert.equal(s.has("docker-no-user"), true);
  assert.equal(s.size, 2);
});

test("isIgnored:比对 cve / id / rule 任一命中", () => {
  const ig = normalizeIgnore(["CVE-2021-23337", "aws-access-key-id"]);
  assert.equal(isIgnored({ cve: "CVE-2021-23337", id: "GHSA-x" }, ig), true);
  assert.equal(isIgnored({ rule: "aws-access-key-id" }, ig), true);
  assert.equal(isIgnored({ cve: "CVE-9", rule: "other" }, ig), false);
  assert.equal(isIgnored({ cve: "CVE-9" }, new Set()), false);
});

test("applyPolicy:忽略命中项从 categories 移除并计数", () => {
  const categories = {
    deps: { ok: true, findings: [
      { cve: "CVE-2021-23337", severity: "HIGH", reachability: "called" },
      { cve: "CVE-NEW", severity: "HIGH", reachability: "called" },
    ] },
    iac: { ok: true, findings: [{ rule: "docker-no-user", severity: "MEDIUM" }] },
    sast: { ok: false, message: "no semgrep", findings: [] },
  };
  const { categories: out, suppressed } = applyPolicy(categories, { ignore: ["CVE-2021-23337", "docker-no-user"] });
  assert.equal(suppressed, 2);
  assert.equal(out.deps.findings.length, 1);
  assert.equal(out.deps.findings[0].cve, "CVE-NEW");
  assert.equal(out.iac.findings.length, 0);
  assert.equal(out.sast.ok, false); // 跳过的类别原样保留
});

test("mergePolicy:flag 覆盖 failOn,skip/ignore 取并集", () => {
  const m = mergePolicy(
    { failOn: "medium", skip: ["sast"], ignore: ["CVE-1"] },
    { failOn: "HIGH", skip: ["deps"], ignore: ["CVE-2"] },
  );
  assert.equal(m.failOn, "HIGH");           // flag 覆盖
  assert.deepEqual([...m.skip].sort(), ["deps", "sast"]);
  assert.deepEqual(m.ignore, ["CVE-1", "CVE-2"]);
});

test("mergePolicy:无覆盖时用文件值,默认 failOn HIGH", () => {
  assert.equal(mergePolicy({}, {}).failOn, "HIGH");
  assert.equal(mergePolicy({ failOn: "low" }, {}).failOn, "LOW");
});

// ---- yarn / pnpm lockfile 解析(纯函数)----
import { parseYarnLockText, parsePnpmLockText } from "../src/lockfiles.js";

test("parseYarnLockText:经典 v1,多 spec 头行,scoped 包名", () => {
  const text = [
    "# yarn lockfile v1",
    "",
    'lodash@^4.17.4, lodash@^4.0.0:',
    '  version "4.17.4"',
    '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.4.tgz"',
    "",
    '"@babel/core@^7.0.0":',
    '  version "7.0.1"',
  ].join("\n");
  const { packages } = parseYarnLockText(text);
  const byName = Object.fromEntries(packages.map((p) => [p.name, p.version]));
  assert.equal(byName["lodash"], "4.17.4");
  assert.equal(byName["@babel/core"], "7.0.1");
});

test("parseYarnLockText:berry v2+(name@npm:range / version: x)", () => {
  const text = [
    '"lodash@npm:^4.17.4":',
    "  version: 4.17.21",
    "",
    '"@scope/pkg@npm:^1.2.0":',
    '  version: "1.2.3"',
  ].join("\n");
  const { packages } = parseYarnLockText(text);
  const byName = Object.fromEntries(packages.map((p) => [p.name, p.version]));
  assert.equal(byName["lodash"], "4.17.21");
  assert.equal(byName["@scope/pkg"], "1.2.3");
});

test("parsePnpmLockText:兼容 /name@ver、/@scope/name@ver、/name/ver、以及 peer 后缀", () => {
  const text = [
    "packages:",
    "  /lodash@4.17.4:",
    "    resolution: {integrity: sha512-xxx}",
    "  /@babel/core@7.0.0:",
    "    resolution: {integrity: sha512-yyy}",
    "  /minimist/1.2.0:",
    "    resolution: {integrity: sha512-zzz}",
    "  /react-dom@18.2.0(react@18.2.0):",
    "    resolution: {integrity: sha512-www}",
  ].join("\n");
  const { packages } = parsePnpmLockText(text);
  const byName = Object.fromEntries(packages.map((p) => [p.name, p.version]));
  assert.equal(byName["lodash"], "4.17.4");
  assert.equal(byName["@babel/core"], "7.0.0");
  assert.equal(byName["minimist"], "1.2.0");
  assert.equal(byName["react-dom"], "18.2.0"); // peer 后缀被截掉
});

// ---- 自动基线(纯函数)----
import { collectFindingIds, buildBaseline } from "../src/policy.js";

test("collectFindingIds:跨类别收集 cve/id/rule 去重", () => {
  const cats = {
    deps: { ok: true, findings: [{ cve: "CVE-1" }, { id: "GHSA-x" }, { cve: "CVE-1" }] },
    iac: { ok: true, findings: [{ rule: "docker-no-user" }] },
    sast: { ok: false, findings: [] },
  };
  const ids = collectFindingIds(cats).sort();
  assert.deepEqual(ids, ["CVE-1", "GHSA-x", "docker-no-user"]);
});

test("buildBaseline:把当前发现并入 ignore,保留已有条目与 failOn/skip", () => {
  const cats = {
    iac: { ok: true, findings: [{ rule: "docker-no-user" }, { rule: "docker-latest-tag" }] },
    secrets: { ok: true, findings: [{ rule: "aws-access-key-id" }] },
  };
  const existing = { failOn: "medium", skip: ["sast"], ignore: ["docker-no-user"] };
  const { policy, added } = buildBaseline(cats, existing, { now: "2026-10-28T00:00:00Z" });
  assert.equal(policy.failOn, "MEDIUM");
  assert.deepEqual(policy.skip, ["sast"]);
  assert.equal(added, 2); // docker-no-user 已在,只加 docker-latest-tag + aws-access-key-id
  assert.ok(policy.ignore.includes("docker-no-user")); // 旧条目原样保留
  const newEntry = policy.ignore.find((x) => x && x.id === "docker-latest-tag");
  assert.ok(newEntry && /baselined 2026-10-28/.test(newEntry.reason));
});

test("buildBaseline:无现有策略时从空开始,默认 failOn HIGH", () => {
  const { policy, added } = buildBaseline({ iac: { ok: true, findings: [{ rule: "r1" }] } }, {});
  assert.equal(policy.failOn, "HIGH");
  assert.equal(added, 1);
  assert.equal(policy.ignore[0].id, "r1");
});

// ---- HTML 报告(纯函数,含 XSS 转义)----
import { renderHtml, findingRow, esc } from "../src/htmlreport.js";

test("esc:转义 HTML 特殊字符", () => {
  assert.equal(esc(`<script>&"'`), "&lt;script&gt;&amp;&quot;&#39;");
});

test("findingRow:各类别归一为行", () => {
  assert.equal(findingRow("deps", { package: "lodash", version: "4.17.4", cve: "CVE-1", kev: true, reachability: "called", ecosystem: "npm" }).name, "lodash@4.17.4 [KEV]");
  assert.equal(findingRow("secrets", { rule: "aws-access-key-id", source: "history", commit: "abc" }).location, "git history abc");
  assert.equal(findingRow("iac", { title: "root", rule: "docker-no-user", cwe: "CWE-250", location: "Dockerfile:1" }).name, "root");
});

test("renderHtml:门禁状态、计数、分节齐全", () => {
  const result = {
    target: "./svc",
    policy: { suppressed: 2 },
    summary: { total: 2, bySeverity: { HIGH: 1, MEDIUM: 1 } },
    gate: { passed: false, failOn: "HIGH", reasons: ["1 leaked secret"] },
    categories: {
      secrets: { ok: true, findings: [{ rule: "aws-access-key-id", severity: "HIGH", source: "worktree", location: "a.txt", line: 2 }] },
      iac: { ok: true, findings: [{ rule: "docker-latest-tag", severity: "MEDIUM", title: "latest tag", location: "Dockerfile:1" }] },
      sast: { ok: false, findings: [] },
    },
  };
  const html = renderHtml(result, { now: "2026-10-28T00:00:00Z" });
  assert.ok(html.startsWith("<!doctype html>"));
  assert.ok(html.includes("GATE FAILED"));
  assert.ok(html.includes("1 leaked secret"));
  assert.ok(html.includes("2 suppressed by policy"));
  assert.ok(html.includes("aws-access-key-id"));
  assert.ok(html.includes("skipped")); // sast 跳过
  assert.ok(html.includes("sev-high"));
});

test("renderHtml:发现内容里的 HTML 被转义(防 XSS)", () => {
  const html = renderHtml({
    target: "x", summary: { total: 1, bySeverity: { HIGH: 1 } }, gate: { passed: true, failOn: "HIGH", reasons: [] },
    categories: { sast: { ok: true, findings: [{ rule: "<img src=x onerror=alert(1)>", severity: "HIGH", message: "</td><script>evil</script>", location: "a.js:1" }] } },
  });
  assert.ok(!html.includes("<script>evil</script>"));
  assert.ok(html.includes("&lt;script&gt;evil&lt;/script&gt;"));
  assert.ok(!html.includes("<img src=x onerror"));
});

// ---- Gradle / Dart / Elixir / Swift lockfile 解析(纯函数)----
import { parseGradleLockfileText, parsePubLockText, parseMixLockText, parseSwiftResolved, normalizeSwiftUrl } from "../src/lockfiles.js";

test("parseGradleLockfileText:Maven 坐标,忽略注释与 empty=", () => {
  const text = [
    "# Gradle generated",
    "com.fasterxml.jackson.core:jackson-databind:2.9.8=compileClasspath,runtimeClasspath",
    "org.apache.logging.log4j:log4j-core:2.14.1=runtimeClasspath",
    "empty=",
  ].join("\n");
  const { packages } = parseGradleLockfileText(text);
  const byName = Object.fromEntries(packages.map((p) => [p.name, p.version]));
  assert.equal(byName["com.fasterxml.jackson.core:jackson-databind"], "2.9.8");
  assert.equal(byName["org.apache.logging.log4j:log4j-core"], "2.14.1");
  assert.equal(packages.length, 2);
});

test("parsePubLockText:packages 段,direct/transitive 区分", () => {
  const text = [
    "packages:",
    "  http:",
    '    dependency: "direct main"',
    "    description:",
    "      name: http",
    "    source: hosted",
    '    version: "0.13.0"',
    "  async:",
    "    dependency: transitive",
    '    version: "2.8.0"',
    "sdks:",
    '  dart: ">=2.12.0"',
  ].join("\n");
  const { packages, direct } = parsePubLockText(text);
  const byName = Object.fromEntries(packages.map((p) => [p.name, p.version]));
  assert.equal(byName["http"], "0.13.0");
  assert.equal(byName["async"], "2.8.0");
  assert.equal(direct.has("http"), true);
  assert.equal(direct.has("async"), false);
});

test("parseMixLockText:只取 :hex 条目的名与版本", () => {
  const text = [
    "%{",
    '  "plug": {:hex, :plug, "1.0.0", "hash", [:mix], [], "hexpm"},',
    '  "bcrypt": {:hex, :bcrypt_elixir, "2.3.0", "hash", [:make, :mix], []},',
    "}",
  ].join("\n");
  const { packages } = parseMixLockText(text);
  const byName = Object.fromEntries(packages.map((p) => [p.name, p.version]));
  assert.equal(byName["plug"], "1.0.0");
  assert.equal(byName["bcrypt_elixir"], "2.3.0");
});

test("normalizeSwiftUrl + parseSwiftResolved:v2 pins → SwiftURL 名", () => {
  assert.equal(normalizeSwiftUrl("https://github.com/apple/swift-nio.git"), "github.com/apple/swift-nio");
  assert.equal(normalizeSwiftUrl("git@github.com:apple/swift-nio.git"), "github.com/apple/swift-nio");
  const v2 = JSON.stringify({ pins: [
    { identity: "swift-nio", location: "https://github.com/apple/swift-nio.git", state: { version: "2.29.0" } },
    { identity: "branchpin", location: "https://github.com/x/y.git", state: { branch: "main" } },
  ], version: 2 });
  const { packages } = parseSwiftResolved(v2);
  assert.equal(packages.length, 1); // 只固定了分支的那条被跳过
  assert.equal(packages[0].name, "github.com/apple/swift-nio");
  assert.equal(packages[0].version, "2.29.0");
});

test("parseSwiftResolved:v1 object.pins 也兼容", () => {
  const v1 = JSON.stringify({ object: { pins: [
    { package: "swift-nio", repositoryURL: "https://github.com/apple/swift-nio.git", state: { version: "2.0.0" } },
  ] }, version: 1 });
  const { packages } = parseSwiftResolved(v1);
  assert.equal(packages[0].name, "github.com/apple/swift-nio");
  assert.equal(packages[0].version, "2.0.0");
});

// ---- IaC 深化:CloudFormation / Ansible(纯函数)----
import { scanCloudFormation, scanAnsible } from "../src/iac.js";

test("classifyIac:识别 CloudFormation(JSON/YAML)与 Ansible", () => {
  assert.equal(classifyIac("tpl.yaml", "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n"), "cloudformation");
  assert.equal(classifyIac("tpl.json", '{"Resources":{"B":{"Type":"AWS::S3::Bucket"}}}'), "cloudformation");
  assert.equal(classifyIac("play.yml", "- hosts: web\n  tasks:\n    - name: x\n"), "ansible");
  // k8s 优先级高于 ansible 误判
  assert.equal(classifyIac("d.yaml", "apiVersion: apps/v1\nkind: Deployment\n"), "kubernetes");
  assert.equal(classifyIac("plain.json", '{"a":1}'), null);
});

test("scanCloudFormation:开放 CIDR / 公开桶 / IAM 通配 / 未加密 / 公网库 / 硬编码密钥", () => {
  const tpl = [
    "AWSTemplateFormatVersion: '2010-09-09'",
    "Resources:",
    "  SG:",
    "    Properties:",
    "      SecurityGroupIngress:",
    "        - CidrIp: 0.0.0.0/0",
    "  Bucket:",
    "    Properties:",
    "      AccessControl: PublicRead",
    "  Policy:",
    "    Properties:",
    '      Action: "*"',
    "  Vol:",
    "    Properties:",
    "      Encrypted: false",
    "  DB:",
    "    Properties:",
    "      PubliclyAccessible: true",
    '      MasterUserPassword: "hunter2plain"',
  ].join("\n");
  const rules = scanCloudFormation(tpl, "tpl.yaml").map((f) => f.rule);
  for (const r of ["cfn-open-cidr", "cfn-public-bucket", "cfn-iam-wildcard", "cfn-unencrypted", "cfn-public-db", "cfn-hardcoded-secret"]) {
    assert.ok(rules.includes(r), `应命中 ${r}`);
  }
  // 密钥值不回显
  const sec = scanCloudFormation(tpl, "tpl.yaml").find((f) => f.rule === "cfn-hardcoded-secret");
  assert.ok(!JSON.stringify(sec).includes("hunter2plain"));
});

test("scanCloudFormation:!Ref / Fn:: 引用不算硬编码密钥", () => {
  const tpl = 'Resources:\n  DB:\n    Properties:\n      MasterUserPassword: !Ref DbPassword\n';
  assert.equal(scanCloudFormation(tpl, "t.yaml").filter((f) => f.rule === "cfn-hardcoded-secret").length, 0);
});

test("scanAnsible:关证书校验 / 0777 / http 下载 / 硬编码密钥", () => {
  const play = [
    "- hosts: web",
    "  tasks:",
    "    - name: fetch",
    "      get_url:",
    "        url: http://example.com/app.tar.gz",
    "        validate_certs: no",
    "        mode: '0777'",
    "    - name: cfg",
    "      lineinfile:",
    "        db_password: supersecret123",
  ].join("\n");
  const rules = scanAnsible(play, "play.yml").map((f) => f.rule);
  assert.ok(rules.includes("ansible-no-cert-validation"));
  assert.ok(rules.includes("ansible-world-writable"));
  assert.ok(rules.includes("ansible-cleartext-download"));
  assert.ok(rules.includes("ansible-hardcoded-secret"));
});

test("scanAnsible:{{ 变量 }} 与 vault 引用不算硬编码密钥", () => {
  const play = "- hosts: all\n  tasks:\n    - name: x\n      debug:\n        db_password: \"{{ vault_db_password }}\"\n";
  assert.equal(scanAnsible(play, "p.yml").filter((f) => f.rule === "ansible-hardcoded-secret").length, 0);
});

// ---- Nuclei 归一化(纯函数,不触网)----
import { normalizeNuclei, mapNucleiSeverity } from "../src/nuclei.js";

test("mapNucleiSeverity:映射到我们的严重度(info→LOW)", () => {
  assert.equal(mapNucleiSeverity("critical"), "CRITICAL");
  assert.equal(mapNucleiSeverity("HIGH"), "HIGH");
  assert.equal(mapNucleiSeverity("info"), "LOW");
  assert.equal(mapNucleiSeverity("weird"), "UNKNOWN");
});

test("normalizeNuclei:解析 JSONL、提取 CVE/CWE、按严重度排序", () => {
  const jsonl = [
    JSON.stringify({ "template-id": "exposed-env", info: { name: "Exposed .env", severity: "medium" }, "matched-at": "https://x/.env", type: "http" }),
    JSON.stringify({ "template-id": "CVE-2021-44228", info: { name: "Log4Shell", severity: "critical", classification: { "cve-id": ["CVE-2021-44228"], "cwe-id": ["CWE-502"] }, reference: ["https://r"] }, "matched-at": "https://x/api", "extracted-results": ["jndi:ldap"] }),
    "not json",
    "",
  ].join("\n");
  const r = normalizeNuclei(jsonl, "https://x");
  assert.equal(r.ok, true);
  assert.equal(r.summary.total, 2);          // 非 JSON 行被跳过
  assert.equal(r.findings[0].severity, "CRITICAL"); // 高危排前
  assert.equal(r.findings[0].cve, "CVE-2021-44228");
  assert.deepEqual(r.findings[0].cwe, ["CWE-502"]);
  assert.deepEqual(r.findings[0].evidence.extracted, ["jndi:ldap"]);
  assert.equal(r.findings[1].rule, "exposed-env");
});

test("normalizeNuclei:空/坏输入不抛异常", () => {
  assert.equal(normalizeNuclei("", "t").summary.total, 0);
  assert.equal(normalizeNuclei(null, "t").findings.length, 0);
});

// 回归:nuclei 没真正跑起来(如模板库未安装)时必须报错,绝不能报成"未发现问题"
import { detectNucleiFailure } from "../src/nuclei.js";

test("detectNucleiFailure:识别 FTL / 模板缺失 / 非零退出码", () => {
  assert.match(detectNucleiFailure("[FTL] Could not run nuclei: no templates provided for scan", 1), /no templates provided/);
  assert.match(detectNucleiFailure('[ERR] Could not find template \'/home/u/nuclei-templates\': no templates found', 0), /Could not find template/);
  assert.equal(detectNucleiFailure("", 2), "nuclei 退出码 2");
});

test("detectNucleiFailure:正常运行(无致命错误、退出码 0)返回 null", () => {
  assert.equal(detectNucleiFailure("[INF] Templates loaded: 100\n[INF] Scan completed", 0), null);
  assert.equal(detectNucleiFailure("", 0), null);
});
