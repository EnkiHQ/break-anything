// 端到端集成测试:全部离线、确定性,适合 CI(不依赖 OSV/网络)。
// 覆盖真正会碰文件系统的扫描函数,并把 scan → SARIF / SBOM 串起来验证。

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { scanIac } from "../src/iac.js";
import { generateSbom } from "../src/sbom.js";
import { scanSecrets } from "../src/secrets.js";
import { toSarif } from "../src/sarif.js";

function tmp() { return mkdtempSync(path.join(tmpdir(), "brk-it-")); }

test("集成:IaC 扫描发现 Dockerfile 错误配置,并能转成合法 SARIF", async () => {
  const d = tmp();
  try {
    writeFileSync(path.join(d, "Dockerfile"),
      'FROM python:latest\nENV API_KEY=supersecret123\nCMD ["python", "app.py"]\n');
    const r = await scanIac(d);
    assert.equal(r.ok, true);
    const rules = r.findings.map((f) => f.rule);
    assert.ok(rules.includes("docker-no-user"));
    assert.ok(rules.includes("docker-latest-tag"));
    assert.ok(rules.includes("docker-hardcoded-secret"));
    // 密钥值不回显
    const sec = r.findings.find((f) => f.rule === "docker-hardcoded-secret");
    assert.ok(!JSON.stringify(sec).includes("supersecret123"));

    const sarif = toSarif("iac", r);
    assert.equal(sarif.version, "2.1.0");
    assert.equal(sarif.runs[0].tool.driver.name, "break-anything");
    assert.ok(sarif.runs[0].results.length >= 3);
    assert.ok(sarif.runs[0].results.every((x) => x.ruleId && x.locations.length));
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("集成:从 package-lock.json 生成 CycloneDX SBOM", async () => {
  const d = tmp();
  try {
    writeFileSync(path.join(d, "package.json"),
      JSON.stringify({ name: "demo", version: "1.0.0", dependencies: { lodash: "4.17.4" } }));
    writeFileSync(path.join(d, "package-lock.json"), JSON.stringify({
      name: "demo", version: "1.0.0", lockfileVersion: 3,
      packages: { "": { name: "demo", version: "1.0.0" }, "node_modules/lodash": { version: "4.17.4" } },
    }));
    const r = await generateSbom(d);
    assert.equal(r.ok, true);
    assert.equal(r.bom.bomFormat, "CycloneDX");
    assert.equal(r.bom.specVersion, "1.5");
    assert.ok(r.bom.components.some((c) => c.purl === "pkg:npm/lodash@4.17.4"));
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("集成:密钥扫描命中植入的 AWS key(脱敏)", async () => {
  const d = tmp();
  try {
    writeFileSync(path.join(d, "config.txt"), "aws_key = AKIAIOSFODNN7EXAMPLE\n");
    const r = await scanSecrets(d, { history: false });
    assert.equal(r.ok, true);
    const hit = r.findings.find((f) => f.rule === "aws-access-key-id");
    assert.ok(hit, "应命中 aws-access-key-id");
    // 转 SARIF 也要正常
    const sarif = toSarif("secrets", r);
    assert.equal(sarif.version, "2.1.0");
    assert.ok(sarif.runs[0].results.length >= 1);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("集成:无受支持 lockfile 时 SBOM 优雅失败", async () => {
  const d = tmp();
  try {
    writeFileSync(path.join(d, "README.md"), "# nothing here\n");
    const r = await generateSbom(d);
    assert.equal(r.ok, false);
    assert.ok(r.bom == null);
  } finally { rmSync(d, { recursive: true, force: true }); }
});
