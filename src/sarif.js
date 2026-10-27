// SARIF 2.1.0 输出:业界标准的静态分析结果交换格式。
// 让 Break Anything 的发现能直接喂进 GitHub / GitLab 代码扫描面板、IDE 安全视图。
// 纯确定性转换,可单测。支持 deps / sast / iac / secrets 四类发现。

const TOOL_VERSION = "0.12.0";
const INFO_URI = "https://github.com/EnkiHQ/break-anything";

// 我们的严重度 → SARIF level 与 GitHub 的 security-severity 数值
const LEVEL = { CRITICAL: "error", HIGH: "error", MEDIUM: "warning", LOW: "note", UNKNOWN: "none" };
const SECSEV = { CRITICAL: "9.5", HIGH: "8.0", MEDIUM: "5.0", LOW: "2.0", UNKNOWN: "0.0" };

function levelFor(sev) { return LEVEL[sev] || "warning"; }
function secSevFor(sev) { return SECSEV[sev] || "0.0"; }

// "file:line" → { uri, line };相对化绝对路径(去掉 root 前缀)
export function splitLocation(loc, root) {
  if (!loc) return { uri: "", line: undefined };
  const m = /^(.*):(\d+)$/.exec(loc);
  let uri = m ? m[1] : loc;
  const line = m ? Number(m[2]) : undefined;
  if (root && uri.startsWith(root.endsWith("/") ? root : root + "/")) {
    uri = uri.slice(root.length + (root.endsWith("/") ? 0 : 1));
  }
  return { uri, line };
}

// 通用构建器:把中间项数组装成 SARIF(纯函数,可单测)
export function buildSarif(items, { toolVersion = TOOL_VERSION } = {}) {
  const rulesMap = new Map();
  const results = [];
  for (const it of items) {
    if (!rulesMap.has(it.ruleId)) {
      rulesMap.set(it.ruleId, {
        id: it.ruleId,
        name: it.name || it.ruleId,
        shortDescription: { text: (it.shortDescription || it.name || it.ruleId || "").toString().slice(0, 300) || it.ruleId },
        ...(it.helpUri ? { helpUri: it.helpUri } : {}),
        properties: {
          ...(it.securitySeverity ? { "security-severity": it.securitySeverity } : {}),
          ...(it.tags ? { tags: it.tags } : {}),
        },
      });
    }
    results.push({
      ruleId: it.ruleId,
      level: it.level,
      message: { text: it.message },
      locations: (it.locations || []).map((l) => ({
        physicalLocation: {
          artifactLocation: { uri: l.uri },
          ...(l.line ? { region: { startLine: l.line } } : {}),
        },
      })),
      ...(it.properties ? { properties: it.properties } : {}),
    });
  }
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "break-anything",
          version: toolVersion,
          informationUri: INFO_URI,
          rules: [...rulesMap.values()],
        },
      },
      results,
    }],
  };
}

// ---- 各类发现 → 中间项 ----
function depsItems(result) {
  const root = result.target;
  const ecoFile = {};
  for (const s of result.sources || []) ecoFile[s.ecosystem] = splitLocation(s.file, root).uri;
  return (result.findings || []).map((f) => ({
    ruleId: f.cve || f.id,
    name: f.package,
    shortDescription: f.summary || f.cve || f.id,
    helpUri: f.cve ? `https://nvd.nist.gov/vuln/detail/${f.cve}` : `https://osv.dev/vulnerability/${f.id}`,
    level: levelFor(f.severity),
    securitySeverity: secSevFor(f.severity),
    message: `${f.package}@${f.version} (${f.ecosystem}) ${f.cve || f.id}: ${(f.summary || "").replace(/\s+/g, " ").slice(0, 200)}`,
    locations: [{ uri: ecoFile[f.ecosystem] || "dependencies", line: undefined }],
    properties: {
      package: `${f.package}@${f.version}`, ecosystem: f.ecosystem,
      reachability: f.reachability, epss: f.epss ?? null, kev: !!f.kev,
      fixedVersions: f.fixedVersions || [],
    },
    tags: ["dependency", f.ecosystem, ...(f.kev ? ["kev"] : [])],
  }));
}

function sastItems(result) {
  const root = result.target;
  return (result.findings || []).map((f) => {
    const { uri, line } = splitLocation(f.location, root);
    return {
      ruleId: f.id || f.rule,
      name: f.rule,
      shortDescription: f.message || f.rule,
      helpUri: (f.references && f.references[0]) || undefined,
      level: levelFor(f.severity),
      securitySeverity: secSevFor(f.severity),
      message: f.message || f.rule,
      locations: [{ uri, line }],
      properties: { cwe: f.cwe || [], owasp: f.owasp || [], confidence: f.confidence || null },
      tags: ["sast", ...(f.cwe || [])],
    };
  });
}

function iacItems(result) {
  const root = result.target;
  return (result.findings || []).map((f) => {
    const { uri, line } = splitLocation(f.location, root);
    return {
      ruleId: f.rule,
      name: f.title || f.rule,
      shortDescription: f.title || f.rule,
      level: levelFor(f.severity),
      securitySeverity: secSevFor(f.severity),
      message: `${f.title}${f.remediation ? ` — ${f.remediation}` : ""}`,
      locations: [{ uri, line }],
      properties: { kind: f.kind, cwe: f.cwe || null },
      tags: ["iac", f.kind, ...(f.cwe ? [f.cwe] : [])],
    };
  });
}

function secretsItems(result) {
  return (result.findings || []).map((f) => {
    const inHistory = f.source === "history";
    const uri = inHistory ? `git-history${f.commit ? `@${f.commit}` : ""}` : (f.location || "");
    return {
      ruleId: f.rule,
      name: f.rule,
      shortDescription: `Potential leaked secret: ${f.rule}`,
      level: levelFor(f.severity),
      securitySeverity: secSevFor(f.severity),
      message: `Potential leaked secret (${f.rule})${inHistory ? ` in git history ${f.commit || ""}` : ""}. Rotate it — don't just delete.`,
      locations: [{ uri, line: inHistory ? undefined : f.line }],
      properties: { source: f.source, ...(f.commit ? { commit: f.commit } : {}) },
      tags: ["secret", "CWE-798"],
    };
  });
}

const ADAPTERS = { deps: depsItems, sast: sastItems, iac: iacItems, secrets: secretsItems };

// 入口:kind + 某命令的结果对象 → SARIF 文档(纯函数,可单测)
export function toSarif(kind, result, opts = {}) {
  const adapter = ADAPTERS[kind];
  const items = adapter ? adapter(result) : [];
  return buildSarif(items, opts);
}
