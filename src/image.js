import { spawn } from "node:child_process";

// 容器镜像扫描:封装 Trivy(行业标准)。装了 trivy 就能用,没装给出清晰安装提示。
// 把 Trivy 的 JSON 归一化成 Break Anything 统一的发现结构。

export async function scanImage(ref, { severityFilter } = {}) {
  const trivy = await which("trivy");
  if (!trivy) {
    return {
      target: ref,
      ok: false,
      engine: "trivy",
      message:
        "未找到 trivy。镜像扫描依赖 Trivy(Aqua Security)。安装:\n" +
        "  macOS:  brew install trivy\n" +
        "  Linux:  见 https://aquasecurity.github.io/trivy/latest/getting-started/installation/",
      findings: [],
      summary: { total: 0, bySeverity: {} },
    };
  }

  const args = ["image", "--quiet", "--format", "json", "--scanners", "vuln"];
  if (severityFilter) args.push("--severity", severityFilter);
  args.push(ref);

  let raw;
  try {
    raw = await run(trivy, args);
  } catch (err) {
    return {
      target: ref,
      ok: false,
      engine: "trivy",
      message: `trivy 执行失败:${err instanceof Error ? err.message : String(err)}`,
      findings: [],
      summary: { total: 0, bySeverity: {} },
    };
  }

  return normalizeTrivy(raw, ref);
}

// 导出以便单测:把 trivy JSON 文本归一化
export function normalizeTrivy(rawJson, ref) {
  let data;
  try { data = typeof rawJson === "string" ? JSON.parse(rawJson) : rawJson; }
  catch { return { target: ref, ok: false, engine: "trivy", message: "无法解析 trivy 输出", findings: [], summary: { total: 0, bySeverity: {} } }; }

  const findings = [];
  for (const result of data.Results || []) {
    const target = result.Target;
    const cls = result.Class; // os-pkgs / lang-pkgs
    for (const v of result.Vulnerabilities || []) {
      findings.push({
        package: v.PkgName,
        version: v.InstalledVersion,
        id: v.VulnerabilityID,
        cve: /^CVE-/i.test(v.VulnerabilityID || "") ? v.VulnerabilityID : null,
        severity: (v.Severity || "UNKNOWN").toUpperCase(),
        fixedVersions: v.FixedVersion ? [v.FixedVersion] : [],
        class: cls,
        location: target,
        summary: v.Title || (v.Description ? v.Description.slice(0, 160) : ""),
        references: (v.References || []).slice(0, 5),
      });
    }
  }
  findings.sort((a, b) => sevRank(b.severity) - sevRank(a.severity));

  return {
    target: ref,
    ok: true,
    engine: "trivy",
    findings,
    summary: {
      total: findings.length,
      fixable: findings.filter((f) => f.fixedVersions.length).length,
      bySeverity: countBy(findings, "severity"),
    },
  };
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

function run(cmd, args) {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    let err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));
    p.on("close", (code) => {
      if (code === 0 || out.trim().startsWith("{")) resolve(out);
      else reject(new Error(err.trim().slice(0, 300) || `exit ${code}`));
    });
    p.on("error", reject);
  });
}

const SEV = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
function sevRank(s) { return SEV[s] ?? 0; }
function countBy(arr, key) {
  const m = {};
  for (const x of arr) m[x[key]] = (m[x[key]] || 0) + 1;
  return m;
}
