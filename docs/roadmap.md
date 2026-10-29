# Roadmap

Break Anything is growing from a dependency scanner into one agent-facing interface for finding,
proving, and fixing weaknesses across the whole surface of a project you own. Roadmap items
describe direction, not shipped support. A new scanner joins the public workflow only once it
produces the same finding envelope (severity, evidence, exploitability, remediation, limitations)
as the shipped scanners.

## Shipped (0.15.0)

- **Supply chain / dependencies (SCA)** — 12 ecosystems: npm (package-lock / yarn / pnpm), PyPI,
  Composer (PHP), Go, Rust, Ruby, Maven + Gradle (Java), NuGet (.NET), Dart (Pub), Elixir (Hex),
  Swift (SPM); OSV lookup, two-tier reachability (`called` > `imported`), EPSS, **CISA KEV
  (known-exploited)**, fix versions.
- **Secrets** — working tree + git history, redacted output.
- **Container images** — via Trivy.
- **Static code (SAST)** — via Semgrep: injection, broken access control, deserialization, SSRF,
  with CWE/OWASP tags and the offending snippet.
- **Infrastructure as Code (IaC)** — built-in, no external engine; 5 formats: Dockerfile,
  Kubernetes, Terraform, CloudFormation (YAML+JSON), Ansible — root containers, privileged pods,
  world-open CIDRs, public buckets, wildcard IAM, disabled encryption, public databases, disabled
  TLS verification, baked-in secrets — with file/line, CWE, and a fix.
- **API security (DAST)** — dynamic probe of a running API for broken object-level authorization
  (IDOR/BOLA), missing authentication, and missing security headers, each with the reproducing
  request as proof. Off by default; authorized targets only.
- **Fix planning** — turns dependency findings into a prioritized remediation plan: minimal safe
  upgrades ordered by reachability then severity, with the exact `npm`/`pip`/`composer` command.
- **One-shot CI gate** — `ci` runs deps+secrets+iac+sast in one command with a single pass/fail
  exit code, combined report, and merged SARIF; configurable via a `.break-anything.json` policy
  (threshold, skip, ignore/baseline).
- **MCP tools** — `deps_scan`, `secrets_scan`, `image_scan`, `sast_scan`, `iac_scan`, `api_scan`,
  `fix_plan`, `sbom_generate`, `ci_scan`.

## Next

- **More SAST engines** — CodeQL, Bandit (Python), gosec (Go), Brakeman (Rails), Find-Sec-Bugs
  (Java), security-code-scan (.NET), retire.js (frontend) — broaden language/stack coverage.
- **Exploitability engine** — reachability is two-tier (`called` > `imported`) and findings now
  carry EPSS + CISA KEV; next is a real call graph to the specific vulnerable symbol named in the
  advisory.
- **More DAST checks** — injection, SSRF, auth/session flaws, plus Nuclei templates and
  OpenAPI-driven fuzzing (Schemathesis) on top of today's authorization prober.
- **Deeper IaC** — opt-in Checkov / tfsec / KICS backends plus CloudFormation, ARM/Bicep, Ansible
  and full CIS benchmarks on top of the built-in rules.

## Later

- **Cloud posture (CSPM)** — Prowler / ScoutSuite against your own AWS/GCP/Azure accounts.
- **Attack surface & recon** — Nmap + Amass + ProjectDiscovery (ffuf/Katana/Dalfox) over your own domains and hosts.
- **Offensive / exploitation (authorized pentest)** — Metasploit, Hydra, Hashcat, BloodHound + Impacket, OpenVAS. Gated, off by default, written-permission-only; turns a "reachable" finding into a proven one.
- **AI / LLM security** — Garak-backed prompt-injection, jailbreak, and data-leakage probes for your own models and agents.
- **Binary & artifact analysis** — Ghidra / radare2 / angr for compiled binaries and firmware (pairs with REA).
- **Smart contracts** — Slither / Mythril / Echidna for Solidity.
- **Mobile** — MobSF for APK/IPA.
- **Fuzzing** — AFL++ / libFuzzer / Jazzer / Atheris with minimized reproducers.
- **Self-remediation (deeper)** — `fix` ships today for dependency upgrade planning; next is
  generating patches, pins, and compatibility shims when upstream has no fix, with a deep handoff to
  [Patch Anything](https://github.com/EnkiHQ/patch-anything) for a merge-ready PR.
- **Evidence bundles** — portable, reproducible finding records that survive across sessions and
  gate CI. Already shipped: CycloneDX SBOM generation + diff (`sbom`) and SARIF 2.1.0 output
  (`--sarif`) for GitHub/GitLab code scanning.

## Principles

- Defensive, authorized-targets-only. Dynamic capabilities stay off by default.
- Orchestrate trusted tools; don't reinvent scanners.
- Signal over noise: always separate "confirmed", "reachable", and "present".
- Honesty: absence of a finding is never reported as proof of safety.
