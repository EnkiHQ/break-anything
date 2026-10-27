# Tool catalog & MCP contracts

Break Anything is one MCP interface over a deep arsenal of industry-standard scanners. The public
MCP interface describes *what the agent wants to learn*; a provider decides *how* to answer. This
page is the exhaustive catalog, organized by scan category.

Legend: **✅ shipped (0.7.0: `deps_scan`, `secrets_scan`, `image_scan`, `sast_scan`, `iac_scan`,
`api_scan`, `fix_plan`)** · **🧭 roadmap**. Dynamic (traffic-sending) tools are **off by default**
and refuse any target not on the authorization allowlist.

---

## ✅ Supply chain & dependencies (SCA) — `deps_scan`

| | |
| --- | --- |
| **Status** | ✅ shipped |
| **Primary engine** | OSV.dev query API (built-in, no install) |
| **Additional engines** | Trivy, Grype, pip-audit, govulncheck, cargo-audit, bundler-audit, `composer audit`, OWASP Dependency-Check |
| **Ecosystems** | npm, PyPI, Composer (PHP), Go, Maven/Gradle, Cargo, RubyGems, NuGet |
| **Intel overlay** | EPSS (exploit probability), CISA KEV (known-exploited), GitHub Advisory |
| **SBOM** | Syft / CycloneDX generation + diff |
| **Signal** | two-tier reachability: `called` (an imported symbol is invoked in your code) > `imported` > `direct` > `transitive`; call-path-to-vulnerable-symbol on the roadmap |
| **MCP tool** | `deps_scan(path, reachability?)` |
| **CLI** | `brk deps <path> [--json] [--no-reachability]` |

## ✅ Secrets — `secrets_scan`

| | |
| --- | --- |
| **Status** | ✅ shipped |
| **Primary engine** | built-in pattern + entropy scanner |
| **Additional engines** | Gitleaks, TruffleHog, detect-secrets |
| **Scope** | working tree + full git history (`--history`) |
| **Patterns** | AWS, GCP, Stripe, GitHub, GitLab, Slack, OpenAI, JWTs, private keys, generic assigned secrets |
| **Extras** | redacted output; optional live-key validation (roadmap) |
| **MCP tool** | `secrets_scan(path, history?)` |
| **CLI** | `brk secrets <path> [--history] [--json]` |

## ✅ Containers & images — `image_scan`

| | |
| --- | --- |
| **Status** | ✅ shipped (requires Trivy) |
| **Engines** | Trivy, Grype, Dockle (CIS best practices), Hadolint (Dockerfile lint) |
| **Finds** | OS + app-layer CVEs, Dockerfile anti-patterns, secrets in layers |
| **MCP tool** | `image_scan(ref)` |
| **CLI** | `brk image <ref> [--json]` |

---

## ✅ Static code analysis (SAST) — `sast_scan`

| | |
| --- | --- |
| **Status** | ✅ shipped (requires Semgrep) |
| **Primary engine** | Semgrep (default ruleset `p/security-audit`) |
| **Roadmap engines** | CodeQL, Bandit (Python), gosec (Go), Brakeman (Rails), Find-Sec-Bugs (Java), Psalm/PHPStan (PHP), njsscan (JS/TS), cppcheck (C/C++) |
| **Finds** | injection, XSS, broken access control, insecure deserialization, path traversal, SSRF, weak crypto — each with file/line, CWE/OWASP tags, and the snippet |
| **MCP tool** | `sast_scan(path, config?)` |
| **CLI** | `brk sast <path> [--json] [--config=<ruleset>] [--top=N]` |

## ✅ Infrastructure as Code (IaC) — `iac_scan`

| | |
| --- | --- |
| **Status** | ✅ shipped — **built in, no external engine** |
| **Primary engine** | built-in rule set (Node, no install) |
| **Roadmap engines** | Checkov, tfsec, Terrascan, KICS, Kubescape, kube-bench (opt-in depth) |
| **Targets** | Dockerfile, Kubernetes/Helm manifests, Terraform (HCL) |
| **Finds** | runs-as-root / no `USER`, `:latest` images, piped remote shell, baked-in secrets (Docker); privileged containers, host namespaces, dangerous capabilities (K8s); world-open CIDR, public buckets, disabled encryption, hardcoded secrets (Terraform) |
| **Roadmap finds** | CloudFormation/ARM/Bicep/Ansible, full CIS benchmarks, over-broad IAM |
| **MCP tool** | `iac_scan(path)` |
| **CLI** | `brk iac <path> [--json] [--top=N]` |

The built-in rules target the most common high-impact misconfigurations with low false positives
(for example, it ignores Terraform `var.*` references when flagging hardcoded secrets). For
exhaustive policy-as-code, the roadmap adds opt-in Checkov/Trivy/KICS backends behind the same
finding envelope.

## 🧭 Cloud posture (CSPM) — `cloud_audit`

| | |
| --- | --- |
| **Engines** | Prowler, ScoutSuite |
| **Clouds** | AWS, GCP, Azure (your own accounts/credentials) |
| **Finds** | CIS/PCI/SOC2 control failures, exposed resources, weak IAM |
| **Planned tool** | `cloud_audit(provider, profile)` — **dynamic, off by default** |

## ✅ API security (DAST) — `api_scan`

| | |
| --- | --- |
| **Status** | ✅ shipped — **dynamic, off by default** |
| **Primary engine** | built-in authorization prober (Node `fetch`, no external engine) |
| **Roadmap engines** | Schemathesis (OpenAPI property-testing/fuzzing), ZAP API scan |
| **Finds** | broken object-level authorization (IDOR/BOLA, CWE-639 / API1:2023), missing authentication (CWE-306 / API2:2023), missing security headers (CWE-693 / API8:2023) |
| **Roadmap finds** | mass assignment, excessive data exposure, OpenAPI-driven fuzzing |
| **Proof** | every finding ships the **reproducing request**, credentials redacted |
| **Gate** | requires `BRK_DYNAMIC_ENABLED=true` **and** target in `BRK_AUTHORIZED_TARGETS_JSON` |
| **MCP tool** | `api_scan(baseUrl, accounts?, idorPaths?)` |
| **CLI** | `brk api <baseUrl> [--config accounts.json] [--json]` |

The IDOR check is designed to avoid false positives: it only flags access when account A's
credentials return the **exact private resource** account B sees for itself, and that response
differs from A's own. Supply the two accounts you control via `--config`:

```json
{
  "accounts": {
    "A": { "headers": { "Authorization": "Bearer tokenA" }, "ownedId": "1" },
    "B": { "headers": { "Authorization": "Bearer tokenB" }, "ownedId": "2" }
  },
  "idorPaths": ["/orders/{id}", "/api/users/{id}/profile"]
}
```

## 🧭 More running-app checks (DAST) — `dast_scan`

| | |
| --- | --- |
| **Engines** | OWASP ZAP, Nuclei, Nikto, Wapiti, sqlmap, ffuf, Katana, Dalfox, gobuster |
| **Finds** | injection, XSS, SSRF, session flaws, hidden content/params — with the triggering request |
| **Planned tools** | `dast_scan(url, profile)`, `dast_nuclei(url, templates)` — **dynamic, off by default** |

## 🧭 Attack surface & recon — `recon`

| | |
| --- | --- |
| **Engines** | Nmap, Amass (OWASP), ProjectDiscovery suite (subfinder, httpx, naabu, dnsx, katana) |
| **Finds** | forgotten subdomains, exposed services, open ports, tech fingerprint, TLS/cert config (testssl.sh, sslyze) |
| **Planned tool** | `recon(domain)` — **dynamic, off by default, your own assets only** |

## 🧭 Smart contracts (Web3) — `contract_scan`

| | |
| --- | --- |
| **Engines** | Slither, Mythril, Echidna (fuzzing) |
| **Finds** | reentrancy, integer overflow, access-control gaps, oracle manipulation |
| **Planned tool** | `contract_scan(path)` |

## 🧭 Mobile — `mobile_scan`

| | |
| --- | --- |
| **Engines** | MobSF, APKiD, Semgrep mobile rules |
| **Targets** | Android APK, iOS IPA |
| **Finds** | insecure storage, hardcoded secrets, weak crypto, exported components |
| **Planned tool** | `mobile_scan(path)` |

## 🧭 Fuzzing — `fuzz`

| | |
| --- | --- |
| **Engines** | AFL++, libFuzzer, Atheris (Python), Jazzer (Java), cargo-fuzz |
| **Finds** | crashes, memory-safety bugs, panics — with a minimized reproducer |
| **Planned tool** | `fuzz(target, harness)` — **dynamic, off by default** |

## 🧭 Offensive / exploitation (authorized pentest) — `exploit_*`

| | |
| --- | --- |
| **Scope** | **Authorized targets only.** Gated, **off by default**, requires written permission and an allowlist. |
| **Engines** | Metasploit Framework, sqlmap, Hydra, Hashcat, BloodHound + Impacket (Active Directory), OpenVAS/Greenbone |
| **Finds** | confirmed exploitability — turns a "reachable" finding into a proven one on a target you own |
| **Planned tools** | `exploit_confirm(finding)`, `exploit_ad_path`, `exploit_cred_spray` — **dynamic, off by default** |

> This family exists so Break Anything can *prove* exploitability like a pentester, not so it can
> attack strangers. Every tool here refuses targets outside your authorization allowlist, and the
> project declines contributions that weaponize it against systems you don't control.

## 🧭 AI / LLM security — `llm_scan`

| | |
| --- | --- |
| **Engines** | [Garak](https://github.com/NVIDIA/garak), prompt-injection + jailbreak probes |
| **Targets** | your own models, agents, and MCP tool surfaces |
| **Finds** | prompt injection, jailbreaks, training-data/secret leakage, unsafe tool exposure |
| **Planned tool** | `llm_scan(endpoint)` — **dynamic, off by default** |

## 🧭 Binary & artifact analysis — `binary_scan`

| | |
| --- | --- |
| **Engines** | Ghidra, radare2/rizin, angr (symbolic execution) |
| **Targets** | compiled binaries, firmware, packaged apps |
| **Finds** | known-vulnerable bundled deps, memory-safety smells, hardcoded secrets (pairs with the REA companion) |
| **Planned tool** | `binary_scan(path)` |

## ✅ Remediation & handoff — `fix_plan`

| | |
| --- | --- |
| **Status** | ✅ shipped (dependency upgrades) |
| **Produces** | a prioritized plan, not a scan |
| **Logic** | group CVEs by package → minimal safe upgrade that clears the most CVEs → order by reachability (`called` first) then severity → exact `npm`/`pip`/`composer` command |
| **No-fix path** | packages with no upstream fix are listed with mitigation guidance (pin, mitigate, maintained fork) |
| **MCP tool** | `fix_plan(path, reachability?)` |
| **CLI** | `brk fix <path> [--from deps.json] [--json]` |
| **Roadmap** | `fix_suggest_patch(finding)`, `fix_mitigation(finding)`, deep handoff to Patch Anything for a merge-ready PR |

---

## Authorization gates

Dynamic families (`dast_*`, `api_*`, `recon`, `cloud_audit`, `fuzz`, `exploit_*`, `llm_scan`)
require both:

```bash
export BRK_DYNAMIC_ENABLED=true
export BRK_AUTHORIZED_TARGETS_JSON='["http://localhost:3000","https://staging.example.internal"]'
```

A dynamic tool refuses any target not present in `BRK_AUTHORIZED_TARGETS_JSON`. There is no flag
that disables this check.

## Evidence envelope

Every tool returns a structured result:

- `finding` — the weakness, with a stable ID
- `provider` — which engine produced it (e.g. `osv`, `trivy`, `semgrep`, `zap`)
- `exploitability` — `confirmed` | `reachable` | `present` | `not_reachable`, plus EPSS and KEV
- `evidence` — file/line, data-flow, or the request/response that proves it
- `remediation` — fix version, patch sketch, or mitigation
- `limitations` — what this result does **not** establish

## Manual MCP registration

```json
{
  "mcpServers": {
    "break-anything": {
      "command": "npx",
      "args": ["-y", "break-anything", "mcp"]
    }
  }
}
```
