# Roadmap

Break Anything is growing from a dependency scanner into one agent-facing interface for finding,
proving, and fixing weaknesses across the whole surface of a project you own. Roadmap items
describe direction, not shipped support. A new scanner joins the public workflow only once it
produces the same finding envelope (severity, evidence, exploitability, remediation, limitations)
as the shipped scanners.

## Shipped (0.5.0)

- **Supply chain / dependencies (SCA)** — npm, Composer (PHP), pip; OSV lookup, import-based
  reachability heuristic, EPSS, fix versions.
- **Secrets** — working tree + git history, redacted output.
- **Container images** — via Trivy.
- **Static code (SAST)** — via Semgrep: injection, broken access control, deserialization, SSRF,
  with CWE/OWASP tags and the offending snippet.
- **Infrastructure as Code (IaC)** — built-in, no external engine: Dockerfile, Kubernetes, and
  Terraform misconfigurations (root containers, privileged pods, world-open CIDRs, public buckets,
  baked-in secrets) with file/line, CWE, and a fix.
- **API security (DAST)** — dynamic probe of a running API for broken object-level authorization
  (IDOR/BOLA), missing authentication, and missing security headers, each with the reproducing
  request as proof. Off by default; authorized targets only.
- **MCP tools** — `deps_scan`, `secrets_scan`, `image_scan`, `sast_scan`, `iac_scan`, `api_scan`.

## Next

- **More SAST engines** — CodeQL, Bandit (Python), gosec (Go), Brakeman (Rails), Find-Sec-Bugs
  (Java), security-code-scan (.NET), retire.js (frontend) — broaden language/stack coverage.
- **Exploitability engine** — upgrade reachability from "is it imported" to "is the vulnerable
  symbol on a real call path", and rank with EPSS + CISA KEV.
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
- **Self-remediation** — when upstream has no fix: generate a patch, pin, compatibility shim, or
  point to a maintained fork. Deep handoff to [Patch Anything](https://github.com/EnkiHQ/patch-anything).
- **SBOM & evidence bundles** — generate/diff SBOMs (Syft) and portable, reproducible finding
  records that survive across sessions and gate CI.

## Principles

- Defensive, authorized-targets-only. Dynamic capabilities stay off by default.
- Orchestrate trusted tools; don't reinvent scanners.
- Signal over noise: always separate "confirmed", "reachable", and "present".
- Honesty: absence of a finding is never reported as proof of safety.
