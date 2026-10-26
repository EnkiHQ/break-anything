# Third-party notices

Break Anything-authored code is licensed under [MIT](LICENSE). Break Anything orchestrates and,
in some modes, requires external tools and data sources that retain their own licenses and terms.
Break Anything grants no license to these tools; you must obtain and use them under their
applicable terms.

## Bundled npm dependency

| Package | License | Purpose |
| --- | --- | --- |
| `@modelcontextprotocol/sdk` | MIT | MCP server protocol implementation |

## Orchestrated tools (not bundled)

These are invoked if present on your system. Break Anything does not install or redistribute
them. Licenses are listed for convenience; verify against each project before relying on it.

| Category | Tool | License |
| --- | --- | --- |
| SCA | Trivy (Aqua) · Grype (Anchore) · osv-scanner (Google) | Apache-2.0 |
| SCA | pip-audit · cargo-audit · bundler-audit · govulncheck | Apache-2.0 / MIT |
| SCA | OWASP Dependency-Check | Apache-2.0 |
| SBOM | Syft (Anchore) | Apache-2.0 |
| Secrets | gitleaks · detect-secrets (Yelp) | MIT / Apache-2.0 |
| Secrets | TruffleHog (Truffle Security) | AGPL-3.0 |
| Images | Dockle · Hadolint | Apache-2.0 / GPL-3.0 |
| SAST | Semgrep | LGPL-2.1 (CLI) |
| SAST | CodeQL | GitHub CodeQL terms (research/CI) |
| SAST | Bandit · gosec · Brakeman · njsscan · cppcheck | Apache-2.0 / MIT / GPL |
| IaC | Checkov · tfsec · Terrascan · KICS | Apache-2.0 |
| IaC | kube-score · kubesec · kube-bench | Apache-2.0 |
| CSPM | Prowler | Apache-2.0 |
| CSPM | ScoutSuite (NCC Group) | GPL-2.0 |
| DAST | OWASP ZAP | Apache-2.0 |
| DAST | Nuclei · httpx · subfinder · naabu (ProjectDiscovery) | MIT |
| DAST | Nikto · Wapiti | GPL-2.0 / GPL-2.0 |
| DAST | sqlmap | GPL-2.0 |
| API | Schemathesis | MIT |
| Recon | Nmap | Nmap Public Source License (NPSL) |
| SAST | SonarQube CE · Find-Sec-Bugs · security-code-scan (.NET) · retire.js | LGPL / various |
| IaC/K8s | Kubescape (ARMO) · Falco (CNCF) | Apache-2.0 |
| Web/recon | ffuf · Katana · Dalfox · Amass (OWASP) · gobuster | MIT / Apache-2.0 |
| Network/TLS | testssl.sh · sslyze · OpenVAS/Greenbone | GPL-2.0 / AGPL-3.0 |
| Offensive (authorized) | Metasploit Framework (Rapid7) | BSD-3-Clause |
| Offensive (authorized) | Hydra · Hashcat · BloodHound · Impacket | GPL / MIT |
| LLM security | Garak (NVIDIA) | Apache-2.0 |
| Binary | Ghidra (NSA) · radare2 · angr | Apache-2.0 / LGPL / BSD |
| Web3 | Slither · Echidna (Trail of Bits) | AGPL-3.0 |
| Web3 | Mythril (Consensys) | MIT |
| Mobile | MobSF | GPL-3.0 |
| Fuzzing | AFL++ · libFuzzer · Jazzer · Atheris · cargo-fuzz | Apache-2.0 / MIT |

> Note on copyleft (GPL/AGPL) tools: Break Anything invokes them as separate external processes
> and does not link or bundle their code, so orchestration does not create a derivative work.
> You remain responsible for complying with each tool's license when you install and run it.

## Data sources

| Source | Terms | Used by |
| --- | --- | --- |
| OSV.dev | CC-BY-4.0 / per-entry | `deps` CVE lookup |
| FIRST.org EPSS | FIRST EPSS terms (free) | `deps` exploit-probability enrichment |
| GitHub Advisory Database | CC-BY-4.0 | via OSV |
| CISA KEV | U.S. public domain | planned KEV enrichment |

If you add a tool or data source, record it here in the same PR.
