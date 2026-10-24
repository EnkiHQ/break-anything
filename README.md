<div align="center">

**English** · [简体中文](docs/readme/README_zh.md)

# Break Anything

### One MCP server that turns your coding agent into a security team.

**Point it at anything you own — code, a dependency tree, a container, a running app, your cloud — it finds what's broken, proves it on your own target, and hands back the fix.**

[![npm version](https://img.shields.io/badge/npm-break--anything-cb3837?style=flat-square)](https://www.npmjs.com/package/break-anything)
[![MCP tool catalog](https://img.shields.io/badge/MCP-tool_catalog-5c4ee5?style=flat-square)](docs/mcp-tools.md)
[![Authorized use only](https://img.shields.io/badge/scope-authorized_targets_only-d13438?style=flat-square)](DISCLAIMER.md)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](LICENSE)

**[Quick start](#quick-start) · [The arsenal](#the-arsenal) · [When you reach for it](#when-you-reach-for-it) · [How it works](#how-break-anything-works) · [Showcases](#showcases) · [FAQ](#faq)**

<code>npx break-anything setup</code>

</div>

> [!IMPORTANT]
> Break Anything finds weaknesses in software **you own or are explicitly authorized to test**.
> It is a defensive, white-box tool: every finding ships with evidence and a fix, and every
> proof-of-concept runs against your own target. It is not an attack framework and must never be
> pointed at third-party systems.

> [!WARNING]
> Get Break Anything only from the official sources in this README and the `break-anything` npm
> package. A copied README or a look-alike repository name does not make a download official.

<div align="center">

<!-- Record with: asciinema rec hero.cast -c "bash demos/hero-demo.sh" && agg hero.cast docs/assets/hero.gif -->
<img src="docs/assets/hero.gif" alt="Break Anything finding reachable CVEs and a secret buried in git history" width="900" />

</div>

---

A critical CVE drops at 2am. Is your service exposed? Which of your forty dependencies actually
*reaches* the vulnerable code — and which are just noise? Is there a live API key sitting in your
git history from a commit you reverted last spring? Does the Terraform you're about to `apply`
open a bucket to the whole internet?

Answering those questions used to mean installing ten scanners, learning ten CLIs, and drowning
in ten thousand findings. **Break Anything gives your coding agent one interface to all of it.**
Ask in plain language; it runs the right industry-standard tools, correlates the results, and
tells you *where* you're exposed, *whether it's actually reachable*, and *how to fix it* — with a
proof-of-concept built against your own build, not a scary paragraph from a CVE database.

Most scanners stop at "here's a CVE, bump the version." Break Anything goes two steps further:

- **Reachability, not presence.** It separates *confirmed exploitable* from *reachable* from
  *present but dead code*, so you fix the three things that matter instead of triaging four
  hundred that don't.
- **Self-remediation when upstream is gone.** When there's no patched version — the maintainer
  vanished, the repo is archived — it proposes a patch, a pin, a shim, or a maintained fork, so
  an abandoned dependency doesn't become your breach.

Everything runs locally. Every result carries its evidence, an exploitability signal, and its own
limitations. Nothing is pointed anywhere you don't own.

## Why Break Anything

| | |
| --- | --- |
| 🧠 **Built for agents** | Describe the worry in a sentence. Your agent picks the tools, runs them, and reasons over the output — no scanner CLIs to memorize. |
| 🎯 **Signal over noise** | Findings ranked by reachability + EPSS + CISA KEV. The critical, reachable, actively-exploited ones rise to the top. |
| 🔬 **Proof, not prose** | A reproducible PoC against *your* build turns "theoretically vulnerable" into "here's the exact request that breaks it." |
| 🛠️ **Real tools, one interface** | Orchestrates the scanners security teams already trust — OSV, Trivy, Semgrep, CodeQL, ZAP, Nuclei, gitleaks, Checkov, Slither — behind one MCP. |
| 🔒 **Local and defensive** | Analysis stays on your machine. Dynamic scanning is off by default and refuses any target not on your allowlist. |
| 🔁 **Find → fix loop** | Hands any finding to [Patch Anything](#companion-patch-anything) for a merge-ready fix, or fixes inline in the same session. |

## Quick start

### Set up your agent

```bash
npx break-anything setup
```

Pick your agents, review the proposed changes, approve. Setup registers the MCP server and its
workflow instructions, backs up existing config, and is safe to re-run. Supports Claude Code,
Codex, Cursor, Gemini CLI, Windsurf, and any client that runs a local MCP server.

### Ask your agent

```text
Use Break Anything on this project. Find vulnerabilities that are actually
reachable in my code, prove the worst one against my local build, and give me a
prioritized fix plan.
```

Point it at a repo, a lockfile, a running localhost app, a container image, or a Terraform dir.

### Or use the terminal

```bash
npx -y break-anything deps ./              # dependency CVEs, ranked by reachability + EPSS
npx -y break-anything secrets ./ --history # leaked keys in the tree and full git history
npx -y break-anything image my-svc:latest  # OS + app CVEs in a container image
```

> **Shipped today:** `deps`, `secrets`, `image`, and their MCP tools. The rest of
> [the arsenal](#the-arsenal) is on the roadmap and lands incrementally — each engine wired in
> only once it returns the same evidence-backed findings.

Install the `brk` command for regular use (`brk`, not `break`, which is a shell keyword):

```bash
npm install --global break-anything && brk --help
```

## How Break Anything works

Your agent calls Break Anything over MCP to inspect a target you control. It routes to the right
engine, correlates findings, confirms reachability, and returns each result with its evidence and
a fix. The CLI uses the same workflows.

![Break Anything flow: your agent points at an authorized target; Break Anything routes to the right engine, confirms reachability, and returns findings with evidence and a fix plan.](docs/assets/break-flow.svg)

| Stage | What happens |
| --- | --- |
| **Find** | Enumerate weaknesses across dependencies, source, secrets, images, IaC, and running apps. |
| **Prove** | Confirm the finding is reachable in your usage and build a proof-of-concept against *your* target. |
| **Fix** | Produce a patch, pin, shim, or mitigation — inline, or handed to Patch Anything. |

Every finding is tagged `confirmed` · `reachable` · `present` · `not-reachable`. Absence of a
finding is never reported as proof of safety.

## What you point it at

You don't pick a mode. Hand Break Anything whatever you have — it detects the form and routes to
the right engine.

| You give it | Form | Categories |
| --- | --- | --- |
| A repo or source tree | source / tech stack | SCA, SAST, Secrets |
| A lockfile (`package-lock.json`, `composer.lock`, `go.mod`…) | manifest | SCA |
| A container image | build artifact | Containers |
| An APK / IPA or compiled binary | build artifact | Mobile, Fuzzing |
| A Terraform / Kubernetes / Dockerfile | config | IaC |
| A running URL or API (yours) | live system | DAST, API |
| Cloud credentials (yours) | live account | Cloud posture |
| Git history | repo metadata | Secrets |

Unlike a binary-only inspector, Break Anything spans source, build artifacts, config, and live
systems. Point it; it figures out the rest.

## The arsenal

Break Anything is organized by **scan category** — the language security teams actually speak —
and each category orchestrates the tools practitioners already trust. Nothing here is a toy:
these are the engines that run in real CI pipelines and real pentests.

Legend: ✅ shipped in 0.1.0 · 🧭 on the roadmap

### ✅ Supply chain & dependencies (SCA)

Find known-vulnerable packages across your whole dependency tree, ranked by whether you actually
call them.

- **Engines:** [OSV](https://osv.dev) / osv-scanner, [Trivy](https://github.com/aquasecurity/trivy), [Grype](https://github.com/anchore/grype), `pip-audit`, `govulncheck`, `cargo-audit`, `bundler-audit`, `composer audit`, [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)
- **Ecosystems:** npm, PyPI, Composer (PHP), Go, Maven/Gradle, Cargo, RubyGems, NuGet
- **Intel overlay:** [EPSS](https://www.first.org/epss/) exploit probability · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) known-exploited · GitHub Advisory
- **SBOM:** [Syft](https://github.com/anchore/syft) / CycloneDX generation and diffing

### ✅ Secrets

Catch leaked credentials in your code and the commits you thought you'd buried.

- **Engines:** [Gitleaks](https://github.com/gitleaks/gitleaks), [TruffleHog](https://github.com/trufflesecurity/trufflehog), [detect-secrets](https://github.com/Yelp/detect-secrets)
- **Scope:** working tree + full git history · provider patterns (AWS, GCP, Stripe, GitHub, Slack, OpenAI…) · optional live-key validation · redacted output

### ✅ Containers & images

Scan what you actually ship, layer by layer.

- **Engines:** [Trivy](https://github.com/aquasecurity/trivy), [Grype](https://github.com/anchore/grype), [Dockle](https://github.com/goodwithtech/dockle), [Hadolint](https://github.com/hadolint/hadolint)
- **Finds:** OS + app-layer CVEs · Dockerfile anti-patterns · secrets baked into layers · CIS image benchmarks

### 🧭 Static code analysis (SAST)

Find the bug class in your source before it ships, with the data-flow that proves it.

- **Multi-language:** [Semgrep](https://semgrep.dev), [CodeQL](https://codeql.github.com)
- **Per-language:** Bandit (Python), gosec (Go), Brakeman (Rails), Find-Sec-Bugs/SpotBugs (Java), Psalm/PHPStan taint (PHP), njsscan/ESLint-security (JS/TS), cppcheck/clang-analyzer (C/C++)
- **Finds:** SQL/command/template injection, XSS, broken access control, insecure deserialization, path traversal, SSRF, weak crypto, unsafe regex (ReDoS)

### 🧭 Infrastructure as Code (IaC)

Catch the misconfiguration before `apply`, not after the breach.

- **Engines:** [Checkov](https://www.checkov.io), [tfsec](https://github.com/aquasecurity/tfsec), [Terrascan](https://github.com/tenable/terrascan), [KICS](https://kics.io), kube-score, kubesec, kube-bench
- **Targets:** Terraform, CloudFormation, Kubernetes/Helm, Dockerfile, ARM/Bicep
- **Finds:** public storage buckets, open security groups, missing encryption, over-broad IAM, privileged containers

### 🧭 Cloud posture (CSPM)

Audit your own cloud accounts against the benchmarks.

- **Engines:** [Prowler](https://github.com/prowler-cloud/prowler), [ScoutSuite](https://github.com/nccgroup/ScoutSuite)
- **Clouds:** AWS, GCP, Azure · CIS / PCI / SOC2 control mapping

### 🧭 Running web apps (DAST)

Attack your own running app the way an outsider would — with your permission.

- **Engines:** [OWASP ZAP](https://www.zaproxy.org), [Nuclei](https://github.com/projectdiscovery/nuclei), [Nikto](https://github.com/sullo/nikto), [Wapiti](https://github.com/wapiti-scanner/wapiti), [sqlmap](https://sqlmap.org)
- **Finds:** OWASP Top 10, injection, XSS, SSRF, auth/session flaws, missing security headers — each with the request that triggers it

### 🧭 API security

Probe your own APIs for the logic flaws scanners miss.

- **Engines:** [Schemathesis](https://github.com/schemathesis/schemathesis) (OpenAPI property-testing/fuzzing), ZAP API scan, auth-matrix prober
- **Finds:** BOLA/IDOR, broken authentication, mass assignment, excessive data exposure (OWASP API Top 10)

### 🧭 Attack surface & recon

Map what you've exposed to the internet — your own domains and hosts only.

- **Engines:** [Nmap](https://nmap.org), ProjectDiscovery suite ([subfinder](https://github.com/projectdiscovery/subfinder), [httpx](https://github.com/projectdiscovery/httpx), [naabu](https://github.com/projectdiscovery/naabu), dnsx)
- **Finds:** forgotten subdomains, exposed services, open ports, tech fingerprint, stale endpoints

### 🧭 Smart contracts (Web3)

- **Engines:** [Slither](https://github.com/crytic/slither), [Mythril](https://github.com/Consensys/mythril), [Echidna](https://github.com/crytic/echidna) (fuzzing)
- **Finds:** reentrancy, integer overflow, access-control gaps, oracle manipulation

### 🧭 Mobile

- **Engines:** [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF), APKiD, Semgrep mobile rules
- **Targets:** Android APK, iOS IPA · **Finds:** insecure storage, hardcoded secrets, weak crypto, exported components

### 🧭 Fuzzing

- **Engines:** [AFL++](https://github.com/AFLplusplus/AFLplusplus), libFuzzer, Atheris (Python), Jazzer (Java), cargo-fuzz
- **Finds:** crashes, memory-safety bugs, and panics — each with a minimized reproducer

The exhaustive, per-tool catalog with MCP contracts lives in [docs/mcp-tools.md](docs/mcp-tools.md).
Every dynamic (traffic-sending) category is **off by default** and refuses any target not on your
authorization allowlist.

## When you reach for it

| The moment | Category | What Break Anything does |
| --- | --- | --- |
| "A CVE is trending — are we hit?" | SCA | Maps your tree, flags only the reachable ones, gives fix versions |
| "Did anyone commit a key?" | Secrets | Scans the tree + full history, redacts, finds the introducing commit |
| "Is our image shipping known holes?" | Containers | OS + app CVEs, Dockerfile smells, baked-in secrets |
| "This Terraform looks risky." | IaC | Flags public buckets / open ports / broad IAM before `apply` |
| "Can user A read user B's data?" | API / DAST | Proves (or disproves) the IDOR with two accounts and a request |
| "Our dependency is abandoned and unpatched." | SCA + self-fix | Proposes a patch, pin, shim, or a maintained fork |
| "We're about to launch — one pass over everything." | All | One prompt, correlated findings, one prioritized fix plan |

## Showcases

Ten worked demos — **all on targets you own, open-source projects, or deliberately vulnerable
labs**. Full scripts in [`demos/`](demos/).

1. **OWASP Juice Shop** — find an IDOR in the authorized lab, prove it with a request, explain the fix.
2. **The dependency you forgot** — an old `lodash` in your lockfile: find it, confirm it's actually called, get the fix version.
3. **PHP supply chain after php2shell** — map a PHP project's whole `composer` chain so the next zero-day doesn't catch you blind.
4. **Log4Shell reachability** — a Java service with a vulnerable `log4j`: confirm it's reachable through your logging path, not just present.
5. **Leaked key in history** — an AWS key committed three months ago: find it, show the blast radius, say "rotate, don't just delete."
6. **Vulnerable base image** — a `Dockerfile` on an outdated base: list CVEs and the minimal bump.
7. **Public bucket** — a Terraform file that exposes an S3 bucket: catch it before `apply`.
8. **Your own Express API** — an IDOR on `/orders/:id`: prove it against localhost with two accounts.
9. **Reentrancy** — a Solidity contract in a lab: trace the external call before the state update.
10. **Find → Fix handoff** — pass any finding to [Patch Anything](#companion-patch-anything) and watch the fix PR get drafted.

## Companion: Patch Anything

Break Anything and [Patch Anything](https://github.com/EnkiHQ/patch-anything) are a pair:

> **Break Anything** finds it and proves it → **Patch Anything** fixes it.

Hand any finding to Patch Anything and it drafts a patch, a dependency bump, a compatibility
shim, or — when upstream is dead — a maintained fork or local mitigation. Discovery and repair,
one loop. Use either alone, or run it end to end.

## FAQ

<details>
<summary><strong>Is this an attack tool? Will it get my repo taken down?</strong></summary>

No. It's a defensive, white-box tool for software you own or are authorized to test. Every PoC
runs against your own target; it ships no weaponized exploits for third-party systems. See
[DISCLAIMER.md](DISCLAIMER.md). GitHub policy explicitly supports dual-use security research.

</details>

<details>
<summary><strong>How is this different from `npm audit` / Trivy / Snyk?</strong></summary>

Those report presence. Break Anything adds **reachability** (is the vulnerable code actually
called), **proof** (a PoC against your own build), and **self-remediation** when upstream has no
fix — and it unifies dependency, code, secret, image, IaC, and runtime findings behind one agent
interface instead of ten CLIs.

</details>

<details>
<summary><strong>Does it replace those tools?</strong></summary>

No — it orchestrates them. Break Anything is the brain and the interface; OSV, Trivy, Semgrep,
ZAP and friends are the engines. You get their depth without learning each one.

</details>

<details>
<summary><strong>Which agents can use it?</strong></summary>

Any agent that supports local MCP servers. Setup configures the common ones automatically.

</details>

<details>
<summary><strong>Does it upload my code?</strong></summary>

Analysis runs locally. Your agent receives the results; its model provider has its own data
policy — review that separately.

</details>

<details>
<summary><strong>Can it test a site I don't own?</strong></summary>

No. Dynamic capabilities require an explicit authorization flag and are for your own or
contractually authorized targets. Unauthorized testing is illegal and unsupported.

</details>

## Documentation

- [Installation and setup](docs/installation.md)
- [The full tool catalog & MCP contracts](docs/mcp-tools.md)
- [Roadmap](docs/roadmap.md)
- [Security model](SECURITY.md) · [Responsible use](DISCLAIMER.md)

## Disclaimer

Break Anything is for lawful security research, education, and testing of software you own or are
authorized to examine. See [DISCLAIMER.md](DISCLAIMER.md). You are responsible for complying with
all applicable laws and with the license terms of every tool it orchestrates.

## License

[MIT](LICENSE). Break-authored code is MIT; the third-party engines it orchestrates retain their
own licenses — see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
