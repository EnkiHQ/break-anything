<div align="center">

**English** · [简体中文](docs/readme/README_zh.md)

# Break Anything

### You think your service is secure. You've never seen it the way an attacker would.

Break Anything points your coding agent at your own code, apps, and infrastructure and hunts them
**like an attacker** — surfacing what's genuinely exploitable, proving it on your own build, and
fixing it. Before someone else finds it first.

*See your own service through an attacker's eyes.*

[![npm version](https://img.shields.io/badge/npm-break--anything-cb3837?style=flat-square)](https://www.npmjs.com/package/break-anything)
[![MCP tool catalog](https://img.shields.io/badge/MCP-tool_catalog-5c4ee5?style=flat-square)](docs/mcp-tools.md)
[![Authorized use only](https://img.shields.io/badge/scope-authorized_targets_only-d13438?style=flat-square)](DISCLAIMER.md)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](LICENSE)

**[Quick start](#quick-start) · [Why it's different](#why-its-different) · [See it in 30s](#see-it-in-30-seconds) · [The arsenal](#the-arsenal) · [FAQ](#faq)**

<code>npx break-anything setup</code>

</div>

> [!IMPORTANT]
> Break Anything tests software **you own or are explicitly authorized to test**. Every
> proof-of-concept runs against your own target. It's a defensive tool, not an attack framework,
> and must never be pointed at third-party systems.

<div align="center">

<!-- Record with: vhs demos/hero.tape -->
<img src="docs/assets/hero.gif" alt="Break Anything: which vulnerabilities actually reach your code, plus a secret hiding in git history" width="900" />

</div>

---

"It's probably fine." It shipped, it works, nobody has complained — so you assume it's secure. But
"no breach yet" was never a security test. The only honest one is to look at your own service the
way an attacker will: which dependency is an open door, what key is still in your git history,
which endpoint hands over another user's data.

And you're never done. A critical unauthenticated RCE turned up in PHP itself in October 2026 after
years in plain sight (php2shell) — if the language behind much of the web still has critical holes,
so does your app. Every dependency you add widens the surface, and you can't close them all. So fix
the few an attacker can reach *today*.

And the economics just flipped: the same AI agents that write code now hunt vulnerabilities at
scale — and attackers have them too. Find your holes first, with the same leverage.

**Break Anything gives your coding agent that attacker's-eye view** — in one sentence, on software
you own: what's genuinely exploitable, proven on *your* build, with the fix. Everything runs
locally. Nothing is pointed anywhere you don't own.

## Quick start

```bash
npx break-anything setup
```

One command. It auto-detects Claude Desktop, Claude Code, Cursor, Codex, Gemini CLI and Windsurf
on your machine and registers Break Anything into each — backing up every file it touches,
preserving your other servers, safe to re-run. Restart your agent, then just ask:

```text
Use Break Anything on this project. Show me only the vulnerabilities that are
actually reachable in my code, prove the worst one, and give me the fix.
```

Prefer the terminal? One command, shipped today:

```bash
npx -y break-anything deps ./              # dependency CVEs, ranked by reachability + EPSS
npx -y break-anything secrets ./ --history # leaked keys in the tree and full git history
npx -y break-anything image my-svc:latest  # OS + app CVEs in a container image
npx -y break-anything sast ./src           # static code analysis (injection, authz, SSRF…)
npx -y break-anything iac ./deploy         # IaC misconfigs (Dockerfile/K8s/Terraform) — no install
npx -y break-anything api http://localhost:4000 --config accounts.json  # IDOR/authz on a running API (authorized)
npx -y break-anything fix ./             # turn the dep findings into a prioritized upgrade plan
```

## Why it's different

Every scanner can hand you a list. The list is the problem. Break Anything is built around the
three things a list can't do:

- **Reachability — it thinks like an attacker.** An attacker doesn't work through 400 theoretical
  CVEs; they go straight for the few they can actually reach. Break Anything ranks the same way:
  `called` → `imported` → `direct` → `transitive`. It doesn't just check that a vulnerable package
  is present — it extracts the symbols you imported from it and checks whether your code actually
  **calls** them. The `lodash` you never invoke is noise; the one you call is the finding. You
  triage 3, not 400.
- **Proof, not prose.** Instead of a CVSS paragraph, it builds a proof-of-concept against *your*
  build — the exact input or request that breaks it — so "theoretically vulnerable" becomes
  "here's the repro."
- **A fix, even when upstream is gone.** No patched version because the maintainer vanished? It
  proposes a patch, a pin, a compatibility shim, or a maintained fork — so an abandoned dependency
  doesn't become your breach. Hand it to [Patch Anything](#companion-patch-anything) for a
  merge-ready PR.

It doesn't replace OSV, Trivy, Semgrep or ZAP — it **orchestrates** them behind one agent
interface and does the reasoning they can't.

## See it in 30 seconds

Three things you'll reach for it, each one sentence to your agent:

| The moment | Ask | What you get back |
| --- | --- | --- |
| **"A CVE is trending — are we hit?"** | *"Scan my deps, only flag what's reachable."* | 3 reachable CVEs with fix versions — not a 400-line wall |
| **"Did someone commit a key?"** | *"Scan the repo and git history for secrets."* | The leaked key, the commit that introduced it, "rotate don't delete" |
| **"Can user A read user B's data?"** | *"Check /orders/:id for broken access control."* | The IDOR, proven against localhost with two accounts |

## What you point it at

You don't pick a mode. Hand it whatever you have — it detects the form and routes to the right
engine.

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

## The arsenal

Organized by scan category — the language security teams speak — each orchestrating tools that
already run in real pipelines. ✅ shipped in 0.7.0 · 🧭 on the roadmap.

### ✅ Shipped today

- **Dependencies (SCA)** — known CVEs across your whole tree, ranked by reachability + [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (known-exploited) + EPSS, with fix versions. Engines: [OSV](https://osv.dev), [Trivy](https://github.com/aquasecurity/trivy), [Grype](https://github.com/anchore/grype), `pip-audit`, `govulncheck`, `composer audit`. Ecosystems shipped: npm, PyPI, Composer, Go, Cargo (crates.io), RubyGems; Maven/NuGet on the roadmap.
- **Secrets** — leaked keys/tokens/private keys in the working tree and full git history, redacted. Engines: [Gitleaks](https://github.com/gitleaks/gitleaks), [TruffleHog](https://github.com/trufflesecurity/trufflehog).
- **Container images** — OS + app CVEs, Dockerfile smells, secrets in layers. Engines: [Trivy](https://github.com/aquasecurity/trivy), [Grype](https://github.com/anchore/grype), [Hadolint](https://github.com/hadolint/hadolint).
- **Static code (SAST)** — injection, broken access control, insecure deserialization, SSRF, hardcoded secrets — each with file/line, CWE/OWASP tags, and the offending snippet. Engine: [Semgrep](https://semgrep.dev).
- **Infrastructure as Code (IaC)** — Dockerfile, Kubernetes, and Terraform misconfigurations (root containers, privileged pods, world-open CIDRs, public buckets, baked-in secrets), each with file/line, CWE, and a fix. Built in — no engine to install.
- **API security (DAST)** — probe a *running* API for broken object-level authorization (IDOR/BOLA), missing auth, and missing security headers, each proven with the reproducing request. Built-in; off by default, authorized targets only.
- **Fix planning** — turns the findings into a prioritized upgrade plan: the minimal safe version that clears the most CVEs per package, ordered by reachability then severity, with the exact `npm`/`pip`/`composer` command. No-fix packages get mitigation guidance.

### 🧭 On the roadmap

- **More SAST engines** — [CodeQL](https://codeql.github.com), SonarQube CE, Bandit (Python), gosec (Go), Brakeman (Rails), Find-Sec-Bugs (Java), security-code-scan (.NET), retire.js (frontend JS).
- **Deeper IaC & cloud** — opt-in [Checkov](https://www.checkov.io) / tfsec / [KICS](https://kics.io) / [Kubescape](https://github.com/kubescape/kubescape) backends, plus CloudFormation, ARM/Bicep, Ansible and full CIS benchmarks on top of the built-in rules.
- **More DAST & attack surface** — OWASP Top 10, content/parameter discovery, XSS, injection against your authorized app, on top of today's authorization prober. [OWASP ZAP](https://www.zaproxy.org), [Nuclei](https://github.com/projectdiscovery/nuclei), [Nikto](https://github.com/sullo/nikto), [ffuf](https://github.com/ffuf/ffuf), [Katana](https://github.com/projectdiscovery/katana), [Dalfox](https://github.com/hahwul/dalfox), [sqlmap](https://sqlmap.org); surface mapping via [Nmap](https://nmap.org) + [Amass](https://github.com/owasp-amass/amass) + ProjectDiscovery.
- **More API checks** — mass assignment, excessive data exposure, OpenAPI-driven fuzzing (OWASP API Top 10). [Schemathesis](https://github.com/schemathesis/schemathesis), ZAP.
- **Offensive / exploitation** — *authorized pentest only; gated, off by default, written permission required.* Prove exploitability on targets you own. [Metasploit](https://www.metasploit.com), sqlmap, [Hydra](https://github.com/vanhauser-thc/thc-hydra), [Hashcat](https://hashcat.net), [BloodHound](https://github.com/SpecterOps/BloodHound) + Impacket (Active Directory), [OpenVAS](https://www.openvas.org).
- **AI / LLM security** — prompt injection, jailbreaks, data leakage in your own models and agents. [Garak](https://github.com/NVIDIA/garak).
- **Binary & artifact analysis** — known-vulnerable deps and unsafe patterns in compiled binaries. [Ghidra](https://ghidra-sre.org), [radare2](https://github.com/radareorg/radare2), [angr](https://github.com/angr/angr) (pairs with REA).
- **Cloud posture · Smart contracts · Mobile · Fuzzing** — [Prowler](https://github.com/prowler-cloud/prowler) · [Slither](https://github.com/crytic/slither), Mythril, Echidna · [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) · [AFL++](https://github.com/AFLplusplus/AFLplusplus), libFuzzer, Jazzer.

Full per-tool catalog and MCP contracts: [docs/mcp-tools.md](docs/mcp-tools.md). Every dynamic
(traffic-sending) category is **off by default** and refuses any target not on your allowlist.

## How it works

Your agent calls Break Anything over MCP to inspect a target you control. It routes to the right
engine, confirms reachability, and returns each finding with its evidence and a fix. The CLI uses
the same workflows.

![Find, prove, fix flow](docs/assets/break-flow.svg)

**Find** weaknesses across deps, code, secrets, images, IaC, and running apps → **Prove** the
finding is reachable with a PoC against your target → **Fix** it inline or via Patch Anything.
Absence of a finding is never reported as proof of safety.

## Companion: Patch Anything

> **Break Anything** finds it and proves it → **[Patch Anything](https://github.com/EnkiHQ/patch-anything)** fixes it.

Hand any finding over and it drafts the patch, bump, shim, or fork. Discovery and repair, one
loop. Use either alone, or run it end to end.

## FAQ

<details>
<summary><strong>How is this different from `npm audit` / Trivy / Snyk?</strong></summary>

They report presence — every vulnerability that exists anywhere in your tree. Break Anything adds
**reachability** (is it actually called), **proof** (a PoC against your own build), and
**self-remediation** when upstream has no fix, and unifies deps, code, secrets, images, IaC, and
runtime behind one agent interface.

</details>

<details>
<summary><strong>Does it replace those tools?</strong></summary>

No — it orchestrates them. Break Anything is the brain and the interface; OSV, Trivy, Semgrep, ZAP
are the engines. You get their depth without learning each one.

</details>

<details>
<summary><strong>Is this an attack tool? Will my repo get taken down?</strong></summary>

No. It's defensive and authorized-targets-only; every PoC runs against your own target and it
ships no weaponized exploits. See [DISCLAIMER.md](DISCLAIMER.md). GitHub policy explicitly supports
dual-use security research.

</details>

<details>
<summary><strong>Does it upload my code?</strong></summary>

Analysis runs locally. Your agent receives the results; its model provider has its own data
policy — review that separately.

</details>

<details>
<summary><strong>Which agents can use it?</strong></summary>

Any agent that supports local MCP servers. Setup configures the common ones automatically.

</details>

## Documentation

[Installation](docs/installation.md) · [Tool catalog & MCP contracts](docs/mcp-tools.md) ·
[Roadmap](docs/roadmap.md) · [Security model](SECURITY.md) · [Responsible use](DISCLAIMER.md)

## License

[MIT](LICENSE). Break-authored code is MIT; the engines it orchestrates keep their own licenses —
see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
