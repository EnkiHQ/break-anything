<div align="center">

**English** · [简体中文](docs/readme/README_zh.md)

# Break Anything

### You think your service is secure. You've never looked at it the way an attacker would.

Break Anything points your coding agent — or your terminal — at your own code, apps, and
infrastructure and hunts them **like an attacker**: it surfaces what's genuinely exploitable, proves
it on your own build, and fixes it. Before someone else finds it first.

[![npm version](https://img.shields.io/npm/v/break-anything?color=cb3837&logo=npm)](https://www.npmjs.com/package/break-anything)
[![npm downloads](https://img.shields.io/npm/dm/break-anything?color=cb3837)](https://www.npmjs.com/package/break-anything)
[![CI](https://img.shields.io/github/actions/workflow/status/EnkiHQ/break-anything/ci.yml?branch=main&label=CI&logo=github)](https://github.com/EnkiHQ/break-anything/actions)
[![node](https://img.shields.io/node/v/break-anything)](https://nodejs.org)
[![MCP tool catalog](https://img.shields.io/badge/MCP-9_tools-5c4ee5)](docs/mcp-tools.md)
[![authorized use only](https://img.shields.io/badge/scope-authorized_targets_only-d13438)](DISCLAIMER.md)
[![license](https://img.shields.io/npm/l/break-anything?color=f4c430)](LICENSE)

**[Quick start](#quick-start) · [Example output](#example-output) · [Why it's different](#why-its-different) · [CI/CD](#cicd-in-one-line) · [The arsenal](#the-arsenal) · [FAQ](#faq)**

```bash
npx break-anything ci .          # one command: deps + secrets + IaC + SAST, one exit code
```

</div>

> [!IMPORTANT]
> Break Anything tests software **you own or are explicitly authorized to test**. Every
> proof-of-concept runs against your own target. It's a defensive tool, not an attack framework, and
> must never be pointed at third-party systems. See [DISCLAIMER.md](DISCLAIMER.md).

<div align="center">

<!-- Record with: vhs demos/hero.tape -->
<img src="docs/assets/hero.gif" alt="Break Anything: which vulnerabilities actually reach your code, plus a secret hiding in git history" width="900" />

</div>

---

"It's probably fine." It shipped, it works, nobody has complained — so you assume it's secure. But
"no breach yet" was never a security test. The only honest one is to look at your own service the way
an attacker will: which dependency is an open door, what key is still in your git history, which
endpoint hands over another user's data.

And you're never done. A critical unauthenticated RCE turned up in PHP itself in October 2026 after
years in plain sight — if the language behind much of the web still ships critical holes, so does
your app. Every dependency you add widens the surface, and you can't close them all. So fix the few
an attacker can reach *today*.

The economics just flipped, too: the same AI agents that write code now hunt vulnerabilities at
scale — and attackers have them. Find your holes first, with the same leverage.

**Break Anything gives your agent that attacker's-eye view** — in one sentence, on software you own:
what's genuinely exploitable, proven on *your* build, with the fix. Everything runs locally. Nothing
is pointed anywhere you don't own.

## Quick start

**As an agent tool (MCP).** One command registers Break Anything into every AI coding agent on your
machine:

```bash
npx break-anything setup
```

It auto-detects Claude Desktop, Claude Code, Cursor, Codex, Gemini CLI and Windsurf — backs up every
file it touches, preserves your other servers, and is safe to re-run. Restart your agent, then ask:

```text
Use Break Anything on this project. Show me only the vulnerabilities that are
actually reachable in my code, prove the worst one, and give me the fix.
```

**From the terminal.** No install, nothing to configure:

```bash
npx -y break-anything ci .                 # whole-repo gate: deps + secrets + IaC + SAST, one exit code
npx -y break-anything deps .               # dependency CVEs, ranked by reachability + KEV + EPSS
npx -y break-anything secrets . --history  # leaked keys in the tree and full git history
npx -y break-anything iac ./deploy         # Dockerfile/K8s/Terraform misconfigs — no engine to install
npx -y break-anything sast ./src           # static analysis (needs Semgrep): injection, authz, SSRF…
npx -y break-anything image my-svc:latest  # OS + app CVEs in a container image (needs Trivy)
npx -y break-anything api http://localhost:4000 --config accounts.json  # IDOR/authz on a running API (authorized)
npx -y break-anything fix .                # turn findings into a prioritized upgrade plan
npx -y break-anything sbom . --out bom.json  # CycloneDX SBOM (--diff old.json to gate drift)
```

Requires Node.js ≥ 18.17. `deps`/`secrets`/`iac`/`fix`/`sbom` are fully built in; `sast` and `image`
wrap Semgrep/Trivy and degrade gracefully if those aren't installed.

## Example output

`brk ci` — the whole repo, one gate, one exit code:

```text
Break Anything · CI security gate
./my-service

  ● deps        9 findings
  ● secrets     1 findings
  ● iac         3 findings
  • sast        skipped (Semgrep not installed)

total 13 findings  ·  CRITICAL 2  HIGH 7  MEDIUM 4

✗ GATE FAILED (fail-on HIGH)
  - 4 reachable HIGH+ dependency vulns
  - 1 known-exploited (KEV) dependency vuln
  - 1 leaked secret
  - 1 HIGH+ IaC issue
```

`brk deps` — ranked by what an attacker can actually reach, with the actively-exploited one flagged:

```text
Break Anything · dependency scan
target ./my-service  ·  2 packages scanned  ·  npm:2

HIGH     systeminformation@5.3.0 (npm) [KEV]
  CVE-2021-21315  ·  called  ·  EPSS 90.7%  ·  fix → 5.3.1
  Command Injection Vulnerability
CRITICAL lodash@4.17.4 (npm)
  CVE-2019-10744  ·  called  ·  EPSS 5.0%  ·  fix → 4.17.12
  Prototype Pollution in lodash

summary 12 findings  ·  12 reachable (10 called)  ·  1 KEV  ·  CRITICAL 2  HIGH 8  MEDIUM 2
KEV = CISA Known Exploited: attackers are using this in the wild right now. Fix these first.
```

`brk fix` — the minimal upgrade that clears the most CVEs, ordered by reachability:

```text
Break Anything · fix plan
./my-service  ·  2 packages to upgrade  ·  resolves 12 vulnerabilities

1. [called · CRITICAL] [KEV] systeminformation 5.3.0 → 5.31.7  resolves 9 CVEs
   npm install systeminformation@5.31.7
2. [called · CRITICAL] lodash 4.17.4 → 4.18.0  resolves 3 CVEs
   npm install lodash@4.18.0
```

## Why it's different

Every scanner can hand you a list. The list *is* the problem. Break Anything is built around the
three things a list can't do:

- **Reachability — it thinks like an attacker.** An attacker doesn't work through 400 theoretical
  CVEs; they go straight for the few they can actually reach. Break Anything ranks the same way:
  `called` → `imported` → `direct` → `transitive`. It doesn't just check that a vulnerable package is
  present — it extracts the symbols you imported from it and checks whether your code actually
  **calls** them. The `lodash` you never invoke is noise; the one you call is the finding. You triage
  3, not 400.
- **Proof, not prose.** Instead of a CVSS paragraph, it builds a proof-of-concept against *your*
  build — the exact input or request that breaks it — so "theoretically vulnerable" becomes "here's
  the repro." The API prober returns the literal request that read another account's data.
- **A fix, even when upstream is gone.** No patched version because the maintainer vanished? It
  proposes a patch, a pin, a compatibility shim, or a maintained fork — so an abandoned dependency
  doesn't become your breach. Hand it to [Patch Anything](#companion-patch-anything) for a
  merge-ready PR.

It doesn't replace OSV, Trivy, Semgrep or ZAP — it **orchestrates** them behind one interface (CLI or
MCP) and does the reasoning they can't.

### How it compares

| | `npm audit` | Trivy / Grype | Snyk | **Break Anything** |
| --- | :---: | :---: | :---: | :---: |
| Lists known CVEs | ✅ | ✅ | ✅ | ✅ |
| Reachability (is it actually called) | ✗ | ✗ | partial | ✅ `called` vs `imported` |
| Known-exploited (CISA KEV) + EPSS ranking | ✗ | partial | ✅ | ✅ |
| Proof-of-concept against *your* build | ✗ | ✗ | ✗ | ✅ (API/DAST) |
| Fix plan when upstream has no patch | ✗ | ✗ | partial | ✅ |
| Deps + secrets + IaC + SAST + runtime, unified | ✗ | partial | ✅ | ✅ one gate |
| Runs locally, no account | ✅ | ✅ | ✗ | ✅ |
| Agent-native (MCP) | ✗ | ✗ | ✗ | ✅ 9 tools |

## See it in 30 seconds

Three moments you'll reach for it, each one sentence to your agent:

| The moment | Ask | What you get back |
| --- | --- | --- |
| **"A CVE is trending — are we hit?"** | *"Scan my deps, only flag what's reachable."* | 3 reachable CVEs with fix versions — not a 400-line wall |
| **"Did someone commit a key?"** | *"Scan the repo and git history for secrets."* | The leaked key, the commit that introduced it, "rotate don't delete" |
| **"Can user A read user B's data?"** | *"Check /orders/:id for broken access control."* | The IDOR, proven against localhost with two accounts |

## CI/CD in one line

`brk ci` returns a non-zero exit code when the gate trips, so it drops straight into any pipeline.
Add SARIF and the findings show up inline on the exact file/line in GitHub's Security tab:

```yaml
# .github/workflows/security.yml
name: security
on: [push, pull_request]
jobs:
  break-anything:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: "22" }

      - name: Security gate (fails the build on reachable HIGH+ / KEV / secrets)
        run: npx -y break-anything ci . --fail-on=high

      - name: Export SARIF
        if: always()
        run: npx -y break-anything ci . --sarif > results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

Any other CI works too — it's just an exit code. GitLab, CircleCI, Jenkins: run `npx -y
break-anything ci .` and check the status.

**Tune the gate with a policy file.** Drop a `.break-anything.json` in your repo to set the
threshold, skip categories, and baseline the findings you've already accepted — so the gate fails on
what's *new*, not on day-one debt:

```json
{
  "failOn": "high",
  "skip": ["sast"],
  "ignore": [
    "CVE-2019-10744",
    { "id": "docker-no-user", "reason": "base image is hardened" }
  ]
}
```

## Output formats

Every finding-producing command speaks the formats your toolchain already reads:

| Format | Flag | Use it for |
| --- | --- | --- |
| Human | *(default)* | Reading in the terminal; color + severity + reachability |
| JSON | `--json` | Scripting, agents, custom dashboards |
| SARIF 2.1.0 | `--sarif` | GitHub / GitLab code scanning, IDE security panels |
| CycloneDX SBOM | `brk sbom` | Archive, audit, and `--diff` to gate dependency drift |

## What you point it at

You don't pick a mode. Hand it whatever you have — it detects the form and routes to the right
engine.

| You give it | Form | Categories |
| --- | --- | --- |
| A repo or source tree | source / tech stack | SCA, SAST, Secrets, IaC |
| A lockfile (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `go.mod`, `pom.xml`…) | manifest | SCA |
| A container image | build artifact | Containers |
| A Terraform / Kubernetes / Dockerfile | config | IaC |
| A running URL or API (yours) | live system | DAST, API |
| Git history | repo metadata | Secrets |

## The arsenal

Organized by scan category — the language security teams speak — each orchestrating tools that
already run in real pipelines. ✅ shipped · 🧭 on the roadmap.

### ✅ Shipped today

- **Dependencies (SCA)** — known CVEs across your whole tree, ranked by **reachability** + [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (known-exploited) + [EPSS](https://www.first.org/epss/) (exploit probability), with fix versions. Powered by [OSV](https://osv.dev). **8 ecosystems:** npm (package-lock / yarn / pnpm), PyPI, Composer (PHP), Go, Rust (crates.io), Ruby (RubyGems), Maven (Java), NuGet (.NET).
- **Secrets** — leaked keys/tokens/private keys in the working tree and full git history, redacted in output. Built in; recognizes AWS, GCP, GitHub, GitLab, Slack, Stripe, OpenAI, JWTs, private keys and generic assigned secrets.
- **Static code (SAST)** — injection, broken access control, insecure deserialization, SSRF, hardcoded secrets — each with file/line, CWE/OWASP tags, and the offending snippet. Engine: [Semgrep](https://semgrep.dev).
- **Infrastructure as Code (IaC)** — Dockerfile, Kubernetes, and Terraform misconfigurations (root containers, privileged pods, world-open CIDRs, public buckets, baked-in secrets), each with file/line, CWE, and a fix. **Built in — no engine to install.**
- **Container images** — OS + app CVEs, Dockerfile smells, secrets in layers. Engine: [Trivy](https://github.com/aquasecurity/trivy).
- **API security (DAST)** — probe a *running* API for broken object-level authorization (IDOR/BOLA), missing auth, and missing security headers, each **proven with the reproducing request**. Built in; off by default, authorized targets only.
- **Fix planning** — the minimal safe upgrade that clears the most CVEs per package, ordered by reachability then severity, with the exact `npm`/`pip`/`composer` command. No-fix packages get mitigation guidance.
- **Standards output** — CycloneDX SBOM generation + diff, and SARIF 2.1.0 for every scanner.
- **One-shot CI gate** — `ci` runs deps + secrets + IaC + SAST in one command, one report, one merged SARIF, one exit code.

### 🧭 On the roadmap

- **More SAST engines** — [CodeQL](https://codeql.github.com), Bandit (Python), gosec (Go), Brakeman (Rails), Find-Sec-Bugs (Java), security-code-scan (.NET), retire.js (frontend).
- **Deeper IaC & cloud** — opt-in [Checkov](https://www.checkov.io) / tfsec / [KICS](https://kics.io) / [Kubescape](https://github.com/kubescape/kubescape) backends; CloudFormation, ARM/Bicep, Ansible; CSPM via [Prowler](https://github.com/prowler-cloud/prowler) / ScoutSuite.
- **More DAST & attack surface** — OWASP Top 10, content/parameter discovery, XSS, injection on top of today's authorization prober. [OWASP ZAP](https://www.zaproxy.org), [Nuclei](https://github.com/projectdiscovery/nuclei), [sqlmap](https://sqlmap.org); surface mapping via [Nmap](https://nmap.org) + ProjectDiscovery.
- **Call-graph reachability** — from "the symbol is called" to "the specific vulnerable function is on a real path."
- **AI/LLM · binary · mobile · fuzzing** — [Garak](https://github.com/NVIDIA/garak) · [Ghidra](https://ghidra-sre.org)/[angr](https://github.com/angr/angr) · [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) · [AFL++](https://github.com/AFLplusplus/AFLplusplus).
- **Offensive / exploitation** — *authorized pentest only; gated, off by default, written permission required.* [Metasploit](https://www.metasploit.com), [Hydra](https://github.com/vanhauser-thc/thc-hydra), [BloodHound](https://github.com/SpecterOps/BloodHound).

Full per-tool catalog and MCP contracts: [docs/mcp-tools.md](docs/mcp-tools.md). Every dynamic
(traffic-sending) category is **off by default** and refuses any target not on your allowlist.

## Data sources

Break Anything trusts open, authoritative sources — not a closed, proprietary database:

- **[OSV.dev](https://osv.dev)** — vulnerabilities across every major open-source ecosystem, each
  advisory from an authoritative upstream (GitHub Advisory, RustSec, Ubuntu, etc.).
- **[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)** — the authoritative
  catalog of vulnerabilities being exploited *in the wild* right now.
- **[EPSS](https://www.first.org/epss/)** (FIRST.org) — the probability a vulnerability will be
  exploited in the next 30 days.

Analysis runs on your machine. Nothing is uploaded except the anonymous package-coordinate queries
needed to look up advisories.

## How it works

Your agent (or the CLI) calls Break Anything to inspect a target you control. It routes to the right
engine, confirms reachability, and returns each finding with its evidence and a fix.

![Find, prove, fix flow](docs/assets/break-flow.svg)

**Find** weaknesses across deps, code, secrets, images, IaC, and running apps → **Prove** the finding
is reachable with a PoC against your target → **Fix** it inline or via Patch Anything. Absence of a
finding is never reported as proof of safety.

## Companion: Patch Anything

> **Break Anything** finds it and proves it → **[Patch Anything](https://github.com/EnkiHQ/patch-anything)** fixes it.

Hand any finding over and it drafts the patch, bump, shim, or fork. Discovery and repair, one loop.
Use either alone, or run them end to end.

## FAQ

<details>
<summary><strong>How is this different from <code>npm audit</code> / Trivy / Snyk?</strong></summary>

They report presence — every vulnerability that exists anywhere in your tree. Break Anything adds
**reachability** (is it actually called), **KEV + EPSS ranking** (is it exploited in the wild / likely
to be), **proof** (a PoC against your own build), and **self-remediation** when upstream has no fix —
and unifies deps, code, secrets, images, IaC, and runtime behind one interface. See the
[comparison table](#how-it-compares).

</details>

<details>
<summary><strong>Does it replace those tools?</strong></summary>

No — it orchestrates them. Break Anything is the brain and the interface; OSV, Trivy, Semgrep, ZAP are
the engines. You get their depth without learning each one.

</details>

<details>
<summary><strong>Can I use it without an AI agent?</strong></summary>

Yes. The `brk` CLI does everything the MCP tools do — `npx -y break-anything ci .` needs no agent, no
account, no config. The MCP server just exposes the same capabilities to agents that support it.

</details>

<details>
<summary><strong>Is this an attack tool? Will my repo get taken down?</strong></summary>

No. It's defensive and authorized-targets-only; every PoC runs against your own target and it ships no
weaponized exploits. See [DISCLAIMER.md](DISCLAIMER.md). GitHub policy explicitly supports dual-use
security research.

</details>

<details>
<summary><strong>Does it upload my code?</strong></summary>

Analysis runs locally. Dependency lookups send only package names + versions to OSV. Your agent
receives the results; its model provider has its own data policy — review that separately.

</details>

<details>
<summary><strong>Which agents can use it?</strong></summary>

Any agent that supports local MCP servers. `npx break-anything setup` configures the common ones
automatically (Claude Desktop, Claude Code, Cursor, Codex, Gemini CLI, Windsurf).

</details>

## Documentation

[Installation](docs/installation.md) · [Tool catalog & MCP contracts](docs/mcp-tools.md) ·
[Roadmap](docs/roadmap.md) · [Changelog](CHANGELOG.md) · [Security model](SECURITY.md) ·
[Responsible use](DISCLAIMER.md) · [Contributing](CONTRIBUTING.md)

## License

[MIT](LICENSE). Break-authored code is MIT; the engines it orchestrates keep their own licenses — see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

<div align="center">
<sub>Built for the age of AI-written code — when finding your own holes first is the only move.</sub>
</div>
