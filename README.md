<div align="center">

**English** · [简体中文](docs/readme/README_zh.md)

# Break Anything

### One MCP for finding vulnerabilities across code, dependencies, apps, and infrastructure.

**Break it before they do. Point your agent at software you own, find the weakness, prove it, fix it.**

[![npm version](https://img.shields.io/badge/npm-break--anything-cb3837?style=flat-square)](https://www.npmjs.com/package/break-anything)
[![MCP tool catalog](https://img.shields.io/badge/MCP-tool_catalog-5c4ee5?style=flat-square)](docs/mcp-tools.md)
[![Authorized use only](https://img.shields.io/badge/scope-authorized_targets_only-d13438?style=flat-square)](DISCLAIMER.md)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](LICENSE)

**[Quick start](#quick-start) · [How it works](#how-break-anything-works) · [What you can test](#what-you-can-test) · [Showcases](#showcases) · [FAQ](#faq) · [Companion: Patch Anything](#companion-patch-anything)**

<code>npx break-anything setup</code>

</div>

> [!IMPORTANT]
> Break Anything finds weaknesses in software **you own or are explicitly authorized to test**.
> It is a defensive, white-box security tool: every finding comes with evidence and a
> remediation path, and every proof-of-concept runs against your own target.
> It is not an attack framework and must not be pointed at third-party systems.

> [!WARNING]
> Get Break Anything only from the official sources listed in this README and in the
> `break-anything` npm package. A similar repository name or a copied README does not
> make a download official.

<div align="center">

<!-- Record with: asciinema rec hero.cast -c "bash demos/hero-demo.sh" && agg hero.cast docs/assets/hero.gif -->
<img src="docs/assets/hero.gif" alt="Break Anything finding reachable CVEs and a secret buried in git history" width="900" />

</div>

---

See a vulnerability land in the news and wonder whether *your* project is exposed? Ask your agent
to check it with Break Anything. It inspects your code, dependencies, running app, and
infrastructure without you learning ten different scanners, explains **where** you are
vulnerable, proves it with a reproducible finding, and hands a fix plan to your agent — or to
[Patch Anything](#companion-patch-anything).

Break Anything connects your coding agent to mature security tooling (Semgrep, CodeQL, OSV,
Trivy, Grype, Nuclei, ZAP, gitleaks, and more) through one consistent interface. You can also
run the same capabilities from your terminal. Analysis runs locally, and every result carries
the evidence, the exploitability signal, and the limitations behind it.

Most scanners stop at "here is a CVE list, bump the version." Break Anything goes further: it
reasons about whether a finding is **actually reachable in your usage**, builds a
proof-of-concept against **your own** target, and — when upstream has no fix — proposes a patch,
a shim, or a mitigation so an abandoned dependency does not become your breach.

## Quick start

### Set up your agent

With Node.js and npm installed, run:

```bash
npx break-anything setup
```

Choose your agents, review the proposed changes, and approve them. Setup registers Break
Anything's MCP server and installs matching workflow instructions, with backups of existing
configuration. Restart your agent afterward.

Setup supports Claude Code, Codex, Cursor, Gemini CLI, Windsurf, and any client that can run a
local MCP server. See [installation](docs/installation.md) for manual registration.

### Ask your agent

```text
Use Break Anything to check my project for vulnerabilities. Prioritise anything
that is actually reachable in my code, prove it against my local build, and give
me a fix plan.
```

Replace the request with your target — a repository, a lockfile, a running localhost app, a
container image, or a Terraform directory.

### Use the terminal

```bash
# Dependencies: known CVEs ranked by reachability + EPSS, with fix versions
npx -y break-anything deps ./

# Secrets: leaked keys in the working tree and (with --history) git history
npx -y break-anything secrets ./ --history

# Container image: OS + app CVEs via Trivy
npx -y break-anything image my-service:latest
```

> Shipped today: `deps`, `secrets`, `image`, and the matching MCP tools. The rest of the
> [tool catalog](docs/mcp-tools.md) is the roadmap, landing incrementally.

To install the `brk` command for regular use:

```bash
npm install --global break-anything
brk --help
```

> The CLI command is `brk` (not `break`, which is a shell keyword).

### Update

```bash
brk update
```

## How Break Anything works

Your agent calls Break Anything through MCP to inspect a target you control. Break Anything
returns each finding with its evidence, an exploitability signal, and a suggested remediation.
The agent uses that to prioritise, reproduce, and fix. CLI commands use the same workflows.

![Break Anything flow: your agent points at an authorized target; Break Anything routes to the right analysis engine, confirms reachability, and returns findings with evidence and a fix plan.](docs/assets/break-flow.svg)

The investigation model:

| Stage | What happens |
| --- | --- |
| **Find** | Enumerate weaknesses across dependencies, source, running app, and infrastructure. |
| **Prove** | Confirm the finding is reachable in your usage and build a proof-of-concept against *your* target. |
| **Fix** | Produce a patch, pin, shim, or mitigation — directly, or by handing off to Patch Anything. |

Break Anything shows how it reached each conclusion. It separates "confirmed exploitable",
"reachable but unproven", and "present but not reachable" instead of drowning you in noise.

## What you can test

Break Anything is organized by **scan category** — the language a security team actually speaks —
not by file type. Each category says what it finds and whether it ships today.

### ✅ Shipped in 0.1.0

| Category | Targets | What you get |
| --- | --- | --- |
| **Supply chain (SCA)** | npm `package-lock.json`, PHP `composer.lock`, Python `requirements.txt` | Known CVEs via OSV, import-based reachability, EPSS exploit probability, fix versions |
| **Secrets** | any repo — working tree + full git history | Leaked keys / tokens / private keys, redacted, with the commit that introduced them |
| **Container images** | any image reference (via Trivy) | OS + application-layer CVEs ranked by severity, with fix versions |

### 🧭 On the roadmap

| Category | Targets | What you'll get | Engine |
| --- | --- | --- | --- |
| **Static code (SAST)** | JS/TS, Python, Go, Java, PHP source | Injection, broken access control, insecure deserialization, path traversal, SSRF — with data-flow evidence | Semgrep / CodeQL |
| **Running apps (DAST)** | your authorized web app / HTTP API | OWASP Top 10, IDOR, auth bypass, mass assignment — with a reproducible request | OWASP ZAP / Nuclei |
| **Infrastructure (IaC)** | Dockerfile, Terraform, Kubernetes, CloudFormation | Misconfigurations before you `apply` | Trivy / checkov |
| **Smart contracts** | Solidity | Reentrancy, integer overflow, access-control gaps | Slither |

See the full plan in the [roadmap](docs/roadmap.md). Every dynamic (traffic-sending) capability
is **disabled by default** and requires both an operator policy and an explicit per-run
authorization flag. Static scanning reads your files without running them.

## Showcases

Ten worked demos — **all on targets you own, open-source projects, or deliberately vulnerable
labs**. See [`demos/`](demos/) for the full scripts.

1. **OWASP Juice Shop** — point at the authorized lab, find an IDOR, prove it with a request, explain the fix.
2. **The dependency you forgot** — an old `lodash`/`minimist` in your lockfile: find it, confirm the vulnerable function is actually called, get the fix version.
3. **PHP supply chain after php2shell** — a PHP project pinned to a vulnerable `composer` dependency: Break Anything maps your whole dependency chain so the *next* php2shell does not catch you blind.
4. **Log4Shell lab** — a Java service with a vulnerable `log4j`: confirm reachability through your logging path, not just presence.
5. **Leaked key** — a test repo with an AWS key committed three months ago: find it in history, show the blast radius.
6. **Vulnerable base image** — a `Dockerfile` on an outdated base: list OS + app CVEs and the minimal bump.
7. **Public bucket** — a Terraform file that makes an S3 bucket world-readable: catch it before `apply`.
8. **Your own Express API** — an IDOR on `/orders/:id`: prove it against localhost with two accounts.
9. **Reentrancy** — a Solidity contract in a lab: trace the external call before the state update.
10. **Find → Fix handoff** — hand any finding above to [Patch Anything](#companion-patch-anything) and watch the fix PR get drafted.

If you break something interesting (that you are allowed to break), open an issue or PR with the
target, your question, and what you found.

## Companion: Patch Anything

Break Anything and [Patch Anything](https://github.com/EnkiHQ/patch-anything) are built to
work as a pair:

> **Break Anything** finds it and proves it → **Patch Anything** fixes it.

When Break Anything surfaces a finding, your agent can hand it straight to Patch Anything, which
generates a patch, a dependency bump, a compatibility shim, or — when upstream is dead — a
maintained fork or local mitigation. One is offense-flavoured discovery; the other is defensive
repair. Use either alone, or run the loop end to end.

## FAQ

<details>
<summary><strong>Is this an attack tool? Will it get my repo taken down?</strong></summary>

No. Break Anything is a defensive, white-box tool for software you own or are authorized to
test. Every proof-of-concept runs against your own target; it ships no weaponized exploits for
third-party systems. See [DISCLAIMER.md](DISCLAIMER.md). GitHub's policy explicitly supports
dual-use security research.

</details>

<details>
<summary><strong>How is this different from `npm audit` / Trivy / Snyk?</strong></summary>

Those report presence. Break Anything adds **reachability** (is the vulnerable code actually
called in your project), **proof** (a PoC against your own build), and **self-remediation** when
upstream has no fix. It also unifies dependency, source, runtime, and infrastructure findings
behind one agent interface.

</details>

<details>
<summary><strong>Which agents can use it?</strong></summary>

Any agent that supports local MCP servers. Setup configures the common ones automatically;
others can use manual MCP registration.

</details>

<details>
<summary><strong>Does it upload my code?</strong></summary>

Analysis runs locally. Your agent receives the tool results, and its model provider has its own
data policy — review that separately.

</details>

<details>
<summary><strong>Can it test a site I do not own?</strong></summary>

No. Dynamic capabilities require an explicit authorization flag and are intended for your own or
contractually authorized targets. Testing systems without authorization is illegal and
unsupported.

</details>

## Documentation

- [Installation and setup](docs/installation.md)
- [MCP tool catalog](docs/mcp-tools.md)
- [Security model](SECURITY.md)
- [Responsible use](DISCLAIMER.md)

## Disclaimer

Break Anything is for lawful security research, education, and testing of software you own or are
authorized to examine. See [DISCLAIMER.md](DISCLAIMER.md) for responsible-use guidance. You are
responsible for using this software in compliance with all applicable laws and the terms of any
third-party tool it orchestrates.

## License

[MIT](LICENSE)

Break-authored code is licensed under MIT. Third-party tools it orchestrates (Semgrep, CodeQL,
Trivy, Grype, Nuclei, ZAP, and others) retain their own licenses; you must obtain and use them
under their applicable terms.
