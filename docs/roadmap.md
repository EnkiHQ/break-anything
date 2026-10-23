# Roadmap

Break Anything is growing from a dependency scanner into one agent-facing interface for finding,
proving, and fixing weaknesses across the whole surface of a project you own. Roadmap items
describe direction, not shipped support. A new scanner joins the public workflow only once it
produces the same finding envelope (severity, evidence, exploitability, remediation, limitations)
as the shipped scanners.

## Shipped (0.1.0)

- **Supply chain / dependencies (SCA)** — npm, Composer (PHP), pip; OSV lookup, import-based
  reachability heuristic, EPSS, fix versions.
- **Secrets** — working tree + git history, redacted output.
- **Container images** — via Trivy.
- **MCP tools** — `deps_scan`, `secrets_scan`, `image_scan`.

## Next

- **SAST** — Semgrep and CodeQL rulepacks for injection, broken access control, insecure
  deserialization, path traversal, SSRF, hardcoded secrets; data-flow evidence. Languages first:
  JS/TS, Python, Go, Java, PHP.
- **Exploitability engine** — upgrade reachability from "is it imported" to "is the vulnerable
  symbol on a real call path", and rank with EPSS + CISA KEV.
- **IaC** — Terraform, Dockerfile, Kubernetes, CloudFormation misconfiguration.
- **DAST (authorized)** — OWASP ZAP + Nuclei against your own running app; API logic tests
  (IDOR, broken access control, mass assignment) with reproducible requests.

## Later

- **Self-remediation** — when upstream has no fix: generate a patch, pin, compatibility shim, or
  point to a maintained fork. Deep handoff to [Patch Anything](https://github.com/EnkiHQ/patch-anything).
- **More ecosystems** — Go modules, Cargo, RubyGems, Maven reachability parity.
- **Smart contracts** — Slither-backed Solidity analysis.
- **Evidence bundles** — portable, reproducible finding records that survive across sessions and
  feed CI gating.
- **SBOM** — generate and diff SBOMs; watch your dependency chain for the *next* zero-day.

## Principles

- Defensive, authorized-targets-only. Dynamic capabilities stay off by default.
- Orchestrate trusted tools; don't reinvent scanners.
- Signal over noise: always separate "confirmed", "reachable", and "present".
- Honesty: absence of a finding is never reported as proof of safety.
