# Changelog

All notable changes to Break Anything are documented here. This project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Planned
- More SAST engines (CodeQL, Bandit, gosec, Brakeman, Find-Sec-Bugs, .NET, frontend).
- More DAST checks (injection, SSRF, auth bypass) and Nuclei template support.
- Optional deep IaC coverage via Checkov / Trivy / KICS on top of the built-in rules.
- Offensive / exploitation family (Metasploit etc.) — gated, authorized-only.
- CISA KEV enrichment in `deps`; call-graph reachability to the vulnerable symbol.

## [0.6.0] - 2026-10-23

### Changed
- `deps` reachability is now two-tier and much stronger. Beyond "is the package imported", it
  extracts the symbols actually imported from a vulnerable package (default / namespace / named /
  renamed, for both `require` and ESM) and checks whether those symbols are **invoked** in your
  code:
  - **`called`** — an imported symbol is actually invoked (`_.merge(...)`, `new Client()`, …) → the
    strongest reachability signal, ranked above everything else.
  - **`imported`** — imported but no call seen (side-effect or type-only import).
  - **`direct` / `transitive`** — unchanged.
  Call analysis covers JS/TS (`.js/.mjs/.cjs/.jsx/.ts/.tsx/.vue`); PHP/Python stay at import
  granularity. Member calls on unrelated objects (`other.merge(...)`) no longer cause false
  positives. The summary now reports both reachable and "called" counts, and `--json` carries
  `reachability: "called"`.

### Honest limitation
- `called` means an imported symbol is invoked — it is still **not** proof that the specific
  vulnerable function named in the advisory executes. True call-graph-to-symbol reachability is on
  the roadmap.

## [0.5.0] - 2026-10-23

### Added
- `iac` — infrastructure-as-code misconfiguration scan, **built in, no external engine required**.
  Covers the common high-impact issues across three formats:
  - **Dockerfile** — runs as root / no `USER`, `:latest` base image, remote script piped into a
    shell, `ADD` of a remote URL, hardcoded secrets in `ENV`/`ARG` (CWE-250/494/798/1104).
  - **Kubernetes** — privileged containers, `allowPrivilegeEscalation`, host namespaces
    (`hostNetwork`/`hostPID`/`hostIPC`), `runAsNonRoot: false`, dangerous capabilities, `:latest`
    images (CWE-250/668/1104).
  - **Terraform** — world-open CIDR (`0.0.0.0/0`), public-read storage ACL, disabled encryption,
    hardcoded secrets (CWE-284/311/732/798).
  Each finding has file/line, CWE, redacted evidence, and a fix. Secret values are never echoed.
- `iac_scan` MCP tool.

## [0.4.0] - 2026-10-23

### Added
- `api` — dynamic API security probe (DAST) for a **running** service: broken object-level
  authorization (IDOR/BOLA, CWE-639 / API1:2023), missing authentication (CWE-306 / API2:2023),
  and missing security headers (CWE-693 / API8:2023). Every finding ships the **reproducing
  request** as proof, with credentials redacted.
- `api_scan` MCP tool.
- Safety gate for all dynamic probing: off by default, requires `BRK_DYNAMIC_ENABLED=true` **and**
  the target to be listed in `BRK_AUTHORIZED_TARGETS_JSON`. The gate is a pure function with unit
  tests; it refuses anything not explicitly authorized.
- `--config <file>` on `api` to supply two accounts you control and the object paths to probe.

### Fixed
- CLI flag parser now accepts both `--key value` and `--key=value` for value flags (`--config`, `--top`).

## [0.3.0] - 2026-10-26

### Added
- `setup` now **auto-registers** Break Anything's MCP server into every supported agent it finds
  on the machine — Claude Desktop, Claude Code, Cursor, Codex, Gemini CLI, Windsurf. It backs up
  each config first, preserves everything else, is idempotent, and never corrupts a malformed
  config (it skips it). `--dry-run` previews; `--print` just prints the config.

## [0.2.0] - 2026-10-24

### Added
- `sast` — static application security testing via Semgrep: injection, broken access control,
  insecure deserialization, SSRF, hardcoded secrets — each with file/line, CWE/OWASP tags, and the
  offending snippet. Supports `--config` and `--top`.
- `sast_scan` MCP tool.
- `--top=N` on `deps` (and `sast`) to show only the worst N findings.
- English-first CLI output (`BRK_LANG=zh` for Chinese).

## [0.1.0] - 2026-10-23

### Added
- `deps` — dependency vulnerability scan via OSV for npm, Composer (PHP), and pip, with
  import-based reachability heuristic, EPSS exploit-probability enrichment, and fix versions.
- `secrets` — secret scan of the working tree and, with `--history`, the full git history;
  matches are redacted in output.
- `image` — container image scan via Trivy with graceful degradation when Trivy is absent.
- MCP server exposing `deps_scan`, `secrets_scan`, and `image_scan`.
- CLI (`brk`) with human-readable and `--json` output, plus CI-friendly exit codes.

[Unreleased]: https://github.com/EnkiHQ/break-anything/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/EnkiHQ/break-anything/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/EnkiHQ/break-anything/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/EnkiHQ/break-anything/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/EnkiHQ/break-anything/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/EnkiHQ/break-anything/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/EnkiHQ/break-anything/releases/tag/v0.1.0
