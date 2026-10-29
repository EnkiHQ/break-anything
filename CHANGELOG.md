# Changelog

All notable changes to Break Anything are documented here. This project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Planned
- More SAST engines (CodeQL, Bandit, gosec, Brakeman, Find-Sec-Bugs, .NET, frontend).
- More DAST checks (injection, SSRF, auth bypass) and Nuclei template support.
- Optional deep IaC coverage via Checkov / Trivy / KICS on top of the built-in rules.
- Offensive / exploitation family (Metasploit etc.) — gated, authorized-only.
- Call-graph reachability to the specific vulnerable symbol.

## [0.20.0] - 2026-10-23

### Added
- **IaC coverage deepened** — `iac` now also scans, still with no external engine:
  - **AWS CloudFormation** (YAML *and* JSON, auto-detected): security groups open to `0.0.0.0/0`,
    public-read S3 ACLs, wildcard IAM `Action`/`Resource`, encryption-at-rest disabled,
    publicly-accessible databases, hardcoded secrets (CWE-284/311/668/732/798). `!Ref`, `!Sub` and
    `Fn::` references are correctly *not* flagged as hardcoded.
  - **Ansible** (playbooks and task files): `validate_certs: no` (CWE-295), world-writable `0777`
    modes (CWE-732), artifacts fetched over cleartext HTTP (CWE-319), hardcoded secrets (CWE-798),
    root privilege escalation (CWE-250). `{{ vars }}` and Vault references are not flagged.
  - IaC formats covered: Dockerfile, Kubernetes, Terraform, CloudFormation, Ansible.
- Pure, unit-tested `scanCloudFormation` / `scanAnsible` plus extended `classifyIac` (86 tests total).

## [0.19.0] - 2026-10-23

### Added
- **Four more dependency ecosystems**, all via OSV, all built in:
  - **Gradle** (Java/Kotlin) — `gradle.lockfile`, mapped to the `Maven` ecosystem (`group:artifact`).
  - **Dart / Flutter** — `pubspec.lock` (`Pub`), with direct vs transitive from the `dependency:` field.
  - **Elixir** — `mix.lock` (`Hex`), the `:hex` entries.
  - **Swift** — `Package.resolved` v1 & v2 (`SwiftURL`), repo URL normalized to OSV's form.
  - Reachability now also walks `.dart`, `.ex`, `.exs`, `.swift` sources.
- Break Anything now covers **12 dependency ecosystems**: npm (package-lock/yarn/pnpm), PyPI,
  Composer, Go, Rust, Ruby, Maven, Gradle, NuGet, Dart, Elixir, Swift.
- Pure, unit-tested parsers for each (81 tests total). Verified live against OSV (e.g. Gradle
  log4j-core 2.14.1 → Log4Shell).

## [0.18.0] - 2026-10-23

### Added
- **Shareable HTML report** — `brk ci --html report.html` writes a self-contained, single-file HTML
  report (inline styles, no external assets): gate verdict banner, severity summary, and a table of
  findings per category. For stakeholders who don't live in a terminal. All scanned content is
  HTML-escaped (XSS-safe); `--html` with no value prints to stdout.
- Pure, unit-tested `renderHtml` / `findingRow` / `esc` (76 tests total, incl. an XSS-escaping test).

## [0.17.0] - 2026-10-23

### Added
- **Auto-baseline** — `brk ci --baseline` records every current finding into `.break-anything.json`'s
  `ignore` list (each with a `baselined <date>` reason), preserving your `failOn`/`skip`. From then on
  the gate only fails on **new** findings — the practical way to adopt the gate on a repo with
  existing debt. `--baseline=<file>` writes elsewhere; existing ignores are kept.
- Pure, unit-tested `collectFindingIds` / `buildBaseline` (72 tests total).

## [0.16.0] - 2026-10-23

### Added
- **Yarn and pnpm lockfile support** for `deps`/`fix`/`sbom`/`ci` — the npm ecosystem is no longer
  limited to `package-lock.json`:
  - `yarn.lock` — both classic v1 (`name@range:` + `version "x"`) and Berry v2+ (`name@npm:range` +
    `version: x`), including scoped packages.
  - `pnpm-lock.yaml` — v5/v6/v9 package keys (`/name@ver`, `/@scope/name@ver`, `/name/ver`), peer
    suffixes stripped.
  - Precedence per project: `package-lock.json` → `yarn.lock` → `pnpm-lock.yaml` (no double counting).
    Direct deps read from `package.json`.
- Pure, unit-tested `parseYarnLockText` / `parsePnpmLockText` (69 tests total).

## [0.15.0] - 2026-10-23

### Added
- **Policy / baseline config** — `ci` now reads a `.break-anything.json` from the target (or
  `--policy <file>`) so teams can actually adopt the gate:
  - `failOn` — default gate threshold (overridable by `--fail-on`).
  - `skip` — categories to skip (unioned with `--skip`).
  - `ignore` — suppress accepted findings by CVE / rule id (string or `{ "id", "reason" }`); suppressed
    findings drop out of both the gate and the counts, and the report shows how many were ignored.
  - `ci_scan` MCP tool gains an `ignore` parameter.
- This is the first release to publish **through the test gate** added in 0.13.0 — `node --test`
  must pass before `npm publish`.
- Pure, unit-tested `normalizeIgnore` / `isIgnored` / `applyPolicy` / `mergePolicy` (66 tests total).

## [0.14.0] - 2026-10-23

### Added
- `ci` — one command runs the whole repo gate: **dependencies + secrets + IaC + SAST**, aggregated
  into a single report, a single combined SARIF, and a single pass/fail exit code. Drop
  `npx break-anything ci` into a pipeline and you're done.
  - Gate fails on reachable or known-exploited (KEV) dependency vulns, any leaked secret, and
    IaC/code issues at or above `--fail-on` (default HIGH). Each failure is explained.
  - `--fail-on=<critical|high|medium|low>`, `--skip=deps,sast`, `--json`, and `--sarif` (merges every
    category into one SARIF run for a single GitHub Code Scanning upload).
  - Missing engines degrade gracefully (e.g. SAST is skipped, not failed, if Semgrep is absent).
- `ci_scan` MCP tool — an agent can run the full gate in one call.
- Pure, unit-tested `evaluateGate` / `aggregate` / `toSarifMulti` (61 tests total).

## [0.13.0] - 2026-10-23

### Changed
- **Publishing is now gated on tests.** The release workflow runs the full `node --test` suite before
  `npm publish`, so a tag with failing tests can no longer ship.
- **CI runs offline integration tests.** A new `test/integration.test.js` exercises the real
  filesystem-touching scanners (iac, sbom, secrets) and the scan→SARIF/SBOM round-trips, with no
  network dependency. CI also runs the actual `brk` binary end-to-end offline (iac `--json`/`--sarif`,
  sbom, secrets) so CLI wiring regressions are caught.

## [0.12.0] - 2026-10-23

### Added
- **SARIF 2.1.0 output** via `--sarif` on `deps`, `sast`, `iac`, and `secrets`. This is the standard
  static-analysis interchange format — pipe it to GitHub Code Scanning (`upload-sarif`), GitLab, or
  an IDE security panel, and findings show up inline on the exact file/line.
  - Severity maps to SARIF `level` (error/warning/note) and GitHub `security-severity` (9.5/8/5/2).
  - deps results anchor to the lockfile; sast/iac/secrets anchor to file:line; git-history secrets
    get a `git-history@<commit>` location. Absolute paths are relativized to the project root.
- Pure, unit-tested `buildSarif` / `splitLocation` / `toSarif` (52 tests total).

## [0.11.0] - 2026-10-23

### Added
- `sbom` — generate a standard **CycloneDX 1.5** SBOM (software bill of materials) across all eight
  supported ecosystems, each component with a package URL (purl). Pure, local, no network.
  - `brk sbom [path]` prints the SBOM JSON (pipeable); `--out <file>` writes it to a file.
  - `brk sbom [path] --diff <old.json>` compares current composition against a previous SBOM and
    reports added / removed / version-changed components, exiting non-zero on any change — built for
    CI drift gates.
- `sbom_generate` MCP tool.
- Pure, unit-tested `purlFor` / `buildSbom` (dedup + deterministic sort) / `diffSbom`.

## [0.10.0] - 2026-10-23

### Added
- **Java and .NET dependency ecosystems** in `deps`/`fix`, built-in:
  - **Maven** — `pom.xml` `<dependencies>` (package name `groupId:artifactId`), with `${...}`
    versions resolved from `<properties>`; OSV ecosystem `Maven`. Covers declared/direct deps;
    full transitive resolution needs the Maven resolver (roadmap).
  - **.NET** — `packages.lock.json` with resolved versions and `type: Direct` tracking; OSV
    ecosystem `NuGet`.
  - Reachability also walks `.java`, `.kt`, `.cs` sources (import-level).
  - Pure, unit-tested parsers. Shipped ecosystems now: npm, PyPI, Composer, Go, Rust, Ruby, Maven, NuGet.

## [0.9.0] - 2026-10-23

### Added
- **Three more dependency ecosystems** in `deps` (and therefore `fix`), all built-in:
  - **Go** — `go.mod` (require blocks and single-line; `// indirect` is treated as transitive;
    OSV ecosystem `Go`).
  - **Rust** — `Cargo.lock` (`[[package]]` blocks), with direct deps read from `Cargo.toml`
    (OSV ecosystem `crates.io`).
  - **Ruby** — `Gemfile.lock` (`GEM/specs` as packages, `DEPENDENCIES` as direct; OSV ecosystem
    `RubyGems`).
  - Reachability now also walks `.go`, `.rs`, `.rb` sources (import-level).
  - Parsers are pure and unit-tested. Shipped ecosystems: npm, PyPI, Composer, Go, Rust, Ruby.

## [0.8.0] - 2026-10-23

### Added
- **CISA KEV enrichment** for `deps` and `fix`. Every finding is now checked against the CISA Known
  Exploited Vulnerabilities catalog — the authoritative "attackers are using this *right now*"
  signal (a fact, not a probability like EPSS).
  - Findings carry `kev` and `kevRansomware`; a red `[KEV]` badge shows in the terminal and a KEV
    count appears in the summary.
  - KEV is factored into prioritization right after reachability (before severity/EPSS), in both the
    `deps` ranking and the `fix` plan — so a reachable, actively-exploited CVE floats to the very top.
  - Catalog is fetched once per run, cached, and degrades gracefully to "no KEV info" if unreachable.
- `kev.js` with a pure, unit-tested catalog indexer (correctly distinguishes `Known` ransomware use
  from `Unknown`).
- **Three more dependency ecosystems** for `deps` and `fix`, all via OSV with direct-dependency
  detection, closing the gap between what the README advertised and what shipped:
  - **Go** — `go.mod` (require block + single-line; `// indirect` → transitive; `v` prefix stripped).
  - **Rust** — `Cargo.lock` (`[[package]]` blocks), with direct deps read from `Cargo.toml`.
  - **Ruby** — `Gemfile.lock` (`GEM > specs:` for resolved gems, `DEPENDENCIES` for direct).
  `deps` now covers npm, PyPI, Composer, Go, crates.io, and RubyGems.
- Reachability now also scans `.go/.rs/.rb` sources (Go import paths resolve to `imported`;
  symbol-call analysis remains JS/TS-only).

## [0.7.0] - 2026-10-23

### Added
- `fix` — turns dependency findings into a prioritized, actionable remediation plan. This closes the
  **Fix** leg of find → prove → fix.
  - Groups CVEs by package and computes the **minimal safe upgrade** that resolves the most CVEs at
    once (handles multi-branch backport fix versions).
  - Orders the work by **reachability first** (`called` before `imported`), then severity, then how
    many CVEs each upgrade clears — so you fix what an attacker can actually reach first.
  - Emits the **exact upgrade command** per ecosystem: `npm install`, `pip install`,
    `composer require`.
  - Packages with **no upstream fix** are listed separately with mitigation guidance (pin, mitigate,
    or move to a maintained fork — hand off to Patch Anything).
  - `brk fix [path]`, plus `--from <deps.json>` to plan from an existing scan without rescanning,
    and `--json`.
- `fix_plan` MCP tool.

### Honest limitation
- Upgrade targets are minimal safe-version *suggestions*; validate compatibility with your own tests.

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

[Unreleased]: https://github.com/EnkiHQ/break-anything/compare/v0.20.0...HEAD
[0.20.0]: https://github.com/EnkiHQ/break-anything/compare/v0.19.0...v0.20.0
[0.19.0]: https://github.com/EnkiHQ/break-anything/compare/v0.18.0...v0.19.0
[0.18.0]: https://github.com/EnkiHQ/break-anything/compare/v0.17.0...v0.18.0
[0.17.0]: https://github.com/EnkiHQ/break-anything/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/EnkiHQ/break-anything/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/EnkiHQ/break-anything/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/EnkiHQ/break-anything/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/EnkiHQ/break-anything/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/EnkiHQ/break-anything/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/EnkiHQ/break-anything/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/EnkiHQ/break-anything/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/EnkiHQ/break-anything/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/EnkiHQ/break-anything/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/EnkiHQ/break-anything/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/EnkiHQ/break-anything/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/EnkiHQ/break-anything/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/EnkiHQ/break-anything/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/EnkiHQ/break-anything/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/EnkiHQ/break-anything/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/EnkiHQ/break-anything/releases/tag/v0.1.0
