# Changelog

All notable changes to Break Anything are documented here. This project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Planned
- SAST scanner (Semgrep/CodeQL) for injection, broken access control, deserialization.
- DAST scanner (OWASP ZAP / Nuclei) for authorized running apps.
- IaC scanner (Terraform / Dockerfile / Kubernetes).
- CISA KEV enrichment in `deps`.

## [0.1.0] - 2026-10-23

### Added
- `deps` — dependency vulnerability scan via OSV for npm, Composer (PHP), and pip, with
  import-based reachability heuristic, EPSS exploit-probability enrichment, and fix versions.
- `secrets` — secret scan of the working tree and, with `--history`, the full git history;
  matches are redacted in output.
- `image` — container image scan via Trivy with graceful degradation when Trivy is absent.
- MCP server exposing `deps_scan`, `secrets_scan`, and `image_scan`.
- CLI (`brk`) with human-readable and `--json` output, plus CI-friendly exit codes.

[Unreleased]: https://github.com/EnkiHQ/break-anything/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/EnkiHQ/break-anything/releases/tag/v0.1.0
