# Installation and setup

## Requirements

- Node.js 22.19+ and npm
- macOS, Linux, or Windows (WSL recommended on Windows for dynamic tools)
- Optional analysis engines depending on the target (see below)

## Set up your agent

```bash
npx break-anything setup
```

Setup detects installed agents, prints every proposed change, backs up existing configuration,
and asks before applying anything. Supported agents:

- Claude Code
- Claude Desktop
- Codex
- Cursor
- Gemini CLI
- Windsurf

Any other client that can run a local MCP server can use the
[manual registration](mcp-tools.md#manual-mcp-registration).

## Install the CLI

```bash
npm install --global break-anything
brk --help
brk doctor
```

`brk doctor` is read-only. It reports which optional engines are present and which capabilities
are therefore available.

## Optional analysis engines

Break Anything orchestrates tools you already trust. It does not bundle or re-license them.

| Capability | Engine | Install |
| --- | --- | --- |
| Dependency CVEs | OSV database | built-in (queries OSV.dev) |
| SAST | Semgrep | `pipx install semgrep` |
| SAST (deep) | CodeQL | CodeQL CLI from GitHub |
| Secrets | gitleaks | `brew install gitleaks` |
| Images / IaC | Trivy | `brew install trivy` |
| Images (second opinion) | Grype | `brew install grype` |
| Dynamic web | OWASP ZAP | ZAP desktop or `zaproxy` |
| Templates | Nuclei | `brew install nuclei` |
| Smart contracts | Slither | `pipx install slither-analyzer` |

## Enable dynamic (running-app) capabilities

Dynamic tools are off by default. To test your own running app or API:

```bash
export BRK_DYNAMIC_ENABLED=true
export BRK_AUTHORIZED_TARGETS_JSON='["http://localhost:3000"]'
```

Dynamic tools refuse any target not in the allowlist. See [DISCLAIMER.md](../DISCLAIMER.md).

## Uninstall

```bash
brk uninstall          # remove MCP registrations + managed skill
brk uninstall --purge  # also remove ~/.brk cache and state
```

Uninstall preserves your other MCP servers, your installed engines, and your evidence bundles.
