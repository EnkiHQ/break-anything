# Contributing to Break Anything

Thanks for helping make Break Anything better. This project orchestrates trusted security tools
behind one agent interface, so contributions that add coverage, improve signal, or reduce noise
are especially welcome.

## Ground rules

Break Anything is a **defensive** tool for software you own or are authorized to test. We will
decline contributions that turn it into attack tooling: turnkey exploits for specific live
third-party targets, denial-of-service payloads, mass-targeting, or features designed to evade
the defenses of systems you do not control. See [DISCLAIMER.md](DISCLAIMER.md).

## Development setup

```bash
git clone https://github.com/EnkiHQ/break-anything.git
cd break-anything
npm install
node bin/brk.js --help
node --test        # run the test suite
```

No build step: the project is plain Node.js ESM. `bin/brk.js` is the CLI entry; `src/` holds the
scanners; `src/mcp.js` exposes them as MCP tools.

## Project layout

| Path | What it is |
| --- | --- |
| `bin/brk.js` | CLI entry and command dispatch |
| `src/scan.js` | dependency scan orchestration |
| `src/osv.js` | OSV vulnerability lookup |
| `src/lockfiles.js` | lockfile parsers (npm / Composer / pip) |
| `src/reachability.js` | import-based reachability heuristic |
| `src/epss.js` | EPSS enrichment |
| `src/secrets.js` | secret scanning (worktree + git history) |
| `src/image.js` | container image scan (Trivy wrapper) |
| `src/report.js` | human-readable renderers |
| `src/mcp.js` | MCP server + tool definitions |

## Adding a scanner

1. Add a module in `src/` that returns the standard result envelope
   (`{ target, ok, findings, summary }`), with each finding carrying `severity`, `evidence`, and
   `remediation` where available.
2. Wire a CLI subcommand in `bin/brk.js`.
3. Add an MCP tool in `src/mcp.js` with a clear, authorized-targets-only description.
4. Add a renderer in `src/report.js`.
5. Add a unit test for any pure parsing/normalization logic (no network in tests).
6. Update the "What you can test" table and the [tool catalog](docs/mcp-tools.md), marking it
   shipped.

## Pull requests

- Keep PRs focused. One scanner or one fix per PR.
- Run `node --test` before submitting.
- Describe what you changed, how you tested it, and any new third-party tool it depends on (add
  it to [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)).

## Reporting bugs and vulnerabilities

- Bugs: [open an issue](https://github.com/EnkiHQ/break-anything/issues).
- Security issues in Break Anything itself: follow [SECURITY.md](SECURITY.md) (report privately).
