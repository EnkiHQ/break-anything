# Hero GIF — how it's made

The single most important launch asset: the README's first image. 15–35 seconds, no narration,
real tool output.

The committed `docs/assets/hero.gif` is generated with [VHS](https://github.com/charmbracelet/vhs)
from a repeatable script, so anyone can re-render it.

## What it shows

Two beats, both real:

1. **A dependency you forgot** — `brk deps demos/sample-npm` runs a live OSV scan and returns the
   real CVE list for an old `lodash`/`minimist`, ranked by reachability + EPSS, with fix versions.
2. **A secret you thought you deleted** — `brk secrets /tmp/brk-hero --history` finds an AWS key
   that was removed from the code but is still in git history, pinned to the commit.

Ending card: `# Find -> Prove -> Fix.    npx break-anything`.

## Re-render it

Install VHS once (macOS):

```bash
brew install vhs
```

Then, from the repo root:

```bash
# A proxy is only needed if your network can't reach the OSV API directly.
HTTPS_PROXY=... HTTP_PROXY=... vhs demos/hero.tape
```

This writes `docs/assets/hero.gif`. The tape ([`demos/hero.tape`](../demos/hero.tape)) defines a
`brk` shell function, sets any proxy, and runs [`demos/hero-setup.sh`](../demos/hero-setup.sh) to
build the throwaway git repo for the secrets beat — all in a hidden prelude.

## Tuning

- **Timing:** the `deps` scan hits the network. The `Sleep` after it must exceed the scan time or
  the next line types over the output. 13s is a safe default; lower it if your network is fast.
- **Theme / size:** `Set Theme`, `Set FontSize`, `Set Width/Height` at the top of the tape.
- **Shorter GIF:** most of the length is the live `deps` network wait. To cut it, pre-capture the
  colored output once (`script -q out.ansi node bin/brk.js deps demos/sample-npm`) and have the
  tape `cat` it instead of running live.

## Guardrails (keep the credibility that makes it spread)

- Every target is a sample project or a throwaway repo you own. Never a third party.
- The CVEs and EPSS numbers are real (live OSV / FIRST.org lookups). Don't fake the output.
