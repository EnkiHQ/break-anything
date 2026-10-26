# Hero GIF — how it's made

The README's first image. Short (~12s), tight, cool, real tool output. Generated with
[VHS](https://github.com/charmbracelet/vhs) from a repeatable script.

## What it shows

Two beats:

1. **Dependencies** — `brk deps` plays a quick scanning animation, then snaps the real top
   findings for an old `lodash`/`minimist`: two CRITICALs + a HIGH at 21.3% EPSS, each tagged
   `reachable`, with fix versions, over a bold `12 findings · 10 reachable` summary.
2. **Secrets** — `brk secrets --history` finds an AWS key removed from the code but still in git
   history, pinned to the commit, with the "rotate, don't just delete" warning.

Outro: `# find -> prove -> fix    npx break-anything`.

## Why the deps output is pre-captured

The `deps` scan hits the OSV network, which adds several seconds of dead air to a recording. So
the real colored output is captured once, off-camera, and replayed instantly behind a scanning
animation — the data is genuine, the GIF stays tight.

Re-capture it (real, colored, top 3) any time:

```bash
script -q demos/.hero/deps.ansi node bin/brk.js deps demos/sample-npm --top=3
```

`demos/hero-brk.sh` is the tape's `brk` wrapper: it animates + replays that file for `deps`, and
runs the real CLI for everything else (`secrets` is local and instant, so it runs live).

## Re-render

```bash
brew install vhs       # once
vhs demos/hero.tape    # writes docs/assets/hero.gif
```

## Tuning

- **Look:** `Set Theme / FontSize / Width / Height / WindowBar / MarginFill / BorderRadius` at the
  top of [`demos/hero.tape`](../demos/hero.tape).
- **Findings shown:** `--top=N` in the capture command (and the real CLI).
- **Avoid `→` in `Type` lines** — VHS can drop the multibyte arrow; use `->`. Arrows inside the
  captured `deps.ansi` render fine.

## Guardrails

- Every target is a sample project or a throwaway repo you own — never a third party.
- The CVEs and EPSS numbers are real (captured from a live OSV / FIRST.org scan). Don't fake them.
