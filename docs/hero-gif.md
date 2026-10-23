# Hero GIF — recording recipe

The single most important launch asset. 25–35 seconds, no narration, the README's first image.

## What it shows

The runnable script [`demos/hero-demo.sh`](../demos/hero-demo.sh) produces three beats, all on
targets you own:

1. **The forgotten dependency** — `cat` a `package.json` pinned to an old `lodash`.
2. **The scan** — `brk deps` returns real CVEs ranked so the *reachable* criticals rise to the
   top. Not a 400-line wall; the few that matter.
3. **The buried secret** — `brk secrets --history` finds an AWS key that was deleted from the
   code but is still sitting in git history, pinned to the commit.

Ending card: `Find → Prove → Fix. npx break-anything`.

## Record it

Install the tools once:

```bash
brew install asciinema agg      # macOS; agg turns the cast into a GIF
```

Record and convert:

```bash
cd /path/to/break-anything
asciinema rec hero.cast -c "bash demos/hero-demo.sh"
agg --font-size 22 --theme monokai hero.cast docs/assets/hero.gif
```

Then reference it at the top of the README:

```markdown
<img src="docs/assets/hero.gif" alt="Break Anything finding reachable CVEs and a secret buried in git history" width="900" />
```

## Tips for a GIF that spreads

- Keep the terminal ~90 columns, large font. People watch these on phones.
- Trim to under 35s. The `deps` result and the "deleted but still in history" reveal are the two
  moments that make people stop scrolling — land them fast.
- Do not show a cursor hunting around. The script paces itself; just let it run.
- Record on a clean prompt, dark theme, no personal paths visible (the script uses a temp dir).
- Post the GIF in the README, the Show HN, and the X thread. Same asset everywhere.

## Honesty guardrails (keep the credibility that makes it spread)

- Every target in the GIF is a sample project or a throwaway repo you own. Never a third party.
- The CVEs and EPSS numbers are real (live OSV / FIRST.org lookups), so the demo holds up when
  someone reruns it. Do not fake the output.
