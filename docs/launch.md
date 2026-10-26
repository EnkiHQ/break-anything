# Launch kit

Research-backed. Sources: Show HN title formula ([signals.sh](https://signals.sh/blog/show-hn-title-formulas)),
star-spike patterns ([dev.to, 50 repos](https://dev.to/0012303/i-analyzed-50-github-repos-that-went-from-0-to-10k-stars-here-are-the-7-patterns-54o1)),
launch-day data ([arXiv 2511.04453](https://arxiv.org/abs/2511.04453)).

## The one-liner (use everywhere, unchanged)

> **Break Anything** — you think your service is secure, but you've never looked at it the way an
> attacker would. Point your coding agent at code you own; it finds what's genuinely exploitable,
> proves it on your own build, and fixes it.

Rule: lead with the fear/pain, not the feature. The hook is the awareness gap ("you never actually
tested it"); the proof is reachability (an attacker only cares about what they can reach — so does
Break Anything).

## Timing

Launch **Tuesday–Thursday, ~8–10am US Eastern**. Timing moves stars more than almost anything
else; the "Show HN" tag itself adds nothing after controlling for timing and content.

## Hacker News (the multiplier — 87% of 10K-star repos start here)

**Title** (formula: `[Name] – [plain description]`; no caps, no `!`, no praise):

```
Show HN: Break Anything – an MCP that audits your own code the way an attacker would
```

**First comment** (this is where the story goes, not the title — personal story earns ~3× the
upvotes of a dry description):

> My app was "probably secure" — it shipped, it worked, nobody complained, so I never actually
> tested it. That's most software. I built Break Anything to close that gap: point your coding
> agent at code you own and it looks at it the way an attacker would. It's an MCP server + CLI
> that orchestrates OSV, Trivy, gitleaks (Semgrep/ZAP next), ranks findings by reachability + EPSS
> (an attacker only cares about what they can actually reach), builds a proof-of-concept against
> your own build, and — when upstream has no fix — proposes a patch. Defensive, local,
> authorized-targets-only. Companion project Patch Anything does the repair half. Honest about
> limits: reachability is today a heuristic (is it imported), not yet full call-path proof.
> Feedback welcome, especially on the reachability engine.

## Cross-posts (same day → next day)

- **r/netsec, r/programming** — lead with the reachability angle: "most SCA reports presence; this
  reports what's actually reachable + a PoC on your own target."
- **X / 即刻 thread** — beat 1: the 400-vs-3 pain. beat 2: the hero GIF. beat 3: find → prove →
  fix. beat 4: companion Patch Anything. beat 5: repo + 10 demos.
- **V2EX / 掘金** — 直给、不绕:标题「`npm audit` 报你 47 个漏洞,到底哪 3 个能真打穿你?」正文讲
  可达性 + 自己靶子的 PoC + 上游不修时的自救,强调防御定位与「只打自己授权的目标」。
- **Awesome lists** — submit a one-line PR to the relevant awesome-security / awesome-devsecops
  lists. These are GitHub's long-tail search engine (steady stars for months).

## Hero GIF

The README's first asset. Current cut (`vhs demos/hero.tape`) tells the whole story in ~19s with
plain-language captions: *12 vulns here — which actually reach me?* → the reachable ones →
*a key I deleted is still in git* → *found, proven, fixed.* Keep it under ~20s. See
[hero-gif.md](hero-gif.md).

## Guardrails (don't skip)

- **Never buy stars.** ~6M fake stars exist on GitHub and fake-star repos get flagged/banned;
  a fake curve destroys the credibility a real launch builds.
- README line 1 is the pain, not the feature. Install command visible without scrolling.
- Every demo/screenshot uses a lab or your own host. Never a third party.
- Respond to every early issue within 24h — even just an acknowledgment. It converts drive-by
  visitors into stargazers.
- Be honest about limits (reachability heuristic, roadmap vs shipped). Restraint reads as
  credibility; overclaiming gets picked apart.
