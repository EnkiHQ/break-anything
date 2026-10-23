# Launch kit

Timing: publish Friday. Trending incubates over the weekend. Post the moment the hero GIF is
ready, not before.

## The one-liner (use everywhere)

> **Break Anything** — point your agent at code you own, find the weakness, prove it, fix it.
> The REA for vulnerabilities.

## Slogans (pick one per channel)

- Break it before they do.
- Your agent now has a security team.
- Find the bug. Prove the bug. Kill the bug.
- After REA understood everything, Break Anything finds what's broken.

## Hero GIF (the single most important asset)

15–30 seconds, no narration:

1. Drag a repo (or type one prompt) into the agent.
2. Break Anything returns 3 findings — not 400 — each tagged `reachable`.
3. One finding expands into a proof request against localhost.
4. "Hand to Patch Anything" → a fix PR appears.

Record demo 1 (Juice Shop) or demo 8 (your Express IDOR). Both run on targets you own.

## Hacker News (Show HN)

Title: `Show HN: Break Anything – an MCP that finds, proves, and fixes vulns in your own code`

Body (short, factual, no hype):

> After REA wrapped reverse-engineering tools for agents, I wanted the same for AppSec. Break
> Anything is one MCP server that gives your coding agent Semgrep, CodeQL, OSV, Trivy, ZAP and
> friends behind one interface. The part I care about: it ranks findings by whether the
> vulnerable code is actually reachable in your project, builds a PoC against your own build, and
> — when upstream has no fix — proposes a patch or mitigation. Defensive only; dynamic scanning
> is off by default and refuses targets not on your allowlist. Companion project Patch Anything
> does the repair half. Feedback welcome, especially on the reachability engine.

## r/netsec / r/programming

Lead with the reachability angle (that is what this crowd respects):

> Most SCA tools report presence. Break Anything reports reachability + a PoC against your own
> target, and handles the "upstream won't fix it" case. MCP server, works with Claude Code /
> Cursor / Codex. Defensive, authorized-targets-only. Repo + 10 reproducible demos (all on labs
> you own) inside.

## X / 即刻 thread

1/ php2shell reminded everyone: your stack breaks even when your code is clean.
2/ So I built Break Anything — point your agent at software you own, it finds what's broken,
   proves it, and fixes it.
3/ The trick isn't another scanner. It's reachability: 3 findings that matter, not 400 that
   don't. [GIF]
4/ Find → Prove → Fix. The fix half is a companion project, Patch Anything.
5/ Defensive only, authorized targets only, runs local. Repo + 10 demos ↓

## V2EX

标题:`给 AI Agent 配一个安全团队:Break Anything(攻破一切)`

正文:承接 php2shell 的话题,说清"不是又一个扫描器,卖点是可达性 + 对自己靶子的 PoC + 上游不修时的自救",
强调防御定位和"只打自己授权的目标",附仓库和 10 个自有靶场 demo。

## Cross-promotion with Patch Anything

- Each README links the other in the first screen.
- Ship them the same week; lead with Break (discovery is more viral), let it funnel stars to
  Patch.
- Pinned issue in each repo: "Using Break + Patch together" with the demo 10 loop.

## Guardrails for the launch (do not skip)

- README line 1 states authorized-targets-only. This is your takedown insurance.
- Every demo and screenshot uses a lab or your own host. Never show popping a third party.
- Do not accept PRs that add turnkey exploits for specific live targets.
- Respond to "can it scan example.com?" with the authorization policy, publicly. It sets the tone
  and protects the project.
