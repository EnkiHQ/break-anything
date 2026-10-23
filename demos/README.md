# Demos

Ten worked demos. **Every target here is one you own, an open-source project, or a deliberately
vulnerable lab.** None of them point at a third-party system. This is the rule that keeps Break
Anything a defensive tool — copy it in your own showcases.

Each demo is a single prompt you give your agent, plus the terminal equivalent. The 30-second
GIF you record for the README should be demo 1 or demo 8: a finding appears, a request proves it,
a fix is suggested.

| # | Demo | Target type | Capability | Risk |
| --- | --- | --- | --- | --- |
| 1 | [Juice Shop IDOR](#1-juice-shop-idor) | authorized lab | DAST + API | none (lab) |
| 2 | [The dependency you forgot](#2-the-dependency-you-forgot) | your lockfile | SCA + reachability | none (static) |
| 3 | [PHP supply chain after php2shell](#3-php-supply-chain-after-php2shell) | your PHP project | SCA graph | none (static) |
| 4 | [Log4Shell reachability](#4-log4shell-reachability) | lab Java service | SCA + reachability | none (lab) |
| 5 | [Leaked key in history](#5-leaked-key-in-history) | your test repo | secrets | none (static) |
| 6 | [Vulnerable base image](#6-vulnerable-base-image) | your Dockerfile | image scan | none (static) |
| 7 | [Public bucket](#7-public-bucket) | your Terraform | IaC | none (static) |
| 8 | [Your Express IDOR](#8-your-express-idor) | your localhost API | API logic | none (your host) |
| 9 | [Reentrancy](#9-reentrancy) | lab contract | Slither | none (lab) |
| 10 | [Find to Fix handoff](#10-find-to-fix-handoff) | any of the above | handoff | none |

---

## 1. Juice Shop IDOR

Spin up the official OWASP Juice Shop lab locally, then:

```text
Use Break Anything against http://localhost:3000 (I own this lab). Find a broken
access control issue, prove it with a concrete request, and explain the fix.
```

```bash
export BRK_DYNAMIC_ENABLED=true
export BRK_AUTHORIZED_TARGETS_JSON='["http://localhost:3000"]'
brk dast active-scan http://localhost:3000 --profile access-control
```

Expected: an IDOR on a basket/order endpoint, with the exact request that proves it and a
one-line fix (enforce ownership check server-side).

## 2. The dependency you forgot

Point at any real project of yours.

```text
Use Break Anything to scan my dependencies. Only flag CVEs where the vulnerable
function is actually reachable from my code. Give me fix versions.
```

```bash
brk deps ./ --reachability --json
```

Expected: a short, high-signal list (reachable only), each with fix version and EPSS — not the
usual 400-line `npm audit` wall.

## 3. PHP supply chain after php2shell

The news hook, done honestly. php2shell is a PHP *runtime* bug, not a dependency bug — so this
demo shows the real lesson: map your whole chain so the next surprise does not catch you blind.

```text
Map my PHP project's full dependency chain with Break Anything. Flag anything
with known CVEs or an unmaintained upstream, and tell me which ones have no fixed
version so I can plan a mitigation.
```

```bash
brk deps ./ --ecosystem composer --graph --flag-unmaintained
```

Expected: the dependency graph, CVE hits, and — the valuable part — a list of deps with **no
upstream fix**, which is where Patch Anything comes in.

## 4. Log4Shell reachability

Use a pinned lab service with a vulnerable `log4j`.

```text
Does my service actually reach the vulnerable log4j code path, or is the library
just present? Prove whichever it is.
```

```bash
brk deps ./ --ecosystem maven --reachability --focus CVE-2021-44228
```

Expected: a verdict of `reachable` or `not_reachable` with the call path, so you patch what
matters first.

## 5. Leaked key in history

```text
Scan my repo and its git history for committed secrets. For anything you find,
estimate the blast radius.
```

```bash
brk secrets ./ --history
```

Expected: the leaked key, the commit that introduced it, and whether it is still live — plus the
reminder to rotate, not just delete.

## 6. Vulnerable base image

```text
Scan my Dockerfile and built image. Give me the minimal base-image bump that
clears the critical CVEs.
```

```bash
brk image my-service:latest
brk iac dockerfile ./Dockerfile
```

## 7. Public bucket

```text
Check my Terraform before I apply it. Flag anything that exposes data publicly.
```

```bash
brk iac terraform ./infra
```

Expected: the world-readable S3 bucket (or equivalent), caught pre-`apply`.

## 8. Your Express IDOR

Run your own API locally with two test accounts.

```text
My API is on http://localhost:4000 and I own it. Check /orders/:id for broken
access control using account A and account B, and prove it.
```

```bash
export BRK_DYNAMIC_ENABLED=true
export BRK_AUTHORIZED_TARGETS_JSON='["http://localhost:4000"]'
brk api idor-probe http://localhost:4000 --paths /orders/:id --accounts ./accounts.json
```

Expected: account A reading account B's order, with the two requests side by side.

## 9. Reentrancy

```text
Analyze this Solidity contract for reentrancy and access-control gaps. Show the
external call that happens before the state update.
```

```bash
brk contract ./contracts/Vault.sol
```

## 10. Find to Fix handoff

```text
Take the finding from the last scan and hand it to Patch Anything. Draft the fix
and open a PR against a branch.
```

```bash
brk fix plan --from last
brk fix handoff-patch-anything --from last
```

Expected: a fix plan, then Patch Anything drafting the change — the full loop that makes the two
projects a pair.
