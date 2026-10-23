# Responsible use

Break Anything is a **defensive security tool**. It helps you find, prove, and fix
vulnerabilities in software **you own or are explicitly authorized to test**.

## Authorized scope only

Use Break Anything only against:

- code, dependencies, images, and infrastructure that you own;
- systems you have **written, contractual authorization** to test (e.g. a pentest engagement
  with a signed scope);
- deliberately vulnerable labs and open-source projects intended for security practice.

Do **not** point Break Anything — especially its dynamic (running-app and API) capabilities — at
any system you do not own or are not authorized to test. Unauthorized testing of computer systems
is illegal in most jurisdictions and is not supported by this project.

## Safety defaults

- **Dynamic capabilities are off by default.** Running-app scanning, API testing, and any
  capability that sends traffic to a target require both an operator policy and an explicit
  per-run authorization flag.
- **Static analysis reads your files; it does not run them.**
- **Proof-of-concept output targets your own build.** Break Anything is designed to demonstrate a
  weakness against your target so you can fix it — not to produce reusable weapons against third
  parties.
- **Analysis is local.** Break Anything does not ship your code to a hosted analysis service. The
  coding agent and model provider you use have their own data policies.

## Not weaponization

Break Anything orchestrates well-known security tooling to help defenders. It is not intended for
developing malware, building attack infrastructure, targeting systems at scale, or evading the
defenses of systems you do not control. Contributions that turn it in those directions will be
declined.

## Your responsibility

You are responsible for using Break Anything in compliance with all applicable laws and
regulations, and with the license terms of every third-party tool it orchestrates. If you are
unsure whether you are authorized to test a given target, assume you are not.

Report security issues in Break Anything itself through the process in [SECURITY.md](SECURITY.md).
