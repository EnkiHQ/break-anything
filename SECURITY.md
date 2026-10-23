# Security model and reporting

## Security model

- **Local by design.** Break Anything runs analysis on your machine and does not upload targets
  to a hosted service.
- **Least privilege.** Providers and launched targets run with the current user's permissions.
  Break Anything is not a sandbox; treat untrusted targets accordingly and run them in a VM or
  container when in doubt.
- **Dynamic capabilities are gated.** Anything that sends traffic to a target (running-app
  scanning, API testing) is disabled unless an operator policy enables it *and* a per-run
  authorization flag is passed.
- **Evidence over assertion.** Each finding carries its provider identity, the evidence behind
  it, an exploitability signal (reachability / EPSS / KEV), and its limitations. Absence of a
  finding is never reported as proof of safety.
- **No bundled credentials or keys.** Break Anything grants no license, key, or activation for
  any third-party tool it orchestrates.

## Reporting a vulnerability in Break Anything

If you find a security issue in Break Anything itself, please report it privately rather than
opening a public issue.

1. Email the maintainers at `security@break-anything.dev` (placeholder — replace with your real
   contact before publishing).
2. Include the version, a description, and reproduction steps.
3. You will receive an acknowledgement, and we will coordinate a fix and disclosure timeline with
   you.

Please do not use a real third-party system to demonstrate a report. A local reproduction is
sufficient.
