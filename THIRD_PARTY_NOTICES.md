# Third-party notices

Break Anything-authored code is licensed under [MIT](LICENSE). Break Anything orchestrates and,
in some modes, requires external tools and data sources that retain their own licenses and terms.
Break Anything grants no license to these tools; you must obtain and use them under their
applicable terms.

## Bundled npm dependency

| Package | License | Purpose |
| --- | --- | --- |
| `@modelcontextprotocol/sdk` | MIT | MCP server protocol implementation |

## Orchestrated tools (not bundled)

These are invoked if present on your system. Break Anything does not install or redistribute
them.

| Tool | License | Used by |
| --- | --- | --- |
| Trivy (Aqua Security) | Apache-2.0 | `image` scan |
| Grype (Anchore) | Apache-2.0 | planned image/second-opinion scan |
| Semgrep | LGPL-2.1 (CLI) | planned SAST |
| CodeQL | GitHub CodeQL terms | planned SAST (deep) |
| gitleaks | MIT | planned secret-scan backend |
| OWASP ZAP | Apache-2.0 | planned DAST |
| Nuclei (ProjectDiscovery) | MIT | planned template scan |
| Slither (Trail of Bits) | AGPL-3.0 | planned smart-contract scan |
| checkov (Prisma/Bridgecrew) | Apache-2.0 | planned IaC scan |

## Data sources

| Source | Terms | Used by |
| --- | --- | --- |
| OSV.dev | CC-BY-4.0 / per-entry | `deps` CVE lookup |
| FIRST.org EPSS | FIRST EPSS terms (free) | `deps` exploit-probability enrichment |
| GitHub Advisory Database | CC-BY-4.0 | via OSV |
| CISA KEV | U.S. public domain | planned KEV enrichment |

If you add a tool or data source, record it here in the same PR.
