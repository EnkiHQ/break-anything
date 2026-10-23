# MCP tool catalog

Break Anything exposes one consistent MCP interface. The public interface describes *what the
agent is trying to learn*; providers decide *how* to answer. Dynamic tools (those that send
traffic to a target) are disabled until an operator policy enables them and a per-run
authorization flag is passed.

Counts below are a design target. **Shipped in 0.1.0: `deps_scan`** (the dependency & supply
chain family — OSV lookup, reachability heuristic, EPSS enrichment, fix versions). The remaining
families are on the roadmap and land incrementally; the catalog shows the intended shape, not
what is already implemented.

| Tool family | Count | Examples | Default |
| --- | --- | --- | --- |
| Dependency & supply chain | 9 | `deps.scan`, `deps.reachability`, `deps.epss`, `deps.kev_status`, `deps.fix_versions`, `deps.graph`, `deps.sbom_export`, `deps.transitive_path`, `deps.license_check` | static, on |
| Static code analysis (SAST) | 8 | `sast.scan`, `sast.dataflow`, `sast.taint_trace`, `sast.authz_gaps`, `sast.deserialization`, `sast.ssrf`, `sast.injection`, `sast.rule_explain` | static, on |
| Secret exposure | 4 | `secrets.scan`, `secrets.history_scan`, `secrets.blast_radius`, `secrets.validate` | static, on |
| Container & image | 5 | `image.scan`, `image.layer_secrets`, `image.base_bump`, `image.misconfig`, `image.sbom` | static, on |
| Infrastructure as code | 5 | `iac.terraform`, `iac.kubernetes`, `iac.dockerfile`, `iac.cloudformation`, `iac.explain` | static, on |
| Reachability & exploitability | 4 | `exploit.reachability`, `exploit.rank`, `exploit.confirm`, `exploit.why_safe` | static, on |
| Web app dynamic (DAST) | 6 | `dast.spider`, `dast.active_scan`, `dast.nuclei`, `dast.auth_probe`, `dast.replay`, `dast.stop` | **dynamic, off** |
| API logic | 5 | `api.enumerate`, `api.idor_probe`, `api.authz_matrix`, `api.mass_assignment`, `api.poc_request` | **dynamic, off** |
| Evidence & PoC | 5 | `evidence.record`, `evidence.export`, `evidence.import`, `poc.build`, `poc.verify` | mixed |
| Remediation & handoff | 4 | `fix.plan`, `fix.suggest_patch`, `fix.mitigation`, `fix.handoff_patch_anything` | static, on |
| Workspace & session | 5 | `target.set`, `target.list`, `scan.status`, `scan.cancel`, `policy.show` | control |

## Authorization gates

Dynamic families (`dast.*`, `api.*`, and `poc.*` when it sends traffic) require:

```bash
export BRK_DYNAMIC_ENABLED=true
export BRK_AUTHORIZED_TARGETS_JSON='["http://localhost:3000","https://staging.example.internal"]'
```

A dynamic tool refuses any target not present in `BRK_AUTHORIZED_TARGETS_JSON`. There is no flag
that disables this check.

## Evidence envelope

Every tool returns a structured result with:

- `finding` — the weakness, with a stable ID;
- `provider` — which engine produced it (e.g. `semgrep`, `trivy`, `osv`);
- `exploitability` — `confirmed` | `reachable` | `present` | `not_reachable`, plus EPSS and KEV
  when available;
- `evidence` — file/line, data-flow, or the request/response that proves it;
- `remediation` — fix version, patch sketch, or mitigation;
- `limitations` — what this result does **not** establish.

## Manual MCP registration

```json
{
  "mcpServers": {
    "break-anything": {
      "command": "npx",
      "args": ["-y", "break-anything", "mcp"]
    }
  }
}
```
