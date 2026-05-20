# JSON Report Schema v3

`skill-veil` exposes a JSON report intended for CI pipelines, dataset triage,
and downstream tooling.

This document describes the current enriched report contract used by:

- `scan`
- `scan-file`
- `scan-package`
- `scan-dataset`

The top-level serialized type is `JsonReport` from
[policy/reports.rs](../crates/skill-veil-core/src/policy/reports.rs).

## Stability

Treat this as the current integration contract for the enriched report format.

Compatible changes may add fields. Existing documented fields should be treated
as stable unless a major version policy says otherwise. For versioning rules,
see [versioning.md](versioning.md).

## Top-Level Shape

Main fields:

- `skill_name`
- `skill_path`
- `extension_kind`
- `classification`
- `package_id`
- `identity_source`
- `structural_validity`
- `heuristic_score`
- `timestamp`
- `findings`
- `primary_findings`
- `supporting_findings`
- `summary`
- `primary_summary`
- `supporting_summary`
- `verdict`
- `verdict_report`
- `artifact_graph`
- `policies`
- `context_policies`
- `profile`
- `suppression_summary`
- `policy_audit`

## High-Value Fields for Integrators

If you do not need the full report, these are the most useful fields to consume
first:

- `verdict`
  Final package judgment:
  - `benign`
  - `suspicious`
  - `malicious`

- `verdict_report.verdict_reasons`
  Structured explanations for the final verdict.

- `verdict_report.root_cause_groups`
  Grouped causal clusters that explain *why* the package was classified that
  way and *where* the cause lives.

- `verdict_report.blast_radius_summary`
  Static impact summary of what the package appears able to reach or affect.

- `verdict_report.declared_permissions`
  Explicitly requested or implied high-level permissions derived from the
  package and its entry artifacts.

- `verdict_report.effective_capabilities`
  Capabilities inferred from actual behavior or linked artifacts, not just
  declared intent.

- `summary`, `primary_summary`, `supporting_summary`
  Risk and action summaries at whole-package, primary-artifact, and
  supporting-artifact scopes.

## `verdict_report`

`verdict_report` is the main field analysts and integrators should read.

Fields:

- `verdict`
  Repeats the final top-level verdict for convenience.

- `package_health`
  Hygiene/posture view:
  - `healthy`
  - `needs_review`
  - `elevated`

  This is **not** the same as the maliciousness verdict. A package can be
  `benign` with `package_health=needs_review`.

- `hygiene_summary`
  Counts and top hygiene-related rules without forcing those signals to be read
  as malware by default.

- `declared_permissions`
  Enumerated permissions inferred from docs/manifests, such as:
  - `browser_full`
  - `file_write`
  - `shell_exec`
  - `network_access`
  - `secrets_access`
  - `o_auth_scopes`

- `effective_capabilities`
  String list of capabilities inferred from behavior and artifacts, for example:
  - `network_access`
  - `process_execution`
  - `secret_access`
  - `persistence_surface`
  - `host_filesystem_access`

- `blast_radius_summary`
  Static impact summary with:
  - `level`
  - `factors`
  - `network_targets`
  - `declared_permissions`

- `verdict_reasons`
  Ordered reasons behind the final package verdict.

- `root_cause_groups`
  Grouped causes with scope, category, signal class, strongest action and
  representative rules.

- `top_risk_drivers`
  Aggregated scoring factors that contributed most to the final result.

## `blast_radius_summary`

Purpose:
- explain potential impact, not just detection
- make it easy to answer “how much could this package touch?”

Fields:

- `level`
  - `low`
  - `medium`
  - `high`

- `factors`
  Human-readable factors that raised blast radius, such as:
  - outbound network access
  - process execution
  - secret access
  - inbound surface

- `network_targets`
  Extracted high-risk targets when available, such as:
  - remote hosts
  - internal IPs
  - metadata endpoints

- `declared_permissions`
  The same permission enum values repeated here when they contributed directly
  to blast radius.

## `declared_permissions`

Purpose:
- summarize what the package says it wants or assumes it can do
- model permission overreach and scope abuse

This field is derived statically from:
- entry artifacts
- MCP manifests
- scripts
- package manifests
- related docs or prompts when they explicitly request privileged access

Use it for:
- policy gating
- blast-radius display
- capability/permission mismatch checks

## `effective_capabilities`

Purpose:
- summarize what the package appears able to do in practice
- complement `declared_permissions`

Unlike `declared_permissions`, these values are behavior-oriented and come from
findings and artifact analysis.

Typical examples:
- `network_access`
- `filesystem_write`
- `process_execution`
- `secret_access`
- `persistence_surface`
- `inbound_surface`

Use it for:
- analyst triage
- compound verdict logic
- downstream risk scoring

## `root_cause_groups`

Purpose:
- explain the final classification without forcing consumers to inspect every
  finding one by one

Fields:

- `scope`
  Where the issue lives:
  - `agent_entrypoint`
  - `package_root_artifact`
  - `supporting_artifact`

- `category`
  Threat category, for example:
  - `remote_exec`
  - `data_exfiltration`
  - `autonomy_escalation`
  - `scope_creep`

- `signal_class`
  How to interpret the signal:
  - `hygiene`
  - `review_signal`
  - `suspicious_package_behavior`
  - `malicious_behavior`

- `strongest_action`
  Strongest recommended action seen in the group.

- `representative_rules`
  Rule IDs that best explain the group.

- `finding_count`
  Number of findings merged into the group.

Use `root_cause_groups` as the main explanation layer for dashboards, PR
comments, dataset triage, or policy summaries.

## Suggested Consumption Order

For most integrations, consume the report in this order:

1. `package_id`
2. `skill_path`
3. `verdict`
4. `verdict_report.package_health`
5. `verdict_report.root_cause_groups`
6. `verdict_report.blast_radius_summary`
7. `verdict_report.declared_permissions`
8. `verdict_report.effective_capabilities`
9. `summary`

## Example

See:

- [json-report-v3-example.json](examples/json-report-v3-example.json)
