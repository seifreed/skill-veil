# Policy Model

`skill-veil` applies policy in this order:

1. rule evaluation produces findings with severity, category, evidence, remediation, and a default `recommended_action`
2. waivers suppress matching findings
3. baseline suppresses accepted findings that are already known
4. policy overrides can change the `recommended_action` of the remaining findings
5. profile and graph-derived context policies can still escalate the final decision

This precedence is intentional:

- `waiver` and `baseline` remove noise before enforcement
- `override` changes action without hiding the finding
- `profile` defines organization defaults
- contextual escalation still wins if runtime blast radius is higher than the rule alone suggests

This precedence is now exposed in both text output and JSON reports through
`policy_audit.precedence_order`.

## Schemas

All persisted policy-related files use:

```text
schema_version: skill-veil.dev/v1alpha1
```

Current persisted files:

- policy file
- baseline file
- waivers file

## Policy File

Example:

```yaml
schema_version: skill-veil.dev/v1alpha1
profiles:
  team:
    fail_on: high
    context_actions:
      - context: network
        action: require_approval
      - context: secrets
        action: block
overrides:
  - id: compose-latest-reviewed
    rule_id: MANIFEST_DOCKER_COMPOSE_LATEST_TAG
    artifact_path: docker-compose.yml
    action: require_approval
    reason: reviewed in deployment pipeline
  - id: outbound-default-block
    context: external_comms
    action: block
    reason: outbound communication requires explicit exception
    expires_at: 2026-12-31T00:00:00Z
```

Supported override selectors:

- `id`
- `rule_id`
- `artifact_path`
- `context`
- `expires_at`

When multiple overrides match, `skill-veil` picks the most specific one. If specificity ties, the later entry wins.

`skill-veil policy validate policy.yaml` validates this schema before use.

## Reporting

JSON reports now include:

- `policy_audit.precedence_order`
- `policy_audit.effective_fail_on`
- `policy_audit.applied_overrides`

This makes override behavior auditable in CI and review workflows.

## Baseline

Create a baseline:

```bash
skill-veil baseline create report.json --output .skill-veil/baseline.json
```

Update a baseline safely:

```bash
skill-veil baseline update report.json --baseline .skill-veil/baseline.json --output .skill-veil/baseline.json
```

If the update would add new findings, the command fails unless you pass:

```bash
--allow-new-findings
```

That guard is there to reduce accidental baseline creep.

## Waivers

Example:

```yaml
schema_version: skill-veil.dev/v1alpha1
waivers:
  - rule_id: TEST_RULE
    artifact_path: install.sh
    context: install
    reason: approved for internal build environment
    expires_at: 2026-12-31T00:00:00Z
```

Validation:

```bash
skill-veil waivers validate waivers.yaml
```

Rules:

- a waiver must define at least one selector
- duplicate waivers are rejected
- expired waivers do not match

## Diff Policies

CI-friendly diff:

```bash
skill-veil diff prev.json curr.json --ci-summary
```

Fail if there are new active findings:

```bash
skill-veil diff prev.json curr.json --fail-on new-active
```

Fail only if the new findings are already `block`:

```bash
skill-veil diff prev.json curr.json --fail-on new-blocking
```

## Recommended Presets

For larger organizations, use one of the scan presets:

- `--preset ci`: compact output, `team` profile defaults
- `--preset strict`: compact output, enterprise-oriented fail thresholds
- `--preset enterprise`: compact output, enterprise profile, reduced text noise
