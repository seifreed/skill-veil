# Verdict Model

`skill-veil` classifies the whole package, not only the top-level `SKILL.md`.

## Final verdict

Every scan result now exposes a package-level verdict:

- `benign`
- `suspicious`
- `malicious`

The verdict is derived from the full package:

- main agent entrypoint
- supporting scripts and referenced artifacts
- package manifests and lockfiles
- contextual graph capabilities

## Why a package can be malicious

A package can be `malicious` because of:

- clear malicious behavior in the main artifact
- clear malicious behavior in supporting artifacts
- dangerous workflow delegation such as remote fetch-and-exec
- graph escalation caused by risky runtime capabilities

A package should typically remain `suspicious` when the dominant evidence is:

- package hygiene
- weak supply-chain posture
- review-oriented signals without clear hostile behavior

## Artifact scopes

Each finding is assigned an artifact scope:

- `agent_entrypoint`
- `package_root_artifact`
- `supporting_artifact`

This keeps the final judgment separate from the location of the cause.

## Signal classes

Each finding is also classified into a coarse signal family:

- `hygiene`
- `suspicious_package_behavior`
- `malicious_behavior`
- `review_signal`

These classes are used to reduce noise from repetitive hygiene findings and to
reserve `malicious` for stronger causes.

## Verdict explanation

Reports include:

- `verdict`
- `verdict_reasons`
- `root_cause_groups`
- `top_risk_drivers`

The intended reading is:

1. read the final package verdict
2. read the top causal reasons
3. inspect the specific findings only if you need detail

## Operational interpretation

- `benign`: no strong hostile behavior found
- `suspicious`: risky package or mixed evidence, review is justified
- `malicious`: strong hostile behavior or a clearly dangerous delegated workflow
