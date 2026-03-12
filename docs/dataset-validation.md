# Dataset Validation

`skill-veil` keeps the repository lightweight and does not ship large third-party
datasets in Git, but the CLI is designed to validate against them locally.

## Recommended workflow

1. Acquire or mount the external dataset locally.
2. Run a package-level verdict scan:

```bash
skill-veil scan-dataset ./dataset \
  --dataset-view verdicts \
  --analyst-summary \
  --preset local \
  --format text
```

3. For machine-readable triage:

```bash
skill-veil scan-dataset ./dataset \
  --dataset-view verdicts \
  --format json \
  --output dataset-verdicts.json
```

## What to review

Focus on:

- `malicious` packages:
  - validate that the top rule and strongest reason are defensible
- `suspicious` packages:
  - decide whether they are true review cases or over-escalation
- `blast_radius`:
  - check whether declared permissions and effective capabilities line up with
    the verdict
- `package_health`:
  - treat this as hygiene/posture, not as proof of malice by itself

## Stable fields for external analysis

The compact verdict view is designed for repeatable dataset comparison:

- `package_id`
- `final_verdict`
- `package_health`
- `blast_radius`
- `declared_permissions`
- `top_rule`
- `strongest_reason`

## Suggested comparison loop

After changing rules or verdict logic:

1. run `scan-dataset --dataset-view verdicts --format json`
2. diff the new JSON against the previous run
3. manually review:
   - new `malicious`
   - dropped `malicious`
   - large jumps in one rule family
4. rerun the benchmark corpus to confirm the detector did not improve one family
   while regressing another

## Keep datasets out of Git

Recommended local-only paths:

- `dataset/`
- `dataset_extracted/`
- `dataset_vt_new/`

Keep these directories outside version control when running local dataset validation.
