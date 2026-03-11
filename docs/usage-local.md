# Usage: Local

This guide is for local review, triage, and policy maintenance.

## 1. Scan a single entrypoint

```bash
skill-veil scan-file examples/malicious-skill/SKILL.md
```

Use this when you want strict `SKILL.md` behavior and do not want README-like
documents promoted automatically.

## 2. Scan a package

```bash
skill-veil scan-package examples/suspicious-skill
```

Use this when you want:

- explicit skill entrypoints
- package manifests
- referenced artifacts
- policy/context-aware reporting

## 3. Produce machine-readable reports

```bash
skill-veil scan-package . --format json --output current.json
skill-veil scan-package . --format sarif --output current.sarif
```

Recommended uses:

- `json` for automation, baseline, waivers, and diff
- `sarif` for GitHub Code Scanning

## 4. Create and maintain a baseline

Create:

```bash
skill-veil baseline create current.json --output .skill-veil/baseline.json
```

Update safely:

```bash
skill-veil baseline update current.json \
  --baseline .skill-veil/baseline.json \
  --output .skill-veil/baseline.json
```

If the update would add new findings, the command fails. Accept the change only
when that is intentional:

```bash
skill-veil baseline update current.json \
  --baseline .skill-veil/baseline.json \
  --output .skill-veil/baseline.json \
  --allow-new-findings
```

## 5. Validate waivers

```bash
skill-veil waivers validate .skill-veil/waivers.yaml
skill-veil policy validate .skill-veil/policy.yaml
```

Validation checks:

- schema version
- duplicate entries
- missing selectors

## 6. Review policy-only output

```bash
skill-veil scan-package . --explain-policy
```

Useful when you want:

- final action
- escalation reasons
- context policies
- suppression summary

## 7. Benchmark changes against the labeled corpus

```bash
skill-veil benchmark crates/skill-veil-core/tests/fixtures/regression_corpus.yaml --format text
```

This is useful before changing:

- rules
- findings scoring
- policy escalation
- discovery heuristics
