# Policy Presets

`skill-veil` ships with lightweight CLI presets for common enforcement modes:

- `local`
  - no extra constraints
  - intended for interactive review
- `ci`
  - enables compact text output
  - defaults to the `team` profile if no profile was set
  - limits displayed findings per file
- `strict`
  - compact output
  - defaults to the `enterprise` profile
  - sets stronger fail and reporting thresholds
- `enterprise`
  - compact output
  - defaults to the `enterprise` profile
  - intended for large repositories where summary-first output matters

Examples:

```bash
skill-veil scan-package . --preset ci --format text
skill-veil scan-package . --preset strict --format text
skill-veil scan-package . --preset enterprise --format json --policy .skill-veil/policy.yaml
```
