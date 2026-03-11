# Dataset Validation - 2026-03-11

This report validates the current `skill-veil` detector against the local
VirusTotal-style dataset stored under `dataset/`.

## Command

```bash
cargo run -q -p skill-veil -- scan-dataset dataset \
  --dataset-view verdicts \
  --preset local \
  --format json
```

## Scope

- dataset packages discovered: `156`
- skipped packages: `8`
- decode warnings: `1`
- parse warnings: `0`

The `verdicts` view is package-aggregated. It is the right lens for asking:

- does this package look benign, suspicious, or malicious?
- which rule is driving the decision?
- is the cause in the main artifact or the supporting package?

## Baseline vs Current

Baseline here refers to the last validated dataset run before the Fase 11-18
expansion landed in the working tree.

| Metric | Baseline | Current | Delta |
| --- | ---: | ---: | ---: |
| suspicious packages | 2 | 21 | +19 |
| malicious packages | 6 | 30 | +24 |
| non-benign packages | 8 | 51 | +43 |

## Current Top Drivers

Top rules in non-benign packages:

| Rule | Count |
| --- | ---: |
| `DECLARED_PERMISSION_NETWORK_ACCESS` | 14 |
| `CAPABILITY_PERMISSION_MISMATCH` | 13 |
| `INTERNAL_NETWORK_ACCESS` | 13 |
| `SKILL_REMOTE_EXEC_CURL_BASH` | 6 |
| `OFFICIAL_MCP_NO_AUTH_REMOTE_ENDPOINT` | 3 |
| `UNSAFE_USER_CONTROLLED_EXEC_SHELL` | 1 |
| `PUBLIC_INBOUND_ENDPOINT` | 1 |

Top rules in `malicious` packages:

| Rule | Count |
| --- | ---: |
| `INTERNAL_NETWORK_ACCESS` | 13 |
| `SKILL_REMOTE_EXEC_CURL_BASH` | 6 |
| `CAPABILITY_PERMISSION_MISMATCH` | 5 |
| `DECLARED_PERMISSION_NETWORK_ACCESS` | 5 |
| `OFFICIAL_MCP_NO_AUTH_REMOTE_ENDPOINT` | 1 |

## What Clearly Still Works

The old strong signal remains intact:

- `SKILL_REMOTE_EXEC_CURL_BASH` still isolates the same family of clearly
  malicious packages.
- Those packages remain high-confidence `malicious` hits and should not be
  relaxed.

## What Regressed

The new signal families increased theoretical coverage, but in the real dataset
they currently over-escalate many packages:

1. `DECLARED_PERMISSION_NETWORK_ACCESS`
   - too many packages are flagged simply because they describe legitimate
     networked integrations.
   - this is useful for blast-radius reporting, but it is not sufficient on its
     own to justify `suspicious` or `malicious`.

2. `CAPABILITY_PERMISSION_MISMATCH`
   - the mismatch heuristic is still too keyword-driven.
   - many packages that ask for network/browser/secret access for integration
     workflows are landing in `suspicious` or `malicious` without clear hostile
     behavior.

3. `INTERNAL_NETWORK_ACCESS`
   - the current rule is too aggressive.
   - internal/local targets can indicate SSRF-like behavior, but in this dataset
     they also appear in benign or operational local integrations.
   - this rule should not currently drive `malicious` on its own.

## Representative False-Positive Candidates

These packages should be reviewed first when tuning the new families:

- `04d84a135b1a28437249a7d75eef4919045377a0dfdcb5e9524c652f4cefc294`
  - `malicious`
  - top rule: `INTERNAL_NETWORK_ACCESS`
- `110bc8da3f08fc2a34b7c2495b28bd9bae66b48503b8248c1f3916b91f8c2fab`
  - `malicious`
  - top rule: `INTERNAL_NETWORK_ACCESS`
- `14288a1292c483be3f38ce82019e77ccb1e84b45429b3026135abefd715f4787`
  - `malicious`
  - top rule: `CAPABILITY_PERMISSION_MISMATCH`
- `24cbad83254c1cf02111431e83c8112846d5bfe26ac419dbf5c45319aeaf6539`
  - `malicious`
  - top rule: `DECLARED_PERMISSION_NETWORK_ACCESS`
- `691e311687bd3c628540cd27469229120ba8326a3994f3983145053fe5ea49db`
  - `suspicious`
  - top rule: `DECLARED_PERMISSION_NETWORK_ACCESS`

## Conclusion

The validation shows two things clearly:

1. the new families are not only theoretical; they do fire on real packages.
2. they are currently too strong for production verdicting on this dataset.

Right now the high-confidence part of the detector remains:

- remote fetch + execute
- explicit malicious workflow patterns

The parts that still need tuning before they should drive verdicts strongly are:

- declared permission modeling
- capability mismatch
- internal network / SSRF-like fetch heuristics
- MCP no-auth remote endpoint severity

## Recommended Next Tuning

1. downgrade `DECLARED_PERMISSION_NETWORK_ACCESS` to blast-radius only unless
   combined with stronger behavior.
2. require stronger intent/behavior before `CAPABILITY_PERMISSION_MISMATCH`
   influences the final verdict.
3. downgrade `INTERNAL_NETWORK_ACCESS` from standalone `malicious` evidence to
   `suspicious` or `review_signal` unless paired with fetch/exec or exfil.
4. rerun the dataset after those changes and compare against this report.
