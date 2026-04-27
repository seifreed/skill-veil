# Benchmark Dashboard

## Current Corpus

- Samples: 2976
- Precision: 1.00
- Recall: 0.91
- False positive rate: 0.00
- Accuracy: 0.91
- Exact label accuracy: 0.56
- Deduplicated findings removed: 25866

- Verdicts: benign=253 suspicious=1051 malicious=1672
- Findings by scope: primary=17686 supporting=21967

### Coverage by Label

- `malicious`: 2976

### Threshold Recommendation

- Approval: 20 -> 10
- Block: 50 -> 30
- Rationale: Selected thresholds using a weighted objective that prefers low false-positive rate, preserves recall, and penalizes label jumps around benign and suspicious samples (score -2.797).

### Strongest Signal Pairs

- `behavior+credential_exposure`: findings=4349 observed_precision=1.00 recommended_confidence=0.95
- `behavior+data_exfiltration`: findings=3070 observed_precision=1.00 recommended_confidence=0.95
- `behavior+obfuscation`: findings=2331 observed_precision=1.00 recommended_confidence=0.95
- `behavior+persistent_prompt_tampering`: findings=2 observed_precision=1.00 recommended_confidence=0.56
- `behavior+privilege_escalation`: findings=388 observed_precision=1.00 recommended_confidence=0.94
- `behavior+remote_exec`: findings=2509 observed_precision=1.00 recommended_confidence=0.95
- `behavior+social_manipulation`: findings=173 observed_precision=1.00 recommended_confidence=0.94
- `behavior+supply_chain`: findings=1931 observed_precision=1.00 recommended_confidence=0.95

## Release History

| Release | Generated | Precision | Recall | FPR | Accuracy | Samples |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| vt-after-p1-1744 | 2026-04-27 | 1.00 | 0.91 | 0.00 | 0.91 | 2976 |
| vt-baseline-test | 2026-04-27 | 1.00 | 0.91 | 0.00 | 0.91 | 2976 |

### Latest Delta

- Precision delta: +0.00
- Recall delta: -0.01
- FPR delta: +0.00
- Accuracy delta: -0.01
