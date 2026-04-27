# Benchmark Dashboard

## Current Corpus

- Samples: 2976
- Precision: 1.00
- Recall: 0.91
- False positive rate: 0.00
- Accuracy: 0.91
- Exact label accuracy: 0.52
- Deduplicated findings removed: 25861

- Verdicts: benign=271 suspicious=1143 malicious=1562
- Findings by scope: primary=17308 supporting=21904

### Coverage by Label

- `malicious`: 2976

### Threshold Recommendation

- Approval: 20 -> 10
- Block: 50 -> 30
- Rationale: Selected thresholds using a weighted objective that prefers low false-positive rate, preserves recall, and penalizes label jumps around benign and suspicious samples (score -3.079).

### Strongest Signal Pairs

- `behavior+credential_exposure`: findings=4349 observed_precision=1.00 recommended_confidence=0.95
- `behavior+data_exfiltration`: findings=3045 observed_precision=1.00 recommended_confidence=0.95
- `behavior+obfuscation`: findings=2331 observed_precision=1.00 recommended_confidence=0.95
- `behavior+persistent_prompt_tampering`: findings=2 observed_precision=1.00 recommended_confidence=0.56
- `behavior+privilege_escalation`: findings=388 observed_precision=1.00 recommended_confidence=0.94
- `behavior+remote_exec`: findings=2509 observed_precision=1.00 recommended_confidence=0.95
- `behavior+social_manipulation`: findings=173 observed_precision=1.00 recommended_confidence=0.94
- `behavior+supply_chain`: findings=1931 observed_precision=1.00 recommended_confidence=0.95

## Release History

| Release | Generated | Precision | Recall | FPR | Accuracy | Samples |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| vt-baseline-test | 2026-04-27 | 1.00 | 0.91 | 0.00 | 0.91 | 2976 |
