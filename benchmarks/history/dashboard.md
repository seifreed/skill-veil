# Benchmark Dashboard

## Current Corpus

- Samples: 41
- Precision: 0.77
- Recall: 0.85
- False positive rate: 0.24
- Accuracy: 0.80
- Exact label accuracy: 0.73
- Deduplicated findings removed: 0

- Verdicts: benign=19 suspicious=10 malicious=12
- Findings by scope: primary=110 supporting=0

### Coverage by Label

- `benign`: 21
- `malicious`: 10
- `suspicious`: 10

### Coverage by Focus Category

- `autonomy_escalation`: 3
- `data_exfiltration`: 3
- `persistent_prompt_tampering`: 2
- `remote_exec`: 5
- `scope_creep`: 3
- `social_manipulation`: 2
- `supply_chain`: 2
- `tool_abuse`: 9

### Coverage by Attack Family

- `autonomy_bypass`: 5
- `exfiltration`: 3
- `mcp_remote_risk`: 6
- `remote_exec`: 3
- `scope_abuse`: 2
- `social_manipulation`: 2
- `supply_chain`: 2
- `tool_abuse`: 1
- `webhook_risk`: 5

### Family Metrics

| Family | Samples | Precision | Recall | FPR | Exact Label | Approval | Block |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| autonomy_bypass | 5 | 1.00 | 0.75 | 0.00 | 0.60 | 20 | 50 |
| exfiltration | 3 | 1.00 | 0.50 | 0.00 | 0.67 | 20 | 50 |
| mcp_remote_risk | 6 | 0.67 | 1.00 | 1.00 | 0.33 | 20 | 50 |
| remote_exec | 3 | 0.67 | 1.00 | 1.00 | 0.67 | 10 | 86 |
| scope_abuse | 2 | 0.00 | 0.00 | 0.00 | 0.50 | 10 | 30 |
| social_manipulation | 2 | 1.00 | 1.00 | 0.00 | 1.00 | 20 | 50 |
| supply_chain | 2 | 1.00 | 1.00 | 0.00 | 1.00 | 10 | 52 |
| tool_abuse | 1 | 1.00 | 1.00 | 0.00 | 1.00 | 20 | 50 |
| webhook_risk | 5 | 0.50 | 1.00 | 0.67 | 0.60 | 22 | 80 |

### Families Needing Tuning

- `mcp_remote_risk`: exact_label=0.33 fpr=1.00 thresholds=20→50
- `scope_abuse`: exact_label=0.50 fpr=0.00 thresholds=10→30
- `webhook_risk`: exact_label=0.60 fpr=0.67 thresholds=22→80
- `autonomy_bypass`: exact_label=0.60 fpr=0.00 thresholds=20→50

### Threshold Recommendation

- Approval: 20 -> 28
- Block: 50 -> 80
- Rationale: Selected thresholds using a weighted objective that prefers low false-positive rate, preserves recall, and penalizes label jumps around benign and suspicious samples (score 0.502).

### Strongest Signal Pairs

- `behavior+credential_exposure`: findings=2 observed_precision=1.00 recommended_confidence=0.56
- `behavior+data_exfiltration`: findings=1 observed_precision=1.00 recommended_confidence=0.47
- `behavior+privilege_escalation`: findings=1 observed_precision=1.00 recommended_confidence=0.47
- `behavior+remote_exec`: findings=19 observed_precision=0.84 recommended_confidence=0.72
- `behavior+supply_chain`: findings=6 observed_precision=0.67 recommended_confidence=0.53
- `behavior+tool_abuse`: findings=1 observed_precision=1.00 recommended_confidence=0.47
- `context+autonomy_escalation`: findings=3 observed_precision=1.00 recommended_confidence=0.61
- `context+persistent_prompt_tampering`: findings=1 observed_precision=1.00 recommended_confidence=0.47

## Release History

| Release | Generated | Precision | Recall | FPR | Accuracy | Samples |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| dev-2026-03-11 | 2026-03-11 | 1.00 | 1.00 | 0.00 | 1.00 | 23 |
| dev-family | 2026-03-11 | 0.75 | 0.88 | 0.28 | 0.80 | 35 |
| local-dev | 2026-03-12 | 0.77 | 0.85 | 0.24 | 0.80 | 41 |

### Latest Delta

- Precision delta: +0.02
- Recall delta: -0.03
- FPR delta: -0.04
- Accuracy delta: +0.00
