# Benchmark Dashboard

## Current Corpus

- Samples: 35
- Precision: 0.75
- Recall: 0.88
- False positive rate: 0.28
- Accuracy: 0.80
- Exact label accuracy: 0.69
- Deduplicated findings removed: 0

- Verdicts: benign=15 suspicious=8 malicious=12
- Findings by scope: primary=104 supporting=0

### Coverage by Label

- `benign`: 18
- `malicious`: 9
- `suspicious`: 8

### Coverage by Focus Category

- `autonomy_escalation`: 3
- `data_exfiltration`: 2
- `persistent_prompt_tampering`: 2
- `remote_exec`: 4
- `scope_creep`: 2
- `social_manipulation`: 2
- `supply_chain`: 2
- `tool_abuse`: 6

### Coverage by Attack Family

- `autonomy_bypass`: 5
- `exfiltration`: 2
- `mcp_remote_risk`: 4
- `remote_exec`: 3
- `scope_abuse`: 2
- `social_manipulation`: 2
- `supply_chain`: 2
- `tool_abuse`: 1
- `webhook_risk`: 2

### Family Metrics

| Family | Samples | Precision | Recall | FPR | Exact Label | Approval | Block |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| autonomy_bypass | 5 | 1.00 | 0.75 | 0.00 | 0.80 | 20 | 50 |
| exfiltration | 2 | 0.00 | 0.00 | 0.00 | 0.50 | 20 | 50 |
| mcp_remote_risk | 4 | 0.75 | 1.00 | 1.00 | 0.50 | 20 | 50 |
| remote_exec | 3 | 0.67 | 1.00 | 1.00 | 0.67 | 10 | 90 |
| scope_abuse | 2 | 0.50 | 1.00 | 1.00 | 0.00 | 32 | 34 |
| social_manipulation | 2 | 1.00 | 1.00 | 0.00 | 1.00 | 20 | 50 |
| supply_chain | 2 | 1.00 | 1.00 | 0.00 | 0.50 | 10 | 56 |
| tool_abuse | 1 | 1.00 | 1.00 | 0.00 | 1.00 | 20 | 50 |
| webhook_risk | 2 | 0.50 | 1.00 | 1.00 | 0.00 | 44 | 46 |

### Threshold Recommendation

- Approval: 20 -> 32
- Block: 50 -> 44
- Rationale: Selected thresholds using a weighted objective that prefers low false-positive rate, preserves recall, and penalizes label jumps around benign and suspicious samples (score 0.570).

### Strongest Signal Pairs

- `behavior+credential_exposure`: findings=1 observed_precision=1.00 recommended_confidence=0.47
- `behavior+privilege_escalation`: findings=1 observed_precision=1.00 recommended_confidence=0.47
- `behavior+remote_exec`: findings=14 observed_precision=0.86 recommended_confidence=0.71
- `behavior+supply_chain`: findings=4 observed_precision=0.75 recommended_confidence=0.53
- `behavior+tool_abuse`: findings=2 observed_precision=1.00 recommended_confidence=0.56
- `context+autonomy_escalation`: findings=3 observed_precision=1.00 recommended_confidence=0.61
- `context+persistent_prompt_tampering`: findings=1 observed_precision=1.00 recommended_confidence=0.47
- `context+scope_creep`: findings=49 observed_precision=0.63 recommended_confidence=0.65

## Release History

| Release | Generated | Precision | Recall | FPR | Accuracy | Samples |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| dev-2026-03-11 | 2026-03-11 | 1.00 | 1.00 | 0.00 | 1.00 | 23 |
| dev-family | 2026-03-11 | 0.75 | 0.88 | 0.28 | 0.80 | 35 |

### Latest Delta

- Precision delta: -0.25
- Recall delta: -0.12
- FPR delta: +0.28
- Accuracy delta: -0.20
