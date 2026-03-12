# Benchmark Tuning Report

## Global Recommendation

- Approval threshold: 20 -> 28
- Block threshold: 50 -> 80
- Rationale: Selected thresholds using a weighted objective that prefers low false-positive rate, preserves recall, and penalizes label jumps around benign and suspicious samples (score 0.502).

## Family Recommendations

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

### autonomy_bypass

- Samples: 5
- Precision: 1.00
- Recall: 0.75
- False positive rate: 0.00
- Exact label accuracy: 0.60
- Recommended thresholds: approval 20 block 50
- Rationale: Selected thresholds using a weighted objective that prefers low false-positive rate, preserves recall, and penalizes label jumps around benign and suspicious samples (score 0.762).

### exfiltration

- Samples: 3
- Precision: 1.00
- Recall: 0.50
- False positive rate: 0.00
- Exact label accuracy: 0.67
- Recommended thresholds: approval 20 block 50
- Rationale: Selected thresholds using a weighted objective that prefers low false-positive rate, preserves recall, and penalizes label jumps around benign and suspicious samples (score 0.638).

### mcp_remote_risk

- Samples: 6
- Precision: 0.67
- Recall: 1.00
- False positive rate: 1.00
- Exact label accuracy: 0.33
- Recommended thresholds: approval 20 block 50
- Rationale: Selected thresholds using a weighted objective that prefers low false-positive rate, preserves recall, and penalizes label jumps around benign and suspicious samples (score 0.107).

### remote_exec

- Samples: 3
- Precision: 0.67
- Recall: 1.00
- False positive rate: 1.00
- Exact label accuracy: 0.67
- Recommended thresholds: approval 10 block 86
- Rationale: Selected thresholds using a weighted objective that prefers low false-positive rate, preserves recall, and penalizes label jumps around benign and suspicious samples (score 0.157).

### scope_abuse

- Samples: 2
- Precision: 0.00
- Recall: 0.00
- False positive rate: 0.00
- Exact label accuracy: 0.50
- Recommended thresholds: approval 10 block 30
- Rationale: Selected thresholds using a weighted objective that prefers low false-positive rate, preserves recall, and penalizes label jumps around benign and suspicious samples (score 0.890).

### social_manipulation

- Samples: 2
- Precision: 1.00
- Recall: 1.00
- False positive rate: 0.00
- Exact label accuracy: 1.00
- Recommended thresholds: approval 20 block 50
- Rationale: Selected thresholds using a weighted objective that prefers low false-positive rate, preserves recall, and penalizes label jumps around benign and suspicious samples (score 0.900).

### supply_chain

- Samples: 2
- Precision: 1.00
- Recall: 1.00
- False positive rate: 0.00
- Exact label accuracy: 1.00
- Recommended thresholds: approval 10 block 52
- Rationale: Selected thresholds using a weighted objective that prefers low false-positive rate, preserves recall, and penalizes label jumps around benign and suspicious samples (score 0.900).

### tool_abuse

- Samples: 1
- Precision: 1.00
- Recall: 1.00
- False positive rate: 0.00
- Exact label accuracy: 1.00
- Recommended thresholds: approval 20 block 50
- Rationale: Selected thresholds using a weighted objective that prefers low false-positive rate, preserves recall, and penalizes label jumps around benign and suspicious samples (score 0.900).

### webhook_risk

- Samples: 5
- Precision: 0.50
- Recall: 1.00
- False positive rate: 0.67
- Exact label accuracy: 0.60
- Recommended thresholds: approval 22 block 80
- Rationale: Selected thresholds using a weighted objective that prefers low false-positive rate, preserves recall, and penalizes label jumps around benign and suspicious samples (score 0.550).

