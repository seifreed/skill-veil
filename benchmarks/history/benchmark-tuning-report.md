# Benchmark Tuning Report

## Global Recommendation

- Approval threshold: 20 -> 32
- Block threshold: 50 -> 44
- Rationale: Selected thresholds using a weighted objective that prefers low false-positive rate, preserves recall, and penalizes label jumps around benign and suspicious samples (score 0.570).

## Family Recommendations

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

### autonomy_bypass

- Samples: 5
- Precision: 1.00
- Recall: 0.75
- False positive rate: 0.00
- Exact label accuracy: 0.80
- Recommended thresholds: approval 20 block 50
- Rationale: Selected thresholds using a weighted objective that prefers low false-positive rate, preserves recall, and penalizes label jumps around benign and suspicious samples (score 0.762).

### exfiltration

- Samples: 2
- Precision: 0.00
- Recall: 0.00
- False positive rate: 0.00
- Exact label accuracy: 0.50
- Recommended thresholds: approval 20 block 50
- Rationale: Selected thresholds using a weighted objective that prefers low false-positive rate, preserves recall, and penalizes label jumps around benign and suspicious samples (score 0.080).

### mcp_remote_risk

- Samples: 4
- Precision: 0.75
- Recall: 1.00
- False positive rate: 1.00
- Exact label accuracy: 0.50
- Recommended thresholds: approval 20 block 50
- Rationale: Selected thresholds using a weighted objective that prefers low false-positive rate, preserves recall, and penalizes label jumps around benign and suspicious samples (score 0.182).

### remote_exec

- Samples: 3
- Precision: 0.67
- Recall: 1.00
- False positive rate: 1.00
- Exact label accuracy: 0.67
- Recommended thresholds: approval 10 block 90
- Rationale: Selected thresholds using a weighted objective that prefers low false-positive rate, preserves recall, and penalizes label jumps around benign and suspicious samples (score 0.157).

### scope_abuse

- Samples: 2
- Precision: 0.50
- Recall: 1.00
- False positive rate: 1.00
- Exact label accuracy: 0.00
- Recommended thresholds: approval 32 block 34
- Rationale: Selected thresholds using a weighted objective that prefers low false-positive rate, preserves recall, and penalizes label jumps around benign and suspicious samples (score 0.900).

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
- Exact label accuracy: 0.50
- Recommended thresholds: approval 10 block 56
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

- Samples: 2
- Precision: 0.50
- Recall: 1.00
- False positive rate: 1.00
- Exact label accuracy: 0.00
- Recommended thresholds: approval 44 block 46
- Rationale: Selected thresholds using a weighted objective that prefers low false-positive rate, preserves recall, and penalizes label jumps around benign and suspicious samples (score 0.890).

