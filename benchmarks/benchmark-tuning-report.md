# Benchmark Tuning Report

## Global Recommendation

- Approval threshold: 20 -> 10
- Block threshold: 50 -> 30
- Rationale: Selected thresholds using a weighted objective that prefers low false-positive rate, preserves recall, and penalizes label jumps around benign and suspicious samples (score -2.666).

