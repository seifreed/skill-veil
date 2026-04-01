# 0027. Granular Boundary Ownership

Date: 2026-03-31

## Status

Accepted

## Context

The major splits are already done. The remaining architectural risk is gradual ownership drift in
small helpers and report-facing value objects.

## Decision

We enforce the following granular ownership rules:

- `domain_types` owns reusable shared value objects, including inventory/report-facing structs
- `analysis_model` owns observation taxonomy and observation-to-finding normalization only
- `findings` owns final findings, deduplication, summaries, reporting, and selected reexports
- `reasoning/explainability`, `reasoning/risk`, `provenance/inventory`, and `network/relations`
  may add local helpers, but must not absorb cross-layer ownership

Any refinement that changes helper placement or value-object ownership must update:

- architecture tests
- focused unit tests
- ADRs when the contract changes materially

## Consequences

- Helper extraction is acceptable only when it reduces local combinatorial density
- Shared value objects must not drift back into observation or final-assembly modules
- Boundary regressions should fail in tests instead of relying on reviewer memory
