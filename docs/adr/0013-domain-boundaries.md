# ADR 0013: Domain Boundary Ownership

## Status

Accepted

## Context

The remaining conceptual drift in `skill-veil-core` was concentrated around three modules:

- `domain_types`, which started as a shared value-object home
- `analysis_model`, which models intermediate observations
- `findings`, which exposes final findings and report-facing summaries

Without a stricter ownership rule, provenance, reasoning, and reporting concepts could
accidentally migrate back into `findings` or `analysis_model`.

## Decision

We fix ownership as follows:

- `domain_types`
  - Owns reusable domain value objects shared by multiple subsystems.
  - Examples: heuristic severity, calibration adjustment, provenance trust, package identity,
    manifest inventory entries, lockfile inventory entries, remote relation kinds.
  - Must not own parsing, final findings, report summaries, or intermediate observation batches.

- `analysis_model`
  - Owns intermediate detector/analyzer observations before final deduplicated findings exist.
  - Examples: `ObservationSource`, `ObservationFinding`, `ObservedEvidence`, `ObservationBatch`.
  - Must not own scoring, risk factors, explainability summaries, or report output types.

- `findings`
  - Owns final findings, deduplication, scoring summaries, and report-facing output models.
  - Examples: `Finding`, `FindingSummary`, `RiskFactor`, `VerdictExplainability`,
    `ProvenanceSummary`.
  - May re-export selected `domain_types` for API stability, but must not re-own those concepts.

## Consequences

- Shared domain concepts can evolve without being tied to reporting concerns.
- Observation-layer code can remain lightweight and detector-focused.
- Reporting/scoring remains anchored to the final finding layer instead of leaking into shared
  domain modules.
- Architecture tests should fail if ownership drifts again.
