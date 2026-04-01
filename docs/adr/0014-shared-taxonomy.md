# ADR 0014: Shared Taxonomy Ownership

## Status

Accepted

## Context

`skill-veil-core` now has a stronger split between shared domain types, observation-layer models,
and final reporting artifacts. The remaining risk is not missing structure but conceptual drift:
future changes could reintroduce shared provenance, inventory, or scoring concepts into the wrong
module.

## Decision

We fix the taxonomy as follows:

- `domain_types`
  - Owns reusable domain value objects shared across subsystems.
  - Examples: provenance trust, publisher consistency, domain reputation, inventory entries,
    calibration adjustment, heuristic severity, package identity, remote relation kind.

- `analysis_model`
  - Owns intermediate observations emitted by detectors, analyzers, graph passes, or taint/provenance
    stages before final deduplicated findings exist.
  - Examples: `ObservationSource`, `ObservationFinding`, `ObservedEvidence`, `ObservationBatch`.

- `findings`
  - Owns final findings, deduplication, scoring, explainability summaries, and report-facing output.
  - May re-export selected shared value objects for API continuity, but must not redefine them.

- `reasoning`, `provenance`, and `network`
  - Own derived domain behavior and assembly logic on top of shared value objects.
  - Must consume shared taxonomy instead of redefining it.

## Consequences

- Shared concepts remain portable and testable outside reporting code.
- Observation-layer logic stays distinct from final scoring and verdict composition.
- Architecture tests can enforce concept ownership instead of only file size or dependency hygiene.
