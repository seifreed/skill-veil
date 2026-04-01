# 0026. Formal Boundary Discipline

Date: 2026-03-31

## Status

Accepted

## Context

The codebase already split the major god modules and moved shared value objects into
`domain_types`. At this stage the remaining risk is not structural absence, but drift:

- `analysis_model` starts importing shared report-facing value objects
- `findings` starts re-owning observation concepts
- combinatorial helper modules quietly absorb scoring or unrelated ownership

## Decision

We treat boundary discipline as a near-formal contract:

- `domain_types` owns reusable value objects only
- `analysis_model` owns observation taxonomy and observation-to-finding normalization only
- `findings` owns final result shapes, deduplication, scoring summaries, and reporting-facing
  reexports
- `reasoning/explainability`, `provenance/inventory`, and `network/relations` may add local
  helpers, but must not absorb scoring ownership or cross-layer concepts

Every refinement pass must come with:

- stronger architecture tests
- focused unit tests for combinatorial helpers
- ADR updates when taxonomy or ownership boundaries are tightened

## Consequences

- The repo prefers explicit ownership checks over informal convention
- Small helper extractions are acceptable when they reduce combinatorial density without moving
  responsibilities
- Regressions in shared taxonomy should fail fast in architecture tests instead of relying on code
  review memory
