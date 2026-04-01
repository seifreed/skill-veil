# 0025: Continuous Boundary Discipline

## Status

Accepted

## Context

The remaining risk is no longer structural. It is gradual erosion:

- final-result modules re-importing observation concepts
- observation modules re-owning shared value objects
- combinatorial helpers becoming inline branching again
- tests and ADRs drifting behind small ownership changes

## Decision

We treat boundary discipline as continuous maintenance:

- every ownership change should add or tighten a guardrail
- every new combinatorial helper should land with a focused unit test
- ADRs should be updated whenever taxonomy meaning changes, not only on large refactors

## Consequences

This keeps the repo from regressing through many small “harmless” edits rather than one large
architectural failure.
