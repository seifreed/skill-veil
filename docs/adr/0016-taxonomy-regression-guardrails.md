# ADR 0016: Taxonomy Regression Guardrails

## Status

Accepted

## Context

The remaining risk in `skill-veil-core` is regression rather than missing structure. Shared domain
types, observation-layer models, and final reporting artifacts now have clear ownership, but that
ownership can drift if new code bypasses the existing boundaries.

## Decision

We treat taxonomy and architecture ownership as test-enforced contracts:

- `domain_types` owns reusable shared value objects only
- `analysis_model` owns observation-layer models only
- `findings` and `findings/reporting` own final findings, scoring, and report-facing summaries
- parsing, regex, and scoring stay confined to the explicit modules that already own them
- thin facade modules remain size-bounded and dependency-bounded

## Consequences

- Architectural drift becomes a failing test instead of a review judgment call
- Shared domain taxonomy remains stable even as new detectors or verdict logic are added
- Future refactors can stay local because ownership boundaries remain explicit and executable
