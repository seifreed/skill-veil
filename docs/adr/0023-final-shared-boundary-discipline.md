# 0023: Final Shared Boundary Discipline

## Status

Accepted

## Context

The codebase already has strong architecture tests, explicit ownership, and split modules for the
main reasoning, provenance, network, and reporting flows.

At this stage, the main risk is semantic drift:

- shared value objects drifting back out of `domain_types`
- observation concepts drifting into `findings`
- final scoring/report artifacts drifting into `analysis_model`
- small combinatorial helpers being inlined back into larger modules

## Decision

We keep the final boundary strict:

- `domain_types` owns reusable value objects only
- `analysis_model` owns observation-layer evidence only
- `findings` owns final findings, deduplication, summaries, and reporting-facing scoring artifacts
- combinatorial helpers stay local to the module that owns the behavior

## Enforcement

Every ownership change must update:

1. architecture tests
2. focused unit tests around the affected helper logic
3. the ADR set when the taxonomy changes

## Consequences

The remaining work is no longer structural rescue. It is discipline against boundary regression.
