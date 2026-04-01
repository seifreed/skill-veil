# ADR 0009: Reasoning And Risk Composition

## Status

Accepted

## Context

The verdict pipeline already separated capabilities, provenance, summaries, and reasoning, but
the reasoning layer still encoded composite risk composition as ad hoc tuples and inline numeric
weights. That made it harder to preserve a stable vocabulary for:

- heuristic severity
- provenance amplification
- composite capability amplification
- explainability wording

## Decision

We model reasoning-side composition with small internal value objects:

- `HeuristicSeverity`
- `RiskContributionSpec`

These objects stay inside `verdict/reasoning.rs` because they represent score-composition policy,
not user-facing API types.

We also keep provenance-derived amplification as a first-class reasoning input instead of a hidden
numeric adjustment. `provenance_factor_spec(...)` is the explicit seam between provenance trust and
verdict scoring.

## Consequences

- Risk composition is easier to test in isolation.
- The wording and contribution mapping for composite factors and provenance factors now share one
  contract.
- The verdict facade can stay thin while reasoning owns the semantics of amplification.
- Future changes to scoring should extend `RiskContributionSpec` or split reasoning further, rather
  than reintroducing tuple-based factor construction in the facade.
