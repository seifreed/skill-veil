# ADR 0010: Reasoning Module Split

## Status

Accepted

## Context

`verdict/reasoning.rs` had grown into a mixed module responsible for:

- explainability assembly
- top-reason derivation
- compound verdict detection
- composite/provenance risk amplification

That concentration made it harder to enforce semantic ownership and to add targeted tests.

## Decision

We keep `verdict/reasoning.rs` as a thin routing facade and split responsibilities into:

- `reasoning/explainability.rs`
- `reasoning/top_reasons.rs`
- `reasoning/compounds.rs`
- `reasoning/risk.rs`
- `reasoning/model.rs`

`reasoning/model.rs` owns local value objects for score composition, including:

- `HeuristicSeverity`
- `CalibrationAdjustment`
- `RiskContributionSpec`

## Consequences

- Reasoning semantics are easier to test in isolation.
- The verdict facade stays thin and does not accumulate score-composition logic.
- Architecture tests can now assert ownership boundaries for each reasoning concern.
- Future extensions should add submodules under `verdict/reasoning/` instead of regrowing the
  facade.
