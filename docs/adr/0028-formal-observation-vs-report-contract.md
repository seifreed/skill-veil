# 0028. Formal Observation vs Report Contract

Date: 2026-03-31

## Status

Accepted

## Context

The remaining architectural risk is no longer missing layers. It is accidental drift between:

- shared value objects in `domain_types`
- intermediate observations in `analysis_model`
- report-facing summaries and outputs in `findings`

## Decision

We treat the observation/report split as a formal contract:

- `domain_types` owns reusable value objects only
- `analysis_model` owns observation taxonomy and normalization into findings
- `findings` owns final summaries, deduplication, scoring, and report-facing exports
- `findings/reporting` may depend on shared value objects, but never on observation taxonomy

Helper extraction in combinatorial modules is acceptable only when it reduces local density without
changing ownership.

## Consequences

- Any new shared/report-facing type must justify whether it belongs in `domain_types` or
  `findings`
- Observation types must not be re-exported into report-facing modules
- Architecture tests must fail fast when this contract drifts
