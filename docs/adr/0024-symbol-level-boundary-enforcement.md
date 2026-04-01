# 0024: Symbol-Level Boundary Enforcement

## Status

Accepted

## Context

The codebase already enforces module-level boundaries well. The remaining risk is smaller:
semantic drift through harmless-looking helper imports, taxonomy leakage, or inline combinatorial
logic that slowly re-couples modules.

## Decision

We push the enforcement one level further:

- `domain_types` owns only shared value objects
- `analysis_model` owns only observation taxonomy and observation aggregation
- `findings` owns only final findings, deduplication, summaries, and reporting surfaces
- combinatorial helper functions remain local to the module that owns the behavior

## Enforcement

We treat the following as first-class regressions:

1. importing shared value objects back into `analysis_model` ownership
2. importing observation taxonomy back into `findings`
3. moving report-facing concepts into `domain_types`
4. inlining helper logic back into larger combinatorial modules without tests

## Consequences

Future ownership changes must land with:

- architecture test updates
- focused unit tests
- ADR updates when the taxonomy meaning changes
