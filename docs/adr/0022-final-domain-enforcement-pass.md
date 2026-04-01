# 0022: Final Domain Enforcement Pass

## Status

Accepted

## Context

The repo already has strong architectural seams and explicit ownership between `domain_types`,
`analysis_model`, `findings`, `reasoning`, `provenance`, and `network`.

At this stage, the main risk is regression by small convenience changes:

- observation concepts drifting back into `findings`
- shared value objects drifting back into `analysis_model`
- scoring helpers spreading outside `findings` and `reasoning/risk`
- explainability and provenance assembly modules accumulating inline combinatorial flow

## Decision

We keep the final ownership map explicit:

- `domain_types` owns shared cross-cutting value objects
- `analysis_model` owns intermediate observations only
- `findings` owns final findings, deduplication, and report-facing scoring artifacts
- `reasoning/risk` owns verdict risk composition helpers
- `reasoning/explainability/sources` owns source bucketing and contribution aggregation
- `reasoning/explainability/traces` owns trace assembly
- `provenance/inventory` owns graph ingestion and inventory normalization
- `network/relations` owns generic remote relation classification and link assembly

## Enforcement

The contract is protected by:

- architecture tests for exact imports and forbidden cross-layer concepts
- facade size limits for routing and assembly modules
- focused unit tests on extracted combinatorial helpers

## Consequences

Future ownership changes must update:

1. implementation
2. architecture tests
3. the relevant ADR

This keeps the repo from drifting back into fuzzy boundaries after the major refactor wave.
