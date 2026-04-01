# ADR 0012: Shared Domain Value Objects

## Status

Accepted

## Context

Several value objects started life inside feature modules:

- heuristic severity and calibration inside `verdict/reasoning`
- package identity and lineage inside `verdict/provenance`
- remote relation kinds inside `artifact_analysis/network`

That was acceptable during the first round of splits, but it left cross-cutting concepts owned by
feature folders instead of the shared domain layer.

## Decision

We move the truly shared value objects into `domain_types.rs`:

- `HeuristicSeverity`
- `CalibrationAdjustment`
- `RemoteRelationKind`
- `PackageIdentity`
- `PackageIdentityLineage`
- `PackageLineageDrift`

Feature modules may wrap, re-export, or adapt these types, but they should not redefine them.

## Consequences

- Shared terminology is centralized and easier to keep consistent.
- Architecture tests can enforce ownership of cross-cutting concepts.
- Feature folders remain responsible for policies and evaluators, not core shared vocabulary.
