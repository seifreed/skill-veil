# ADR 0011: Network Ownership And Remote Relations

## Status

Accepted

## Context

`services/artifact_analysis/network.rs` had accumulated four different responsibilities:

- regex ownership
- remote relation classification
- internal target classification
- webhook exposure heuristics

That concentration made it easy for relation semantics and detection heuristics to drift.

## Decision

We keep `network.rs` as a thin facade and split ownership into:

- `network/patterns.rs` for regex definitions
- `network/relations.rs` for URL extraction and remote relation typing
- `network/targets.rs` for internal-target and SSRF-style classification
- `network/webhook.rs` for inbound webhook exposure heuristics

`RemoteRelationKind` remains the explicit seam between string URLs and the artifact graph, and it
now distinguishes at least `ConnectsTo` and `Downloads`.

## Consequences

- Regex ownership is explicit and enforceable through architecture tests.
- Connect-vs-download classification no longer depends on ad hoc call-site decisions.
- Target classification and webhook exposure can evolve independently without regrowing the facade.
