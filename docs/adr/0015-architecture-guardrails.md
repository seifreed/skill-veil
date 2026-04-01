# ADR 0015: Architecture Guardrails

## Status

Accepted

## Context

The remaining architectural risk in `skill-veil-core` is no longer missing structure. It is
regression: parsing, regex ownership, scoring, or shared-domain concepts could drift back into the
wrong modules over time.

## Decision

We treat architecture guardrails as executable contracts:

- facade modules stay thin and must not absorb parsing, regex, or filesystem concerns
- parsing remains confined to explicit inventory/policy modules
- shared domain value objects stay in `domain_types`
- observation-layer concepts stay in `analysis_model`
- final scoring, explainability, and reporting stay in `findings` plus `verdict/reasoning`

## Consequences

- The codebase remains refactor-friendly without depending on reviewer memory.
- Architectural regression becomes a test failure instead of a style discussion.
- Future contributors can extend the system with clearer ownership boundaries.
