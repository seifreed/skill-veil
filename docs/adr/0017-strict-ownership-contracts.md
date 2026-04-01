# ADR 0017: Strict Ownership Contracts

## Status

Accepted

## Context

The codebase already has strong modular structure. The remaining risk is subtle regression:
shared domain types, observation models, reporting shapes, parsing modules, and combinatorial
reasoning helpers can drift across boundaries without obvious breakage.

## Decision

We keep the architecture strict through three kinds of contract:

- source-based architecture tests for imports, ownership, parsing, regex, scoring, and facade size
- unit tests for combinatorial modules where behavior is easy to regress silently
- ADR-backed taxonomy so ownership changes must be made intentionally

## Consequences

- Ownership changes become explicit and reviewable
- Regressions in taxonomy or layering are caught before they become structural debt
- The project can evolve without reopening the original clean-architecture problems
