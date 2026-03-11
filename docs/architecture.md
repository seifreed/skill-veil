# Architecture

## Overview

`skill-veil` follows a clean, ports-and-adapters oriented layout.

- `skill-veil-core`: domain and application logic
- `skill-veil-cli`: delivery layer and UX

## Core flow

1. Discover targets.
2. Parse markdown into `SkillDocument`.
3. Evaluate rules.
4. Analyze referenced artifacts and manifests.
5. Build `artifact_graph`.
6. Compute findings, score, policy action, and report output.

## Main modules

- `scanner`: orchestration
- `rules`: declarative rule loading and evaluation
- `findings`: finding model, explainable score, action triggers
- `artifact_graph`: relationships and capability facts
- `policy`: JSON, SARIF, SHIELD and policy synthesis
- `services/artifact_analysis`: artifact-specific heuristics

## Boundary decisions

- Rule evaluation stays in core.
- CLI formatting and command routing stay in the CLI crate.
- Artifact relationships and capability facts are first-class domain concepts.
- Policy escalation can be driven by both findings and artifact context.
