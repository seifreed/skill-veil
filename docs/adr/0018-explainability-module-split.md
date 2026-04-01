# 0018. Explainability Module Split

Date: 2026-03-30

## Status

Accepted

## Context

`verdict/reasoning/explainability.rs` había vuelto a concentrar dos responsabilidades distintas:

- ensamblado de traces explicativos
- atribución de fuentes y heurísticas de drift sensitivity

Eso hacía más difícil vigilar ownership semántico con tests de arquitectura.

## Decision

Se mantiene `explainability.rs` como fachada fina y se divide el ownership así:

- `explainability/traces.rs`
  - assembly de traces
  - labels de activación y escalado
- `explainability/sources.rs`
  - attribution de `source_contributions`
  - clasificación de `score_factor`/`graph`/`policy`/`network`/`provenance`
  - drift-sensitive driver heuristics

## Consequences

- Mejor enforcement de arquitectura sobre ownership de explainability.
- Menos densidad combinatoria en la fachada.
- Menor riesgo de que futuras heurísticas mezclen traces con source attribution.
