# Phase 1 Exit Criteria

Fase 1 se considera cerrada solo si estas condiciones siguen siendo ciertas de
forma continua en `main` y en releases etiquetadas.

## Scanner correctness

- `README.md` narrativos no se promueven a entrypoints cuando existe `SKILL.md`.
- `scan-file` y `scan-package` siguen cubiertos por tests.
- los casos grises permanecen en `require_approval` salvo evidencia más fuerte.

## Regression corpus

- el corpus de regresión mantiene:
  - al menos `7` muestras benignas
  - al menos `3` muestras sospechosas
  - al menos `2` muestras maliciosas
- `precision >= 0.66`
- `recall >= 1.0`
- `false_positive_rate == 0.0`
- el threshold tuning recomendado no empeora el `false_positive_rate`

## Benchmark discipline

En cada cambio importante del scanner:

1. ejecutar `cargo run -p skill-veil -- benchmark benchmarks/corpus.yaml --format text`
2. revisar `benchmark-latest.json` y `benchmark-history.json` en CI
3. comprobar que no cae la cobertura benigna ni suben los falsos positivos
4. si se toca scoring o discovery, añadir al menos una muestra o regresión nueva

## Release discipline

Cada tag `v*` debe publicar:

- `benchmark-report.json`
- `benchmark-history.json`

Si una release reduce precisión o introduce falsos positivos en benignos,
Fase 1 deja de estar efectivamente cerrada aunque el código compile.
