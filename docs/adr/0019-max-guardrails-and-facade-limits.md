# 0019. Max Guardrails and Facade Limits

Date: 2026-03-30

## Status

Accepted

## Context

El proyecto ya tiene una arquitectura limpia y una taxonomía de dominio bastante cerrada.
La deuda restante no es estructural sino de enforcement: evitar que futuras contribuciones
reintroduzcan mezcla entre ownership semántico, parsing, scoring y fachadas finas.

## Decision

Se elevan los guardrails en tres ejes:

- ownership más exacto para `domain_types`, `analysis_model` y `findings`
- límites de tamaño más estrictos en fachadas y subfachadas críticas
- tests unitarios finos en módulos combinatorios con más riesgo de deriva

## Consequences

- Menor riesgo de regresión semántica.
- Menor riesgo de que una fachada vuelva a absorber lógica combinatoria.
- Más coste de mantenimiento en tests de arquitectura, aceptado como tradeoff.
