# 0021. Book-Grade Enforcement

Date: 2026-03-30

## Status

Accepted

## Context

La arquitectura ya estaba fuerte, pero faltaba elevar el enforcement desde
guardrails generales a contratos más exactos entre submódulos concretos.

## Decision

Se endurecen los tests para vigilar:

- imports exactos entre `domain_types`, `analysis_model` y `findings`
- ownership exacto del split `reasoning/explainability`
- que `provenance/inventory` siga siendo capa de ensamblado y normalización
- que scoring no reaparezca fuera de `findings` y `reasoning/risk`

## Consequences

- Más precisión en los contratos de arquitectura.
- Más rigidez aceptada en los tests de arquitectura.
- Menor riesgo de regresión semántica futura.
