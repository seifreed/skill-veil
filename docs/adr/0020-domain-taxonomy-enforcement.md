# 0020. Domain Taxonomy Enforcement

Date: 2026-03-30

## Status

Accepted

## Context

La frontera conceptual entre `domain_types`, `analysis_model` y `findings`
ya estaba definida, pero faltaba enforcement más exacto para evitar futuras
regresiones por imports cruzados o re-ownership accidental.

## Decision

Se endurecen los guardrails para fijar este reparto:

- `domain_types`
  - sólo value objects compartidos
  - sin ownership de observaciones, findings finales, parsing ni reporting
- `analysis_model`
  - sólo observaciones intermedias
  - sin scoring final, explainability ni provenance summary final
- `findings`
  - findings finales, scoring, reporting y reexports de tipos compartidos
  - sin ownership de observaciones

## Consequences

- Menor riesgo de deriva semántica entre capas.
- Más tests de arquitectura específicos y, por tanto, más rigidez aceptada.
- Cualquier cambio futuro de ownership debe venir acompañado de ADR y tests.
