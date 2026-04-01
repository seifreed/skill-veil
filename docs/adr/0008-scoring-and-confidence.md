# ADR 0008: Scoring And Confidence Must Use Explicit Domain Contracts

## Estado
Aceptado

## Contexto
El sistema usa scoring, confidence y trust en varios puntos:

- findings
- provenance
- reasoning
- benchmark calibration

Sin contratos explícitos, es fácil degradar el modelo a floats, strings o factores ad hoc repartidos por distintos módulos.

## Decisión
Se fija la siguiente regla:

- la severidad y la confianza deben expresarse mediante tipos o funciones de dominio explícitas cuando afecten decisiones de política o veredicto
- los módulos de ensamblado no deben recalibrar ni reinterpretar confidence por su cuenta
- cuando aparezcan nuevas clases estables de confianza o riesgo, deben introducirse como value objects o enums con nombre

Aplicación actual:

- `RiskBand` normaliza bandas de score
- `ProvenanceConfidence` normaliza confianza de origen remoto
- `RemoteOriginAssessment` une reputación, confianza y rationale

## Consecuencias
- baja la posibilidad de scoring implícito y duplicado
- mejora la auditabilidad del razonamiento
- las futuras reglas de confidence deberán integrarse en contratos de dominio existentes, no en helpers sueltos
