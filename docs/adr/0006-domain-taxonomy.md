# ADR 0006: Domain Taxonomy For Signals, Policies, Capabilities And Provenance

## Estado
Aceptado

## Contexto
El proyecto ya separa mejor sus capas, pero seguía siendo fácil mezclar vocabulario de dominio:

- `signals` como detección bruta
- `policies` como evaluación y decisión
- `capabilities` como efecto o superficie resultante
- `findings` como salida auditable
- `provenance` como confianza de origen

Sin una taxonomía explícita, las nuevas heurísticas tienden a duplicar conceptos o a usar nombres parecidos para responsabilidades distintas.

## Decisión
Se fija el siguiente vocabulario:

- `signals`: detección o evidencia semántica de bajo nivel
- `policies`: evaluación de reglas de dominio a partir de señales, contexto y perfiles
- `capabilities`: superficie efectiva o declarada del artefacto
- `relations`: vínculos estructurales o remotos entre artefactos y recursos
- `findings`: observaciones finales serializables y auditables
- `provenance`: evaluación de origen, confianza y consistencia de suministro

Además:

- cuando una decisión tenga clases estables, debe expresarse con un value object o enum con nombre
- las fachadas deben orquestar; no deben reinterpretar la taxonomía

## Aplicación actual
- `InstructionSignals` vive en `instructions/signals.rs`
- `permission_policy`, `network_policy` y `webhook_policy` son evaluadores de política
- `NetworkTarget`, `RemoteRelationKind`, `DependencyPinning`, `PackageBinaryExposure` y `RemoteOriginAssessment` son value objects de dominio

## Consecuencias
- baja la ambigüedad semántica al añadir nuevas reglas
- se reducen helpers genéricos mal ubicados
- la revisión de clean architecture puede apoyarse también en reglas de vocabulario, no sólo en tamaño o dependencias
