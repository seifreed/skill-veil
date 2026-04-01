# ADR 0004: Heuristics Must Be Captured As Explicit Policy Types

## Estado
Aceptado

## Contexto
Parte del análisis seguía expresando decisiones de seguridad como condicionales dispersos sobre strings.

Eso generaba tres problemas:

- heurísticas difíciles de reutilizar entre findings, capacidades y observaciones
- conceptos de dominio representados sólo por strings o tuplas informales
- más probabilidad de inconsistencias cuando una misma señal se usa en varios flujos

## Decisión
Las heurísticas repetibles deben modelarse como tipos o políticas explícitas cuando representen una familia estable de decisiones.

Aplicación actual:

- `InstructionSignals` concentra señales semánticas de instrucciones
- `NetworkTarget` modela objetivos internos de red
- `WebhookExposure` modela clases de exposición de endpoints inbound
- `InstallHookRisk` modela riesgo de hooks de instalación
- `DeclaredPermissionRule` sigue siendo el contrato para permisos declarados

## Regla práctica
Cuando una heurística:

- produce findings y capacidades a la vez
- necesita etiquetas o razones estables
- o aparece en más de un sitio

debe extraerse a un tipo con nombre o a un evaluador explícito.

## Consecuencias
- baja la primitive obsession
- mejora la consistencia entre detección, reasoning y reporting
- añadir nuevas clases de señal requiere extender un contrato de dominio claro en lugar de copiar condicionales
