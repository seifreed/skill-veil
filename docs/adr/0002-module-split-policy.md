# ADR 0002: Module Split Policy For Dense Core Files

## Estado
Aceptado

## Contexto
El proyecto tenía varios archivos densos que mezclaban:

- coordinación
- parsing técnico
- scoring
- heurísticas de dominio
- contratos de salida

Eso dificultaba la revisión y hacía más probable que un archivo se convirtiera en un segundo origen de verdad.

## Decisión
Cuando un módulo del core crezca y empiece a mezclar más de una de esas responsabilidades:

- el archivo raíz debe quedar como fachada con reexports y API pública estable
- los contratos de dominio deben vivir en submódulos dedicados
- el parsing o IO debe moverse a módulos de soporte especializados
- la lógica heurística debe agruparse por familia de artefacto o política, no por conveniencia de implementación

## Aplicación actual
- `findings.rs` ahora actúa como fachada y delega reporting a `findings/reporting.rs`
- `rules.rs` delega carga y validación de packs a `rules/pack.rs`
- `services/artifact_analysis/manifests.rs` delega en `manifests/package.rs`, `manifests/container.rs` y `manifests/config.rs`

## Consecuencias
- el tamaño del archivo raíz deja de ser el indicador principal; importa más que tenga una sola responsabilidad
- los nuevos cambios deben extender el submódulo correcto antes que engordar la fachada
