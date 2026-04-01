# ADR 0001: Core Boundaries And Infrastructure Placement

## Estado
Aceptado

## Contexto
El `core` había mejorado, pero seguía arrastrando dos riesgos:

- fachadas y casos de uso con detalles de infraestructura incrustados
- regresiones silenciosas cuando alguien reintroduce `std::fs`, parseo ad hoc o serialización en los módulos de coordinación

## Decisión
Se fija la siguiente regla:

- los archivos fachada u orquestadores no deben depender directamente de `std::fs`, `serde_json`, `serde_yaml`, `toml::Value` ni `regex::Regex`
- esos detalles deben vivir en módulos especializados de infraestructura o parsing
- la carga de rule packs queda concentrada en `rules/pack.rs`
- el dispatch de análisis de artefactos queda como router fino; la heurística específica vive en submódulos de `manifests`, `mcp`, `instructions`, `lockfiles` o `scripts`

## Verificación
`crates/skill-veil-core/src/architecture_tests.rs` contiene tests de arquitectura por inspección de fuentes para detectar regresiones en esos puntos sensibles.

## Consecuencias
- baja el acoplamiento accidental en `rules.rs`, `findings.rs` y `artifact_analysis`
- la complejidad de parsing sigue existiendo, pero confinada a módulos explícitos
- nuevas heurísticas deben añadirse al submódulo adecuado, no a las fachadas
