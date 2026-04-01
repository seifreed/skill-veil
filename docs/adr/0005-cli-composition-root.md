# ADR 0005: CLI Roots Stay Thin And Delegate Use Cases

## Estado
Aceptado

## Contexto
La CLI mejoró bastante, pero seguía siendo fácil que `commands.rs` absorbiera casos de uso completos por conveniencia.

Eso degradaba dos propiedades:

- la CLI dejaba de ser composition root y volvía a mezclar orquestación, serialización y reglas operativas
- los tests de arquitectura tenían menos capacidad para detectar regresiones de responsabilidad

## Decisión
Se fija la siguiente política:

- `commands.rs` y `dataset.rs` deben actuar como raíces de composición finas
- los casos de uso específicos viven en submódulos como `commands/baseline.rs`, `commands/diff.rs`, `commands/rules.rs`, `commands/benchmark.rs` o `dataset/output.rs`
- la serialización y el IO de archivos deben concentrarse en módulos de soporte explícitos

## Verificación
`crates/skill-veil-core/src/architecture_tests.rs` comprueba que:

- `commands.rs` y `dataset.rs` no usen `std::fs` ni serialización JSON directa
- `commands.rs` no vuelva a contener flujos completos de baseline o diff

## Consecuencias
- la CLI sigue siendo más pequeña y predecible
- cada comando complejo tiene un lugar estable donde crecer sin contaminar la raíz
- las futuras revisiones de clean architecture pueden enfocarse en fronteras reales, no en un archivo monolítico
