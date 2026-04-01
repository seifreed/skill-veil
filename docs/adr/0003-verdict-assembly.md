# ADR 0003: Verdict Assembly Stays Thin And Policy Driven

## Estado
Aceptado

## Contexto
`verdict.rs` acumuló durante un tiempo dos riesgos:

- lógica duplicada respecto a submódulos de capacidades, provenance y reasoning
- un archivo raíz que podía volver a convertirse en segundo origen de verdad

Eso degradaba la legibilidad y hacía más difícil saber dónde debía vivir cada regla nueva.

## Decisión
Se fija la siguiente política:

- `verdict.rs` debe actuar como ensamblador fino y API pública estable
- la derivación de capacidades vive en `verdict/capabilities.rs`
- la explicación y las razones del veredicto viven en `verdict/reasoning.rs`
- provenance y resúmenes viven en sus propios submódulos
- cualquier nueva heurística de veredicto debe añadirse al submódulo especializado, no al ensamblador raíz

## Verificación
- `crates/skill-veil-core/src/architecture_tests.rs` comprueba que `verdict.rs` no introduzca regex, serialización ni detalles de infraestructura
- el ensamblado final sigue validado por `cargo check` y `cargo test`

## Consecuencias
- desaparece el doble origen de verdad en veredictos
- las revisiones futuras se vuelven más locales
- el archivo raíz se mantiene pequeño incluso cuando el modelo de veredicto crezca
