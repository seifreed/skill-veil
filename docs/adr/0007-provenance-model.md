# ADR 0007: Provenance Is Derived From Origin, Inventory, Lineage And Publisher Signals

## Estado
Aceptado

## Contexto
`provenance` había crecido hasta mezclar varias responsabilidades:

- clasificación de orígenes remotos
- inventario de manifiestos y lockfiles
- extracción de publishers
- identidad de paquete
- notas de lineage y trust derivation

Eso hacía más difícil extender el modelo sin reintroducir un archivo denso y ambiguo.

## Decisión
Se fija la siguiente estructura:

- `verdict/provenance.rs`: ensamblador fino de provenance
- `verdict/provenance/origin.rs`: clasificación de origen remoto y confianza asociada
- `verdict/provenance/inventory.rs`: inventario de manifests, lockfiles e identidad de paquete
- `verdict/provenance/lineage.rs`: cobertura de lockfiles y anomalías de lineage
- `verdict/provenance/publisher.rs`: extracción y consistencia de publisher

Además:

- la confianza de origen debe expresarse con value objects explícitos
- la identidad de paquete debe tratarse como concepto de dominio, no como string improvisado durante el parseo

## Consecuencias
- provenance deja de ser un segundo motor oculto dentro de un solo archivo
- las reglas de origen, lineage e inventario pueden evolucionar de forma local
- los tests unitarios pueden apuntar a seams de dominio concretos
