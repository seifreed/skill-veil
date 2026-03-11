# Finding Model

Cada finding en `skill-veil` responde a cuatro preguntas:

1. qué riesgo hay
2. por qué importa
3. qué evidencia lo respalda
4. qué contexto operativo toca

## Campos clave

- `category`: clase de amenaza
- `reason`: explicación del riesgo
- `evidence_kind`: `ioc`, `behavior`, `intent`, `context`
- `recommended_action`: `log`, `require_approval`, `block`
- `policy_contexts`: contextos operativos afectados
- `raw_confidence`: confianza declarada por regla/analyzer
- `confidence`: confianza calibrada
- `confidence_rationale`: explicación de la calibración
- `remediation`: guía de mitigación específica por categoría y contexto

## Confidence model

La confianza final no replica ciegamente la confianza declarada por la regla.
Se calibra combinando:

- la confianza bruta de la regla
- un baseline por tipo de evidencia
- un baseline por categoría

Orden de fuerza esperado:

- `ioc`
- `behavior`
- `intent`
- `context`

Esto evita tratar un hallazgo lingüístico difuso igual que un patrón operativo
o un IOC fuerte.

## Threat category -> policy context

Relación actual por defecto:

- `remote_exec`, `supply_chain`, `unsafe_binary` -> `install`
- `credential_exposure` -> `secrets`
- `tool_abuse` -> `code_modification`, `secrets`
- `autonomy_escalation` -> `code_modification`, `external_comms`
- `persistent_prompt_tampering` -> `code_modification`, `external_comms`
- `data_exfiltration` -> `network`, `external_comms`, `secrets`
- `social_manipulation`, `persuasive_language` -> `external_comms`, `code_modification`
- `scope_creep`, `privilege_escalation` -> `code_modification`

## Remediation model

La remediation por defecto ya no es solo por categoría. También incluye el
contexto operativo principal para que el triage sea accionable en CI y revisión
manual.
