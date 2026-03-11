# skill-veil Threat Model

`skill-veil` treats agent extensions as a supply-chain surface, not only as text files.

## Security Goal

Detect and explain risky agent artifacts before they are executed, installed, or trusted by a human or CI pipeline.

## Primary Threat Classes

### 1. Remote Execution
- Remote download and execution.
- Inline shell, PowerShell, Python, or base64 bootstrap code.
- Deferred execution hidden in setup or warmup paths.

### 2. Supply Chain
- Unpinned dependencies.
- Global installers and remote binaries.
- Risky package manifests and install hooks.
- Known malicious domains, publishers, or infrastructure.

### 3. Persistent Prompt Tampering
- Attempts to modify `AGENTS.md`, `CLAUDE.md`, `SOUL.md`, `SYSTEM.md`, or equivalent persistent instruction files.
- Semantic persistence via recurring directives or long-lived behavioral state.

### 4. Secret Access
- Direct handling of API keys, wallets, OAuth tokens, credentials, or plaintext secrets.
- Filesystem traversal targeting `.env`, tokens, key material, or credential stores.

### 5. Tool Abuse
- Instructions to use powerful tools outside expected scope.
- Code modification or infrastructure actions without explicit review.

### 6. Autonomy Escalation
- Attempts to bypass human approval.
- Self-propagation, self-registration, or uncontrolled multi-agent coordination.

### 7. Data Exfiltration
- Outbound transfer of environment data, tokens, local databases, messages, camera data, or user content.
- Webhook, bot, or covert channel exfiltration.

### 8. Social Manipulation
- Persuasive language intended to suppress review.
- Boundary-testing language, urgency, or anti-safety framing.

## Evidence Model

Each finding should classify evidence as one of:

- `ioc`: known indicator such as malicious domain, publisher, C2, or hash.
- `behavior`: concrete operational pattern such as execution, exfiltration, or persistence.
- `intent`: manipulative or coercive language suggesting malicious purpose.
- `context`: environmental or architectural signal that raises risk even if behavior is incomplete.

## Confidence Model

Confidence is calibrated, not copied directly from the rule:

- `raw_confidence` comes from the rule or analyzer
- `confidence` is adjusted using evidence strength and category strength
- the calibration rationale is stored per finding

This keeps `ioc` and concrete `behavior` findings stronger than broad `intent`
or weak `context` signals even when the original rule confidence is similar.

## Artifact Model

Each finding should also explain where the evidence came from:

- `skill_document`
- `code_snippet`
- `referenced_artifact`
- `package_manifest`
- `generic_artifact`

## Triage Contract

Every finding should answer these four questions:

1. What risk is present?
2. Why is it risky?
3. What evidence triggered it?
4. What action should the user take?
5. Which operational context is affected?

In the current model:
- risk = `category`
- why = `reason`
- evidence = `evidence_kind` + `match_value` + artifact context
- action = `recommended_action`
- operational context = `policy_contexts`

## Open Source Direction

The long-term goal is not to act as a generic antivirus. The goal is to become a transparent, auditable security layer for agent supply chain analysis across skills, prompts, manifests, MCP servers, and persistent instruction artifacts.
