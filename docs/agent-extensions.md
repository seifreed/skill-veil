# Agent Extensions

Phase 8 extends `skill-veil` beyond `SKILL.md` into a unified `agent extension`
model.

Current first-class targets:

- `SKILL.md` and `*.skill.md`
- `AGENTS.md`
- `CLAUDE.md`
- `SYSTEM.md`
- `PERSONA.md`
- `SOUL.md`
- prompt-pack entries under `prompts/` or `*.prompt.md`
- MCP manifests: `mcp.json`, `mcp.yaml`, `mcp.yml`

Current extension kinds:

- `skill`
- `agent_instruction`
- `prompt_pack`
- `mcp_server`
- `generic_extension`

Examples:

```bash
skill-veil scan-file examples/agent-instructions/AGENTS.md
skill-veil scan-package examples/prompt-pack
skill-veil scan-package examples/mcp-server
```

The model is intentionally pragmatic:

- instruction files are analyzed for persistent semantic tampering
- prompt packs are treated as first-class prompt artifacts
- MCP manifests are treated as first-class extension manifests
- the same policy, diff, SARIF, and dataset flows continue to work

## MCP-specific analysis

`skill-veil` treats MCP manifests as extension control planes, not as ordinary
JSON blobs.

Current MCP analysis covers:

- remote endpoints
- tunnel or opaque control planes
- command or stdio execution surfaces
- declared auth model
- inline bearer, token, or API key material
- broad OAuth or identity-linked scopes
- permissive tool exposure
- internal network targets
- webhook or inbound surface issues

Typical MCP findings include:

- `MCP_REMOTE_SERVER_ENDPOINT`
- `MCP_REMOTE_EXEC_SURFACE`
- `MCP_OPAQUE_REMOTE_CONTROL_PLANE`
- `MCP_NO_AUTH_MODEL`
- `MCP_INLINE_AUTH_SECRET`
- `MCP_PERMISSIVE_TOOL_EXPOSURE`
- `MCP_BROAD_IDENTITY_SCOPE`

Interpretation guidance:

- a remote MCP endpoint is not automatically malicious
- a remote endpoint plus tunnel semantics, no auth, or exec surface is much more serious
- permissive tools and broad scopes increase blast radius even if the manifest is not directly malicious

This is meant to answer:

> Is this MCP package a normal remote integration, or does it widen the agent's
> control surface in a dangerous way?
