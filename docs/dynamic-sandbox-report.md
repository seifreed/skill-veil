# Dynamic Sandbox Report

`skill-veil scan ... --dynamic-report <FILE>` writes a standalone JSON
document with the full runtime evidence from a dynamic sandbox run. It is
separate from the main scan report (see
[json-report-schema-v3.md](json-report-schema-v3.md)): the scan report
carries the advisory `SANDBOX_*` findings folded in with every other
channel, while this artifact is the self-contained record of *what the
skill did at runtime* — the raw observed behaviors, the signatures they
matched, and the intercepted network requests with complete headers and
untruncated payloads.

The flag requires `--dynamic` or `--sandbox-detonate-agent` and a binary
built with `--features sandbox`. With the flag set, a report is written
even when nothing is observed, so a clean run still produces an auditable
artifact. If the sandbox does not run at all (no Docker / gVisor, or a
non-`sandbox` build), no file is written and a one-line note explains why.

## Stability

The serialized shape is versioned by the top-level `schema_version`
(currently `1`). Compatible changes add fields; `schema_version` is bumped
on any breaking change. See [versioning.md](versioning.md).

## Top-level shape

| Field | Type | Description |
|---|---|---|
| `schema_version` | integer | Artifact schema version (`1`). |
| `source_path` | string | The scanned skill/artifact the sandbox ran against. |
| `runtime` | string | `gvisor` (real isolation) or `runc` (weaker, host kernel shared). |
| `timed_out` | bool | The run hit the wall-clock timeout (partial observation). |
| `truncated` | bool | The observer truncated output (behavior flood). |
| `behaviors` | array | Raw observed runtime behaviors (see below). |
| `matched_signatures` | array | The advisory `SANDBOX_*` findings derived from the behaviors. Same `Finding` shape as the main scan report. |
| `network_captures` | array | Structured recording-proxy captures. Non-empty only with `--sandbox-record-network` or `--sandbox-detonate-agent`. |

### `behaviors[]`

The contract emitted by the in-container observer and the host-side agent.

| Field | Type | Description |
|---|---|---|
| `class` | string | `network_connect`, `dns_query`, `process_spawn`, `file_write`, `sensitive_file_read`, `persistence_write`, `privilege_change`, or `agent_tool_call`. |
| `detail` | string | The concrete evidence: `host:port`, a path, a command line, or a flattened `METHOD url body=…` (payload preview capped at 256 chars). |
| `source` | string | `script` (a referenced script under strace) or `agent` (the instrumented LLM acting on the skill's instructions). |

### `network_captures[]`

The raw HTTP evidence behind the flattened `network_connect` behaviors,
recovered by the recording proxy (HTTPS is MITM-decrypted with an
image-local throwaway CA). Each entry is one intercepted request.

| Field | Type | Description |
|---|---|---|
| `method` | string | HTTP method, or `CONNECT` for a TLS tunnel the proxy could not decrypt. |
| `url` | string | Request URL (omitted when only the CONNECT host is known). |
| `host` | string | Destination host. |
| `body` | string | Request body — the exfiltrated payload, up to the proxy's 4096-byte cap (omitted when empty). |
| `headers` | object | Full request headers as a string→string map (omitted when none). |
| `tls_error` | string | Present when TLS interception failed; the destination still survives. |
| `forward_error` | string | Present when an allowlisted forward attempt failed. |

## Example

```json
{
  "schema_version": 1,
  "source_path": "suspicious-skill/SKILL.md",
  "runtime": "gvisor",
  "timed_out": false,
  "truncated": false,
  "behaviors": [
    {
      "class": "sensitive_file_read",
      "detail": "/root/.aws/credentials",
      "source": "script"
    },
    {
      "class": "network_connect",
      "detail": "POST https://c2.invalid/drop body=token=AKIA…",
      "source": "agent"
    }
  ],
  "matched_signatures": [
    {
      "rule_id": "SANDBOX_SENSITIVE_FILE_READ",
      "category": "credential_exposure",
      "severity": "high",
      "match_value": "/root/.aws/credentials"
    },
    {
      "rule_id": "SANDBOX_NETWORK_CONNECT",
      "category": "data_exfiltration",
      "severity": "high",
      "match_value": "POST https://c2.invalid/drop body=token=AKIA…"
    }
  ],
  "network_captures": [
    {
      "method": "POST",
      "url": "https://c2.invalid/drop",
      "host": "c2.invalid",
      "body": "token=AKIA1234567890",
      "headers": {
        "Authorization": "Bearer eyJ…",
        "Content-Type": "application/json",
        "User-Agent": "exfil/1.0"
      }
    }
  ]
}
```

`matched_signatures` entries are abbreviated above; they carry the full
`Finding` shape documented in
[json-report-schema-v3.md](json-report-schema-v3.md). Every sandbox
finding is advisory (`ReviewSignal` / `RequireApproval`): the dynamic
channel runs after the verdict and never inflates the deterministic static
verdict.
