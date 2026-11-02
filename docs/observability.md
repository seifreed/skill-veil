# Logging and observability

skill-veil is a synchronous security-analysis CLI and Rust library, with a
Python wrapper that launches the CLI. It is not a long-running service. Its
production observability therefore uses structured diagnostic events and
operation spans without requiring a collector, daemon, database, or SaaS
backend.

## Baseline audit

The initial audit found a useful but incomplete foundation:

- the core and CLI already used the `tracing` facade for recoverable scanner,
  filesystem, rule-pack, cache, and integration failures;
- the CLI installed a single `tracing-subscriber` and kept diagnostics on
  stderr;
- terminal output and several configuration `Debug` implementations already
  redacted or neutralised attacker-controlled data;
- 144 structured macro calls existed across the Rust crates, but 47 direct
  `eprintln!` calls mixed diagnostics, warnings, and user-facing status;
- the subscriber removed timestamps and module targets, supported only text,
  had no operation spans or correlation, and could not write to a configured
  file;
- only the terminal-control filter had direct logging tests.

The initial score was **3.8/10**:

| Dimension | Initial | Evidence |
|---|---:|---|
| Architecture and decoupling | 5 | Standard facade, but setup and writer lived in `main.rs`. |
| Functional coverage | 3 | Local warnings existed; lifecycle, retries, network calls, and durations were mostly absent. |
| Event quality | 4 | Useful warnings, but inconsistent free-form messages and direct stderr diagnostics. |
| Structure and consistency | 2 | Text only; no timestamp, target, event name, or outcome convention. |
| Context and correlation | 0 | No spans or propagated correlation identifier. |
| Security and privacy | 6 | Strong terminal filtering and config redaction, but no last-line credential redaction. |
| Performance and resilience | 6 | Low volume and synchronous, but no size bound, file fallback, or concurrency test. |
| Configuration and portability | 4 | `RUST_LOG`, `--verbose`, and `--quiet` only. |
| Error management | 5 | Typed/core errors and `anyhow` context, but mixed sinks and default panic output. |
| Testing and verifiability | 3 | Injection tests existed; structure, levels, correlation, concurrency, and destination failure did not. |

## Architecture

Library code emits events through `tracing`; it does not choose formatting or
destinations. The CLI composition root owns `observability.rs`, which installs
one `tracing-subscriber` layer and an `EnvFilter`. This preserves the existing
hexagonal boundary: domain code has no dependency on a concrete output sink.

The writer buffers one complete event, caps it at 64 KiB, redacts credentials,
neutralises terminal controls and embedded line breaks, then writes it as one
locked record. stderr is the default destination. A configured file is opened
in append mode and shared through a mutex, so concurrent Rayon or worker-thread
events cannot interleave. If the file cannot be opened, logging falls back to
stderr and emits `logging.destination_fallback`; logging failure does not stop a
scan.

File writes are intentionally synchronous. skill-veil is a bounded CLI whose
event volume is small, and adding a background logging thread would complicate
shutdown and error handling without measurable benefit. Files are not rotated
or deleted by the process. Use journald/syslog capture, a container runtime, or
the host's `logrotate` when retention is required.

## Configuration

| CLI | Environment | Purpose |
|---|---|---|
| `--log-level trace|debug|info|warn|error` | `SKILL_VEIL_LOG_LEVEL` | Global threshold. |
| `--log-format text|json` | `SKILL_VEIL_LOG_FORMAT` | Human-readable or JSON Lines output. |
| `--log-file PATH` | `SKILL_VEIL_LOG_FILE` | Append logs to a local file instead of stderr. |
| `--correlation-id ID` | `SKILL_VEIL_CORRELATION_ID` | Join an invocation to an external workflow. |
| `--environment NAME` | `SKILL_VEIL_ENVIRONMENT` | Label the deployment environment. |
| `--verbose` | — | Compatibility shortcut for `debug`. |
| `--quiet` | — | Compatibility shortcut for `error`. |

`RUST_LOG` remains the standard per-module override when `--log-level` and
`SKILL_VEIL_LOG_LEVEL` are absent. The default threshold is `warn`, preserving
quiet command output. Global logging options conflict when their meaning would
be ambiguous.

Examples:

```bash
skill-veil --log-level info scan-package ./skill
skill-veil --log-format json --log-level debug --environment ci scan-file SKILL.md
SKILL_VEIL_LOG_FILE=/var/log/skill-veil.jsonl \
  SKILL_VEIL_LOG_FORMAT=json skill-veil --log-level info rules validate
RUST_LOG=skill_veil_core::scanner_execution=trace,skill_veil=info \
  skill-veil scan-package ./skill
```

## Event contract

JSON output is JSON Lines. Standard `tracing-subscriber` fields include a UTC
RFC 3339 `timestamp`, `level`, `message`, and Rust module `target`. The current
operation span adds:

- `service=skill-veil`
- `component=cli`
- `operation`
- `environment`, when configured
- `correlation_id`, when supplied by the caller

Events use stable snake-case field names and dot-separated event names.
Lifecycle events use `command.started` and `command.completed`, with `status`,
`outcome`, `exit_code`, and `duration_ms`. Failures add `error_type` and
`error_code`. Rust has no fatal level; an unrecoverable process-boundary failure
is an `ERROR` followed by exit code 2.

Operational boundaries add the following event families:

| Event | Level | Relevant fields |
|---|---|---|
| `scan.completed` | INFO | outcome, duration, package/finding/error counts |
| `scan.target_failed` / `scan.channel_failed` | WARN | operation, error type, safe error |
| `scan.channel_skipped` | WARN | operation and bounded reason |
| `http.request_completed` | DEBUG | integration, status, retries, duration |
| `http.request_retry` | WARN | integration, attempt, limit, backoff, reason |
| `cache.hit` / `cache.miss` | DEBUG | cache operation and non-sensitive key class |
| `cache.read_failed` / `cache.write_failed` | WARN | operation and I/O/decode error |
| `sandbox.container_completed` / `sandbox.container_timeout` | DEBUG/WARN | duration and cancellation state |
| `rules.download_completed` | INFO | verified version/SHA, size/count, duration |

Command result data remains on stdout. Human-facing confirmations such as an
output path or update notification remain on stderr and are not diagnostic log
events; machine consumers should use JSON logging and identify records by
`event_name`.

The Python binding starts the child with JSON logging unless the caller already
selected a format. Successful and blocked scans forward validated, bounded JSON
events to the `skill_veil` Python logger and retain the parsed event on each
record as `skill_veil_event`. Plain child stderr is never re-emitted as a log
record. Standard environment inheritance propagates correlation and environment
labels to the child process.

Do not invent trace or span identifiers. A local span is enough for this
single-process CLI. W3C Trace Context and OpenTelemetry become appropriate only
if skill-veil gains a distributed request boundary or an existing collector;
neither is currently present.

## Level policy

- `TRACE`: high-volume internal decisions useful only for focused debugging.
- `DEBUG`: component selection, cache decisions, bounded technical context.
- `INFO`: invocation lifecycle and successful operational transitions.
- `WARN`: recoverable degradation, skipped optional analysis, retries, and
  findings over the configured gate.
- `ERROR`: an operation failed or the process cannot complete the command.

Emit an error once at the boundary that decides the operation failed. Lower
layers should return an error with context unless they recover or skip work; a
recovered degradation is a warning, not a duplicate error.

## Security

The writer is the final defence for every backend. It redacts bearer/basic
credentials, named API keys, tokens, passwords, cookies, session identifiers,
client secrets, and PEM private-key bodies. It replaces control characters and
embedded newlines, preventing forged log records and terminal escape attacks.
Each event is bounded to prevent attacker-controlled data from creating an
unbounded record.

Instrumentation must still minimise data at the source:

- never log request/response bodies, file contents, prompts, headers, or full
  configuration values;
- log provider names, HTTP status, attempt number, byte counts, and durations;
- use `%path.display()` only when the path is necessary to identify a failed
  local operation;
- do not log API keys even at trace level;
- retain the original error chain in the returned error and log it only at the
  operation boundary.

The redactor is defence in depth, not permission to emit sensitive values.

## Adding instrumentation

Use `tracing` directly in the producer. Include an `event_name`, `operation`,
`status` or `outcome`, and bounded diagnostic fields. Prefer one completion
event with `duration_ms` over separate start/success events for short internal
operations. Create a span only when several child events need shared context.

Every new non-trivial event contract needs a positive and negative test: prove
that required fields are present and that secrets or attacker-controlled line
breaks are absent. The CLI integration test in `tests/observability_cli.rs`
demonstrates the full JSON/error/correlation path.
