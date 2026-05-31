# skill-veil — Python bindings & LangGraph adapter

Python wrapper around the native [`skill-veil`](https://github.com/seifreed/skill-veil)
binary for embedding agent-extension security scanning into Python and
AI pipelines. The wrapper drives the compiled scanner and parses its JSON
output, so **the verdict is always the scanner's own calibrated result** —
the Python layer never re-implements detection logic.

## Install

```bash
pip install skill-veil                 # bindings only
pip install 'skill-veil[langgraph]'    # + the LangGraph adapter
```

The bindings need the `skill-veil` binary on `PATH`, at `$SKILL_VEIL_BIN`,
or built in the repo's `target/{release,debug}/`. Install it with:

```bash
cargo install --path crates/skill-veil-cli
```

## Quick start

```python
import skill_veil

report = skill_veil.scan("./my-skill")          # file, directory, or SKILL.md

print(report.worst_verdict)                      # benign | suspicious | malicious
for pkg in report:
    print(pkg.skill_name, pkg.verdict, pkg.risk_score, pkg.recommendation)
    for f in pkg.findings:
        print("  ", f.rule_id, f.severity, f.reason)

if report.any_blocking:
    raise SystemExit("refusing to install")
```

`scan()` returns a typed [`ScanReport`](skill_veil/models.py); the raw
JSON is always on `.raw` (and per package / per finding) so a new scanner
field never blocks you. For the untyped payload directly, use
`skill_veil.scan_raw(path)`.

### Optional enrichment

Enrichment that needs network or local services is **off by default** for
clean, fast, offline scans. Opt in per channel — none of it changes the
verdict:

```python
report = skill_veil.scan(
    "./my-skill",
    use_llm=True,          # LLM enrichment (advisory)
    use_vt=True,           # VirusTotal cross-check
    fp_review=True,        # advisory LLM false-positive review
    fp_review_out="fp.json",
    profile="enterprise",
    fail_on="high",
)
```

## LangGraph adapter

Mirrors the `graph.invoke({...})` ergonomics of AI-pipeline scanners:

```python
from skill_veil import graph

state = graph.invoke({"input_path": "./my-skill", "use_llm": True})
state["verdict"]          # benign | suspicious | malicious
state["risk_score"]       # 0..100
state["recommendation"]   # allow | review | block
state["findings"]         # flat list of finding dicts
state["result"]           # full raw per-package JSON
```

`skill_veil.scan_node` is the same logic as a plain `dict -> dict`
function, usable in any orchestrator without LangGraph installed.

## API

| Symbol | Purpose |
|---|---|
| `scan(path, **opts) -> ScanReport` | Typed scan |
| `scan_raw(path, **opts) -> list[dict]` | Raw JSON scan |
| `ScanReport` | `.packages`, `.worst`, `.worst_verdict`, `.any_malicious`, `.any_blocking`, iterable |
| `PackageResult` | `.verdict`, `.risk_score`, `.recommendation`, `.findings`, `.is_malicious/.is_suspicious/.is_benign` |
| `Finding` | `.rule_id`, `.severity`, `.category`, `.signal_class`, `.recommended_action`, `.confidence`, `.reason`, `.line_number` |
| `build_graph()`, `scan_node`, `graph` | LangGraph adapter |
| `find_binary(explicit=None)` | Resolve the scanner binary |
| `ScanError`, `BinaryNotFoundError` | Errors |

## Tests

```bash
pip install -e '.[dev]'
pytest
```

The unit tests run without the binary (argv construction, output
parsing, model mapping).
