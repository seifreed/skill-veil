# Examples

Runnable demos for the skill-veil Python bindings. All need the
`skill-veil` binary on `PATH` or at `$SKILL_VEIL_BIN`.

| File | Shows | Needs |
|---|---|---|
| [`basic_scan.py`](basic_scan.py) | `scan()` → typed `ScanReport`, iterate findings | bindings only |
| [`langgraph_gate.py`](langgraph_gate.py) | Full LangGraph graph: scan → conditional route → allow/review/block | `skill-veil[langgraph]` |

```bash
pip install -e '..[langgraph]'
export SKILL_VEIL_BIN=../../../target/debug/skill-veil   # or install on PATH

python basic_scan.py    ../../../examples/malicious-skill/SKILL.md
python langgraph_gate.py ../../../examples/malicious-skill/SKILL.md
```

`langgraph_gate.py` wires the framework-agnostic `skill_veil.scan_node`
into a `StateGraph` with conditional edges:

```
START → scan ─┬─ benign     → allow → END
              ├─ suspicious → review → END
              └─ malicious  → block → END
```

The decision logic (`route_on_verdict`, `allow_node`, `review_node`,
`block_node`) is plain Python, so the routing is unit-testable without
LangGraph installed (see `../tests/test_examples.py`).
