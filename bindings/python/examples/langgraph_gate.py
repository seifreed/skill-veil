"""Complete LangGraph install-gate for agent skills.

A multi-node graph that scans a skill, then routes on the scanner's
verdict to an ``allow`` / ``review`` / ``block`` decision — the shape a
real CI or marketplace gate would use. The verdict is always the
scanner's own; ``use_llm`` / ``fp_review`` are advisory enrichment that
never change it.

Run it:

    pip install 'skill-veil[langgraph]'
    # binary on PATH, or: export SKILL_VEIL_BIN=/path/to/skill-veil
    python langgraph_gate.py ../../../examples/malicious-skill/SKILL.md

Exit code is 0 only when the decision is ``allow``.
"""

from __future__ import annotations

import sys
from typing import Any, Dict, List

from skill_veil import scan_node  # framework-agnostic scan step (dict -> dict)

try:
    from typing import TypedDict

    class GateState(TypedDict, total=False):
        input_path: str
        use_llm: bool
        fp_review: bool
        # filled by scan_node:
        result: list
        verdict: str
        risk_score: int
        recommendation: str
        findings: list
        # filled by a decision node:
        decision: str
        reasons: list
except Exception:  # pragma: no cover
    GateState = dict  # type: ignore[assignment,misc]


def route_on_verdict(state: Dict[str, Any]) -> str:
    """Conditional-edge selector: the verdict names the next node."""
    return state.get("verdict", "benign")


def _top_rule_ids(state: Dict[str, Any], limit: int = 5) -> List[str]:
    return [f.get("rule_id", "?") for f in state.get("findings", [])][:limit]


def allow_node(state: Dict[str, Any]) -> Dict[str, Any]:
    return {"decision": "allow", "reasons": ["benign verdict — safe to install"]}


def review_node(state: Dict[str, Any]) -> Dict[str, Any]:
    rules = ", ".join(_top_rule_ids(state)) or "no rule ids"
    return {
        "decision": "review",
        "reasons": [f"suspicious — needs human review ({rules})"],
    }


def block_node(state: Dict[str, Any]) -> Dict[str, Any]:
    rules = ", ".join(_top_rule_ids(state)) or "no rule ids"
    return {"decision": "block", "reasons": [f"malicious — do not install ({rules})"]}


def build_gate():
    """Compile the scan → route → decision graph. Needs the optional
    ``langgraph`` dependency."""
    from langgraph.graph import END, START, StateGraph

    builder = StateGraph(GateState)
    builder.add_node("scan", scan_node)
    builder.add_node("allow", allow_node)
    builder.add_node("review", review_node)
    builder.add_node("block", block_node)

    builder.add_edge(START, "scan")
    builder.add_conditional_edges(
        "scan",
        route_on_verdict,
        {"benign": "allow", "suspicious": "review", "malicious": "block"},
    )
    for node in ("allow", "review", "block"):
        builder.add_edge(node, END)

    return builder.compile()


def main(argv: List[str]) -> int:
    if len(argv) < 2:
        print("usage: python langgraph_gate.py <path-to-skill>", file=sys.stderr)
        return 2

    try:
        gate = build_gate()
    except ImportError as exc:
        print(exc, file=sys.stderr)
        return 1

    final = gate.invoke({"input_path": argv[1], "use_llm": False, "fp_review": False})

    print(
        f"verdict={final.get('verdict')} "
        f"risk={final.get('risk_score')} "
        f"decision={final.get('decision')}"
    )
    for reason in final.get("reasons", []):
        print("  -", reason)

    return 0 if final.get("decision") == "allow" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
