"""LangGraph adapter for skill-veil.

Exposes the scanner as a graph node so it drops into a LangGraph
pipeline, mirroring the ergonomics of NVIDIA SkillSpector's
``graph.invoke({...})``::

    from skill_veil import graph

    state = graph.invoke({"input_path": "./my-skill", "use_llm": True})
    if state["verdict"] != "benign":
        block_install(state)

:func:`scan_node` is framework-agnostic — a plain ``dict -> dict``
function usable in any pipeline. :func:`build_graph` wraps it in a
compiled LangGraph; ``langgraph`` is an optional dependency imported
only when a graph is actually built.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .api import scan

try:  # langgraph is optional; the typed state degrades to a plain dict.
    from typing import TypedDict

    class ScanState(TypedDict, total=False):
        input_path: str
        binary: Optional[str]
        use_llm: bool
        use_vt: bool
        fp_review: bool
        result: list
        verdict: str
        risk_score: int
        recommendation: str
        findings: list
except Exception:  # pragma: no cover - TypedDict is stdlib on 3.9+
    ScanState = dict  # type: ignore[assignment,misc]


def scan_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Scan ``state['input_path']`` and return the verdict fields to merge
    into the graph state. Framework-agnostic: callable directly."""
    report = scan(
        state["input_path"],
        binary=state.get("binary"),
        use_llm=state.get("use_llm", False),
        use_vt=state.get("use_vt", False),
        fp_review=state.get("fp_review", False),
    )
    worst = report.worst
    return {
        "result": report.raw,
        "verdict": report.worst_verdict,
        "risk_score": worst.risk_score if worst else 0,
        "recommendation": worst.recommendation if worst else "allow",
        "findings": [f.raw for pkg in report for f in pkg.findings],
    }


def build_graph():
    """Build and compile a single-node LangGraph that runs a scan.

    Requires the optional ``langgraph`` dependency
    (``pip install 'skill-veil[langgraph]'``).
    """
    try:
        from langgraph.graph import END, START, StateGraph
    except ImportError as exc:  # pragma: no cover - exercised without langgraph
        raise ImportError(
            "the LangGraph adapter needs the optional 'langgraph' dependency: "
            "pip install 'skill-veil[langgraph]'"
        ) from exc

    builder = StateGraph(ScanState)
    builder.add_node("scan", scan_node)
    builder.add_edge(START, "scan")
    builder.add_edge("scan", END)
    return builder.compile()


_compiled = None


def __getattr__(name: str):
    """Lazily build the module-level ``graph`` on first access so importing
    this module never hard-requires ``langgraph``."""
    if name == "graph":
        global _compiled
        if _compiled is None:
            _compiled = build_graph()
        return _compiled
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
