"""Python bindings for skill-veil — the agent-extension security scanner.

The bindings drive the native ``skill-veil`` binary and parse its JSON
output, so the verdict is always the scanner's own calibrated result::

    import skill_veil

    report = skill_veil.scan("./my-skill")
    if report.worst_verdict != "benign":
        print("do not install:", [f.rule_id for p in report for f in p.findings])

A LangGraph adapter is available for AI pipelines::

    from skill_veil import graph
    state = graph.invoke({"input_path": "./my-skill", "use_llm": True})
"""

from __future__ import annotations

from ._binary import BinaryNotFoundError, find_binary
from ._runner import ScanError
from .api import scan, scan_raw
from .models import Finding, PackageResult, ScanReport, verdict_rank

__version__ = "0.2.0"

__all__ = [
    "scan",
    "scan_raw",
    "ScanReport",
    "PackageResult",
    "Finding",
    "verdict_rank",
    "find_binary",
    "BinaryNotFoundError",
    "ScanError",
    "build_graph",
    "scan_node",
    "graph",
    "__version__",
]

_LANGGRAPH_EXPORTS = {"build_graph", "scan_node", "graph"}


def __getattr__(name: str):
    """Lazily forward the LangGraph adapter symbols so importing
    ``skill_veil`` never requires ``langgraph`` to be installed."""
    if name in _LANGGRAPH_EXPORTS:
        from . import langgraph as _lg

        return getattr(_lg, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
