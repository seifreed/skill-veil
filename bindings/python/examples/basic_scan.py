"""Minimal scan without LangGraph.

    python basic_scan.py ../../../examples/malicious-skill/SKILL.md

Exit code is 0 only when nothing is blocking (no malicious/suspicious
package).
"""

from __future__ import annotations

import sys
from typing import List

import skill_veil


def main(argv: List[str]) -> int:
    if len(argv) < 2:
        print("usage: python basic_scan.py <path-to-skill>", file=sys.stderr)
        return 2

    try:
        report = skill_veil.scan(argv[1])
    except skill_veil.BinaryNotFoundError as exc:
        print(exc, file=sys.stderr)
        return 1

    print(f"scanned {len(report)} package(s); worst verdict: {report.worst_verdict}")
    for pkg in report:
        print(f"\n{pkg.skill_name}  [{pkg.verdict}] risk={pkg.risk_score} -> {pkg.recommendation}")
        for finding in pkg.findings[:8]:
            print(f"    {finding.severity:<8} {finding.rule_id}: {finding.reason}")

    return 1 if report.any_blocking else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
