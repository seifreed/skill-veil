"""Typed views over the skill-veil JSON scan output.

The scanner emits a JSON array of per-package reports. These dataclasses
expose the load-bearing fields (verdict, risk score, findings) with
typed accessors while keeping the full untyped payload in ``raw`` so a
caller is never blocked by a schema field this binding has not modelled.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional

_VERDICT_ORDER = {"benign": 0, "suspicious": 1, "malicious": 2}
_VERDICT_RECOMMENDATION = {
    "benign": "allow",
    "suspicious": "review",
    "malicious": "block",
}


def verdict_rank(verdict: str) -> int:
    """Total order over verdicts: ``benign < suspicious < malicious``.

    Unknown labels sort below ``benign`` so a schema addition never
    silently outranks a real malicious verdict.
    """
    return _VERDICT_ORDER.get(verdict, -1)


@dataclass(frozen=True)
class Finding:
    """A single detected signal within a package."""

    rule_id: str
    severity: str
    category: str
    signal_class: str
    recommended_action: str
    confidence: Optional[float]
    reason: str
    line_number: Optional[int]
    artifact_path: Optional[str]
    raw: Dict[str, Any] = field(repr=False)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Finding":
        return cls(
            rule_id=d.get("rule_id", ""),
            severity=d.get("severity", ""),
            category=d.get("category", ""),
            signal_class=d.get("signal_class", ""),
            recommended_action=d.get("recommended_action", ""),
            confidence=d.get("confidence"),
            reason=d.get("reason", ""),
            line_number=d.get("line_number"),
            artifact_path=d.get("artifact_path"),
            raw=d,
        )


@dataclass(frozen=True)
class PackageResult:
    """One package's verdict, risk score, and findings."""

    skill_name: str
    skill_path: str
    verdict: str
    risk_score: int
    recommended_action: str
    findings: List[Finding]
    raw: Dict[str, Any] = field(repr=False)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PackageResult":
        summary = d.get("summary") or {}
        return cls(
            skill_name=d.get("skill_name", ""),
            skill_path=d.get("skill_path", ""),
            verdict=d.get("verdict", ""),
            risk_score=int(summary.get("risk_score", 0)),
            recommended_action=summary.get("recommended_action", ""),
            findings=[Finding.from_dict(f) for f in d.get("findings", [])],
            raw=d,
        )

    @property
    def is_malicious(self) -> bool:
        return self.verdict == "malicious"

    @property
    def is_suspicious(self) -> bool:
        return self.verdict == "suspicious"

    @property
    def is_benign(self) -> bool:
        return self.verdict == "benign"

    @property
    def recommendation(self) -> str:
        """Coarse install guidance derived from the verdict:
        ``allow`` | ``review`` | ``block``."""
        return _VERDICT_RECOMMENDATION.get(self.verdict, "review")


@dataclass(frozen=True)
class ScanReport:
    """The full result of a scan — one or more package reports."""

    packages: List[PackageResult]
    raw: List[Dict[str, Any]] = field(repr=False)

    @classmethod
    def from_raw(cls, raw: List[Dict[str, Any]]) -> "ScanReport":
        return cls(
            packages=[PackageResult.from_dict(p) for p in raw],
            raw=raw,
        )

    @property
    def worst(self) -> Optional[PackageResult]:
        """The package with the highest-ranked verdict, or ``None`` for
        an empty report."""
        if not self.packages:
            return None
        return max(self.packages, key=lambda p: verdict_rank(p.verdict))

    @property
    def worst_verdict(self) -> str:
        w = self.worst
        return w.verdict if w else "benign"

    @property
    def any_malicious(self) -> bool:
        return any(p.is_malicious for p in self.packages)

    @property
    def any_blocking(self) -> bool:
        """``True`` if any package is malicious or suspicious — the set a
        gate would not auto-allow."""
        return any(not p.is_benign for p in self.packages)

    def __iter__(self) -> Iterator[PackageResult]:
        return iter(self.packages)

    def __len__(self) -> int:
        return len(self.packages)

    def __getitem__(self, index: int) -> PackageResult:
        return self.packages[index]
