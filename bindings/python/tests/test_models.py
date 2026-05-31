"""Parsing contracts for the typed model layer. No binary required."""

from skill_veil import PackageResult, ScanReport, verdict_rank
from skill_veil.models import Finding

SAMPLE = [
    {
        "skill_name": "evil",
        "skill_path": "examples/malicious-skill/SKILL.md",
        "verdict": "malicious",
        "summary": {
            "risk_score": 100,
            "recommended_action": "block",
            "total_findings": 2,
        },
        "findings": [
            {
                "rule_id": "OFFICIAL_REMOTE_FETCH_EXEC",
                "severity": "critical",
                "category": "remote_exec",
                "signal_class": "malicious_behavior",
                "recommended_action": "block",
                "confidence": 0.95,
                "reason": "fetches and runs a remote script",
                "line_number": 12,
                "artifact_path": "examples/malicious-skill/SKILL.md",
            },
            {
                "rule_id": "DECLARED_PERMISSION_NETWORK_ACCESS",
                "severity": "low",
                "category": "scope_creep",
                "signal_class": "hygiene",
                "recommended_action": "log",
                "confidence": 0.87,
                "reason": "declares network access",
                "line_number": 3,
                "artifact_path": "examples/malicious-skill/SKILL.md",
            },
        ],
    },
    {
        "skill_name": "ok",
        "skill_path": "examples/clean/SKILL.md",
        "verdict": "benign",
        "summary": {"risk_score": 2, "recommended_action": "log"},
        "findings": [],
    },
]


def test_report_parses_packages_and_findings():
    report = ScanReport.from_raw(SAMPLE)
    assert len(report) == 2
    first = report[0]
    assert isinstance(first, PackageResult)
    assert first.verdict == "malicious"
    assert first.risk_score == 100
    assert first.recommended_action == "block"
    assert len(first.findings) == 2
    assert isinstance(first.findings[0], Finding)
    assert first.findings[0].rule_id == "OFFICIAL_REMOTE_FETCH_EXEC"
    assert first.findings[0].line_number == 12


def test_worst_picks_highest_ranked_verdict():
    report = ScanReport.from_raw(SAMPLE)
    assert report.worst_verdict == "malicious"
    assert report.worst.skill_name == "evil"
    assert report.any_malicious is True
    assert report.any_blocking is True


def test_benign_only_report_is_not_blocking():
    report = ScanReport.from_raw([SAMPLE[1]])
    assert report.worst_verdict == "benign"
    assert report.any_malicious is False
    assert report.any_blocking is False
    assert report[0].recommendation == "allow"


def test_recommendation_maps_from_verdict():
    report = ScanReport.from_raw(SAMPLE)
    assert report[0].recommendation == "block"
    assert report[1].recommendation == "allow"


def test_verdict_rank_total_order():
    assert verdict_rank("benign") < verdict_rank("suspicious") < verdict_rank("malicious")
    assert verdict_rank("unknown-future-label") < verdict_rank("benign")


def test_empty_report_has_benign_worst_verdict():
    report = ScanReport.from_raw([])
    assert report.worst is None
    assert report.worst_verdict == "benign"
    assert report.any_blocking is False
