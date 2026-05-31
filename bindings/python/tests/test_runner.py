"""Argv construction and output-parsing contracts. No binary required."""

import pytest

from skill_veil._runner import ScanError, _build_argv, _parse_stdout


def test_build_argv_defaults_disable_polluting_enrichment():
    argv = _build_argv("skill-veil", "/some/file.md")
    assert argv[:5] == ["skill-veil", "scan-file", "/some/file.md", "--format", "json"]
    assert "--no-update-check" in argv
    assert "--no-llm-enrich" in argv
    assert "--no-vt-enrich" in argv
    assert "--no-promptintel-enrich" in argv


def test_build_argv_directory_uses_scan_package(tmp_path):
    argv = _build_argv("skill-veil", str(tmp_path))
    assert argv[1] == "scan-package"


def test_build_argv_opt_in_enrichment_drops_suppression_flags():
    argv = _build_argv("skill-veil", "/f.md", use_llm=True, use_vt=True, use_promptintel=True)
    assert "--no-llm-enrich" not in argv
    assert "--no-vt-enrich" not in argv
    assert "--no-promptintel-enrich" not in argv


def test_build_argv_fp_review_and_sidecar():
    argv = _build_argv(
        "skill-veil", "/f.md", fp_review=True, fp_review_out="/out/fp.json"
    )
    assert "--llm-fp-review" in argv
    i = argv.index("--llm-fp-review-out")
    assert argv[i + 1] == "/out/fp.json"


def test_build_argv_passes_policy_and_extra_args():
    argv = _build_argv(
        "skill-veil",
        "/f.md",
        profile="enterprise",
        fail_on="high",
        rules_dir="/rules",
        extra_args=["--strict-rules"],
    )
    assert argv[argv.index("--profile") + 1] == "enterprise"
    assert argv[argv.index("--fail-on") + 1] == "high"
    assert argv[argv.index("--rules-dir") + 1] == "/rules"
    assert "--strict-rules" in argv


def test_parse_stdout_ignores_trailing_enrichment_text():
    stdout = (
        '[{"verdict": "malicious", "summary": {"risk_score": 90}, "findings": []}]\n'
        "\n=== LLM Enrichment (informational) ===\n"
        "  provider=lmstudio model=qwen packages=1\n"
    )
    parsed = _parse_stdout(stdout)
    assert len(parsed) == 1
    assert parsed[0]["verdict"] == "malicious"


def test_parse_stdout_rejects_empty_output():
    with pytest.raises(ScanError):
        _parse_stdout("   \n")


def test_parse_stdout_rejects_non_array_json():
    with pytest.raises(ScanError):
        _parse_stdout('{"verdict": "benign"}')
