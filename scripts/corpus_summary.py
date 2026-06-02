#!/usr/bin/env python3
"""Derive per-skill JSONL + aggregate summary from `scan-dataset --format json` output.

Reads `<corpus>.raw.json` files produced by `skill-veil scan-dataset` and emits,
for each corpus, a compact `<corpus>.skills.jsonl` (one line per scanned SKILL.md)
plus a combined `summary.json` with verdict distributions, average findings,
top firing rules, and a benign/malicious cross-analysis (approximate FP / FN
rates against the VirusTotal corpus labels).

Usage:
    corpus_summary.py --results-dir DIR --corpora malicious benign github \
        --generated-utc 2026-06-02T20:47:52+00:00
"""

import argparse
import collections
import json
import pathlib
import sys


def load_reports(raw_path: pathlib.Path) -> list[dict]:
    with raw_path.open() as handle:
        data = json.load(handle)
    return data.get("reports", [])


def skill_line(entry: dict) -> dict:
    report = entry["report"]
    rule_ids = sorted({f["rule_id"] for f in report.get("findings", [])})
    return {
        "path": report.get("skill_path", ""),
        "verdict": report.get("verdict", "unknown"),
        "n_findings": len(report.get("findings", [])),
        "rules": rule_ids,
    }


def summarize_corpus(skills: list[dict]) -> dict:
    verdicts = collections.Counter(s["verdict"] for s in skills)
    total = len(skills)
    rule_counter: collections.Counter[str] = collections.Counter()
    findings_total = 0
    for skill in skills:
        findings_total += skill["n_findings"]
        rule_counter.update(skill["rules"])

    def pct(n: int) -> float:
        return round(100.0 * n / total, 1) if total else 0.0

    return {
        "skills": total,
        "verdicts": dict(verdicts),
        "verdict_pct": {k: pct(v) for k, v in verdicts.items()},
        "avg_findings": round(findings_total / total, 2) if total else 0.0,
        "top_rules": rule_counter.most_common(15),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", required=True, type=pathlib.Path)
    parser.add_argument("--corpora", nargs="+", required=True)
    parser.add_argument("--generated-utc", required=True)
    parser.add_argument(
        "--rules-note",
        default="official skill-veil-rules pack loaded from ./rules/official/ (dev fallback)",
    )
    args = parser.parse_args()

    corpora_summary: dict[str, dict] = {}
    for corpus in args.corpora:
        raw_path = args.results_dir / f"{corpus}.raw.json"
        if not raw_path.exists():
            print(f"warning: missing {raw_path}", file=sys.stderr)
            continue
        reports = load_reports(raw_path)
        skills = [skill_line(entry) for entry in reports]
        jsonl_path = args.results_dir / f"{corpus}.skills.jsonl"
        with jsonl_path.open("w") as handle:
            for skill in skills:
                handle.write(json.dumps(skill, sort_keys=True) + "\n")
        corpora_summary[corpus] = summarize_corpus(skills)
        print(f"{corpus}: {len(skills)} skills -> {jsonl_path.name}", file=sys.stderr)

    cross = {}
    if "benign" in corpora_summary:
        b = corpora_summary["benign"]
        non_benign = b["verdicts"].get("suspicious", 0) + b["verdicts"].get("malicious", 0)
        cross["benign_corpus_flagged_non_benign_pct"] = (
            round(100.0 * non_benign / b["skills"], 1) if b["skills"] else 0.0
        )
        cross["benign_corpus_flagged_malicious_pct"] = b["verdict_pct"].get("malicious", 0.0)
    if "malicious" in corpora_summary:
        m = corpora_summary["malicious"]
        cross["malicious_corpus_called_benign_pct"] = m["verdict_pct"].get("benign", 0.0)
    cross["note"] = (
        "benign->non-benign approximates FP rate; "
        "malicious->benign approximates FN rate (vs VT labels)."
    )

    summary = {
        "generated_utc": args.generated_utc,
        "config": {
            "scanner_only": True,
            "llm": False,
            "vt": False,
            "nova_semantics": False,
            "rules": args.rules_note,
        },
        "corpora": corpora_summary,
        "cross_analysis": cross,
    }
    out_path = args.results_dir / "summary.json"
    with out_path.open("w") as handle:
        json.dump(summary, handle, indent=2)
    print(f"wrote {out_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
