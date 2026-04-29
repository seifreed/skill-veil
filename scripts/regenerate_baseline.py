#!/usr/bin/env python3
"""
Apply mislabel overrides to `benchmarks/vt-baseline.json` in place.

Reads `benchmarks/vt-baseline-overrides.yaml`, then for each sample
whose SHA appears in the overrides flips `expected` to the provided
`new_label` and stamps `relabel_reason` / `relabel_source` /
`original_expected` for audit. Recomputes the metrics block from
scratch over the relabeled samples and rewrites the baseline JSON.

The operation is idempotent: re-running with the same overrides set
produces the same baseline. New overrides accumulate naturally.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BASELINE = REPO / "benchmarks" / "vt-baseline.json"
OVERRIDES = REPO / "benchmarks" / "vt-baseline-overrides.yaml"


def load_overrides_map() -> dict:
    if not OVERRIDES.is_file():
        return {}
    try:
        import yaml  # type: ignore
    except ImportError:
        sys.exit("PyYAML required: pip install pyyaml")
    doc = yaml.safe_load(OVERRIDES.read_text()) or {}
    return {o["sha256"]: o for o in doc.get("overrides", []) if "sha256" in o}


def is_positive(label: str) -> bool:
    return label in ("malicious", "suspicious")


def recompute_metrics(samples: list[dict]) -> dict:
    tp = sum(
        1
        for s in samples
        if s.get("expected") == "malicious" and is_positive(s.get("actual", ""))
    )
    fn = sum(
        1
        for s in samples
        if s.get("expected") == "malicious" and s.get("actual") == "benign"
    )
    fp = sum(
        1
        for s in samples
        if s.get("expected") == "benign" and is_positive(s.get("actual", ""))
    )
    tn = sum(
        1
        for s in samples
        if s.get("expected") == "benign" and s.get("actual") == "benign"
    )
    total = tp + fn + fp + tn
    return {
        "precision": (tp / (tp + fp)) if (tp + fp) else 1.0,
        "recall": (tp / (tp + fn)) if (tp + fn) else 1.0,
        "false_positive_rate": (fp / (fp + tn)) if (fp + tn) else 0.0,
        "accuracy": ((tp + tn) / total) if total else 1.0,
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
    }


def recompute_coverage(samples: list[dict]) -> dict:
    by_label: dict[str, int] = {}
    for s in samples:
        by_label[s.get("expected", "unknown")] = by_label.get(
            s.get("expected", "unknown"), 0
        ) + 1
    return {
        "total_samples": len(samples),
        "by_label": by_label,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--print-only",
        action="store_true",
        help="Skip writing the baseline; print metrics summary",
    )
    args = parser.parse_args()

    base = json.loads(BASELINE.read_text())
    overrides = load_overrides_map()
    print(f"Loaded {len(base.get('samples', []))} samples from {BASELINE.name}")
    print(f"Loaded {len(overrides)} overrides from {OVERRIDES.name}")

    relabeled: list[dict] = []
    applied = 0
    reverted = 0
    for s in base.get("samples", []):
        new = dict(s)
        sha = s.get("id") or s.get("sha256") or ""
        # Reset previously-applied flips to their original VT label before
        # re-applying. This is the only way `regenerate_baseline.py` is
        # idempotent when overrides are REMOVED between runs (e.g. a stricter
        # consensus rule rejects a sample that the previous run accepted).
        if "original_expected" in new and sha not in overrides:
            new["expected"] = new["original_expected"]
            for stale in ("relabel_reason", "relabel_source", "relabel_confidence"):
                new.pop(stale, None)
            reverted += 1
        if sha in overrides:
            o = overrides[sha]
            # Preserve the original expected the FIRST time we relabel; on
            # subsequent runs keep whatever original_expected was already
            # recorded so the audit trail tracks the VT source-of-truth.
            new.setdefault("original_expected", s.get("expected"))
            new["expected"] = o["new_label"]
            new["relabel_reason"] = o.get("reason", "")
            new["relabel_source"] = o.get("source", "")
            new["relabel_confidence"] = o.get("confidence")
            applied += 1
        relabeled.append(new)
    if reverted:
        print(f"Reverted {reverted} previously-flipped samples to their VT label")

    old_metrics = base.get("metrics", {})
    metrics = recompute_metrics(relabeled)
    coverage = recompute_coverage(relabeled)

    out = {
        "schema_version": base.get("schema_version", "1.0"),
        "overrides_file": OVERRIDES.name,
        "overrides_applied": applied,
        "regenerated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "metrics": metrics,
        "coverage": coverage,
        "samples": relabeled,
    }

    print("\nMetrics comparison (before → after relabel):")
    for key in (
        "precision",
        "recall",
        "false_positive_rate",
        "accuracy",
        "true_positive",
        "false_negative",
        "true_negative",
        "false_positive",
    ):
        old = old_metrics.get(key)
        new = metrics.get(key)
        if isinstance(old, float) and isinstance(new, float):
            diff = new - old
            print(f"  {key:<20s}: {old:.4f} → {new:.4f} ({diff:+.4f})")
        else:
            print(f"  {key:<20s}: {old} → {new}")

    if args.print_only:
        return 0

    BASELINE.write_text(json.dumps(out, indent=2))
    print(f"\nWrote {BASELINE} ({applied} overrides applied)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
