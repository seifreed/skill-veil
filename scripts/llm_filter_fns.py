#!/usr/bin/env python3
"""
Multi-provider LLM cross-check for the VT-flagged corpus.

For every sample that VirusTotal labelled `malicious`, this script
queries multiple LLM providers (default: grok, openai, anthropic) and
applies a strict consensus rule before accepting the sample as a
mislabel candidate.

Consensus rule (all must hold):
  1. Every queried provider returns verdict == "benign".
  2. Every provider's confidence is >= LLM_HARD_THRESHOLD (default 0.85).
  3. At least one provider's confidence is >= LLM_HIGH_CONFIDENCE
     (default 0.90).

Samples that pass the rule are written to
`benchmarks/vt-baseline-overrides.yaml` (schema 2.0) with per-provider
audit trail. Samples that fail the rule are recorded in
`benchmarks/multi-llm-audit.yaml` with the rejection reason and
each provider's vote — they revert to their original VT label
(`malicious`) in the baseline.

See `benchmarks/CLAUDE.md` for the full workflow.
"""

from __future__ import annotations

import argparse
import datetime as dt
import glob
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BASELINE = REPO / "benchmarks" / "vt-baseline.json"
OVERRIDES = REPO / "benchmarks" / "vt-baseline-overrides.yaml"
AUDIT = REPO / "benchmarks" / "multi-llm-audit.yaml"
CACHE = REPO / "benchmarks" / ".multi-llm-cache.json"
SKILL_VEIL_BIN = REPO / "target" / "release" / "skill-veil"

LLM_VERDICT_RE = re.compile(
    r"llm\s+verdict\s*:\s*(?P<verdict>benign|suspicious|malicious)\s+"
    r"\(confidence\s+(?P<confidence>[\d.]+)\)",
    re.IGNORECASE,
)
LLM_MODEL_RE = re.compile(
    r"llm\s+model\s*:\s*(?P<model>[\w./:-]+)",
    re.IGNORECASE,
)

DEFAULT_PROVIDERS = ("grok", "openai", "anthropic")
HARD_THRESHOLD = 0.85
HIGH_CONFIDENCE = 0.90


def _require_yaml():
    try:
        import yaml  # type: ignore

        return yaml
    except ImportError:
        sys.exit("PyYAML required: pip install pyyaml")


def load_baseline() -> dict:
    return json.loads(BASELINE.read_text())


def vt_malicious_samples(baseline: dict, include_already_flipped: bool) -> list[dict]:
    """Return the candidate set:
    - Always: VT-malicious samples that skill-veil classified as benign
      (current FN bucket — `expected == malicious AND actual == benign`).
    - When include_already_flipped: samples whose `original_expected ==
      malicious` but were already flipped to `expected == benign` via a
      prior override run. These get re-validated under the new consensus.
    """
    rows = []
    for s in baseline["samples"]:
        expected = s.get("expected")
        actual = s.get("actual")
        original = s.get("original_expected")
        if expected == "malicious" and actual == "benign":
            rows.append(s)
            continue
        if include_already_flipped and original == "malicious" and expected == "benign":
            rows.append(s)
    return rows


def load_existing_overrides() -> dict:
    yaml = _require_yaml()
    if not OVERRIDES.is_file():
        return {"schema_version": "2.0", "overrides": []}
    return yaml.safe_load(OVERRIDES.read_text()) or {
        "schema_version": "2.0",
        "overrides": [],
    }


def existing_override_shas(doc: dict) -> set[str]:
    return {o["sha256"] for o in doc.get("overrides", [])}


def load_cache() -> dict:
    if not CACHE.is_file():
        return {}
    try:
        return json.loads(CACHE.read_text())
    except json.JSONDecodeError:
        return {}


def write_cache(cache: dict) -> None:
    CACHE.write_text(json.dumps(cache, indent=2, sort_keys=True))


def cache_key(sha256: str, provider: str) -> str:
    return f"{sha256}:{provider}"


def resolve_skill(sample_path: str) -> Path | None:
    base = sample_path.replace("benchmarks/../", "")
    abs_base = REPO / base
    for name in ("SKILL.md", "Skill.md", "skill.md"):
        p = abs_base / name
        if p.is_file():
            return p
    matches = sorted(glob.glob(str(abs_base / "*.md")))
    return Path(matches[0]) if matches else None


def scan_with_provider(skill: Path, provider: str, timeout: int = 180) -> str | None:
    """Run skill-veil scan with the given LLM provider override.
    Returns merged stdout (verdict block parsed downstream)."""
    env = {**os.environ, "NO_COLOR": "1"}
    out = subprocess.run(
        [
            str(SKILL_VEIL_BIN),
            "scan",
            str(skill),
            "--no-vt-enrich",
            "--llm-provider",
            provider,
            "--format",
            "text",
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )
    return out.stdout


def parse_llm_block(stdout: str) -> dict | None:
    match = LLM_VERDICT_RE.search(stdout or "")
    if not match:
        return None
    model_match = LLM_MODEL_RE.search(stdout or "")
    return {
        "verdict": match.group("verdict").lower(),
        "confidence": float(match.group("confidence")),
        "model": model_match.group("model") if model_match else None,
    }


def consensus_passes(verdicts: dict[str, dict | None]) -> tuple[bool, str]:
    """Apply the strict consensus rule. Returns (passed, rejection_reason).
    rejection_reason is empty when passed."""
    for provider, v in verdicts.items():
        if v is None:
            return False, f"{provider} returned no LLM block"
        if v.get("error"):
            return False, f"{provider} errored: {v['error']}"
        if v["verdict"] != "benign":
            return False, (
                f"{provider} verdict={v['verdict']} (conf={v['confidence']:.2f})"
            )
        if v["confidence"] < HARD_THRESHOLD:
            return False, (
                f"{provider} below hard threshold "
                f"(conf={v['confidence']:.2f} < {HARD_THRESHOLD})"
            )
    if not any(v["confidence"] >= HIGH_CONFIDENCE for v in verdicts.values()):
        return False, (
            f"no provider reached high-confidence bar ({HIGH_CONFIDENCE}); "
            f"max conf={max(v['confidence'] for v in verdicts.values()):.2f}"
        )
    return True, ""


def query_sample(
    sample: dict,
    providers: tuple[str, ...],
    cache: dict,
    timeout: int,
    use_cache: bool,
) -> dict[str, dict | None]:
    sha = sample.get("id") or sample.get("sha256") or ""
    skill = resolve_skill(sample.get("path", ""))
    verdicts: dict[str, dict | None] = {}
    if skill is None:
        return {p: {"error": "skill file not found"} for p in providers}
    for prov in providers:
        key = cache_key(sha, prov)
        if use_cache and key in cache:
            verdicts[prov] = cache[key]
            continue
        try:
            stdout = scan_with_provider(skill, prov, timeout=timeout)
        except subprocess.TimeoutExpired:
            verdicts[prov] = {"error": "timeout"}
            continue
        except OSError as exc:
            verdicts[prov] = {"error": f"subprocess failed: {exc}"}
            continue
        parsed = parse_llm_block(stdout or "")
        if parsed is None:
            verdicts[prov] = {"error": "no llm block in scan output"}
        else:
            parsed["queried_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
            verdicts[prov] = parsed
        cache[key] = verdicts[prov]
    return verdicts


def build_override_entry(sample: dict, verdicts: dict[str, dict]) -> dict:
    sha = sample.get("id") or sample.get("sha256") or ""
    return {
        "sha256": sha,
        "sha_short": sha[:12],
        "skill_path": sample.get("path", ""),
        "new_label": "benign",
        "source": "multi_llm_consensus",
        "consensus_rule": (
            f"unanimous_benign + at_least_one >= {HIGH_CONFIDENCE}"
        ),
        "hard_threshold": HARD_THRESHOLD,
        "high_confidence": HIGH_CONFIDENCE,
        "verdicts": verdicts,
        "reason": (
            f"All {len(verdicts)} providers returned benign at confidence "
            f">= {HARD_THRESHOLD}, at least one >= {HIGH_CONFIDENCE}"
        ),
    }


def build_audit_entry(
    sample: dict,
    verdicts: dict[str, dict | None],
    passed: bool,
    rejection_reason: str,
) -> dict:
    sha = sample.get("id") or sample.get("sha256") or ""
    return {
        "sha256": sha,
        "sha_short": sha[:12],
        "skill_path": sample.get("path", ""),
        "consensus_passed": passed,
        "rejection_reason": rejection_reason,
        "verdicts": verdicts,
    }


def write_overrides(entries: list[dict], providers: tuple[str, ...]) -> None:
    yaml = _require_yaml()
    doc = {
        "schema_version": "2.0",
        "description": (
            "Multi-LLM consensus mislabel overrides for vt-baseline.json. "
            "Each entry passed unanimous-benign agreement across the "
            "configured LLM providers (see consensus_rule). Samples that "
            "did not pass consensus are recorded in multi-llm-audit.yaml "
            "and revert to their VT label."
        ),
        "generated_by": "scripts/llm_filter_fns.py",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "providers": list(providers),
        "hard_threshold": HARD_THRESHOLD,
        "high_confidence": HIGH_CONFIDENCE,
        "overrides": entries,
    }
    OVERRIDES.write_text(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True))


def write_audit(entries: list[dict], providers: tuple[str, ...]) -> None:
    yaml = _require_yaml()
    doc = {
        "schema_version": "1.0",
        "description": (
            "Per-sample multi-LLM cross-check log. Includes both passing "
            "and rejected samples for full audit trail. regenerate_baseline.py "
            "does NOT read this file — see vt-baseline-overrides.yaml for "
            "the active overrides."
        ),
        "generated_by": "scripts/llm_filter_fns.py",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "providers": list(providers),
        "hard_threshold": HARD_THRESHOLD,
        "high_confidence": HIGH_CONFIDENCE,
        "runs": entries,
    }
    AUDIT.write_text(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True))


def preflight_providers(providers: tuple[str, ...]) -> None:
    """Fail fast if any provider lacks credentials. Surfaces actionable
    error before burning hours scanning."""
    env_keys = {
        "grok": ("XAI_API_KEY", "GROK_API_KEY"),
        "openai": ("OPENAI_API_KEY",),
        "anthropic": ("ANTHROPIC_API_KEY",),
        "lmstudio": (),
        "ollama": (),
    }
    missing = []
    for prov in providers:
        keys = env_keys.get(prov, ())
        if not keys:
            continue
        if not any(os.environ.get(k) for k in keys):
            missing.append((prov, keys))
    if missing:
        lines = ["Missing API credentials:"]
        for prov, keys in missing:
            lines.append(
                f"  - {prov}: set one of {', '.join(keys)} or configure "
                f"~/.skill-veil.toml [llm.{prov}] api_key"
            )
        lines.append(
            "If credentials are stored in ~/.skill-veil.toml, this preflight "
            "may be a false alarm — pass --skip-preflight to bypass."
        )
        sys.exit("\n".join(lines))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--providers",
        default=",".join(DEFAULT_PROVIDERS),
        help=(
            "Comma-separated provider list to query "
            f"(default: {','.join(DEFAULT_PROVIDERS)})"
        ),
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Process at most N samples (debugging)",
    )
    parser.add_argument(
        "--include-existing-overrides",
        action="store_true",
        default=True,
        help=(
            "Re-query providers for samples already in overrides.yaml. "
            "Default true: existing single-LLM overrides must survive the "
            "multi-provider consensus to remain valid."
        ),
    )
    parser.add_argument(
        "--no-include-existing-overrides",
        dest="include_existing_overrides",
        action="store_false",
        help="Only query the residual FNs; leave existing overrides untouched",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Ignore the verdict cache and re-query every provider",
    )
    parser.add_argument(
        "--skip-preflight",
        action="store_true",
        help="Skip the API-key preflight check",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print summary without writing overrides/audit/cache files",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=5,
        help="Log progress every N samples",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=180,
        help="Per-provider scan timeout in seconds",
    )
    args = parser.parse_args()

    if not SKILL_VEIL_BIN.is_file():
        sys.exit(
            f"skill-veil binary not found at {SKILL_VEIL_BIN}; "
            "run `cargo build -p skill-veil --release` first"
        )

    providers = tuple(p.strip() for p in args.providers.split(",") if p.strip())
    if not providers:
        sys.exit("--providers must list at least one provider")

    if not args.skip_preflight:
        preflight_providers(providers)

    baseline = load_baseline()
    samples = vt_malicious_samples(baseline, args.include_existing_overrides)

    if args.include_existing_overrides:
        existing = load_existing_overrides()
        existing_map = {o["sha256"]: o for o in existing.get("overrides", [])}
        seen = {s.get("id") for s in samples}
        for sha, entry in existing_map.items():
            if sha not in seen:
                samples.append(
                    {
                        "id": sha,
                        "path": entry.get("skill_path", ""),
                        "expected": "malicious",
                        "actual": "benign",
                    }
                )

    full_set_size = len(samples)
    if args.limit:
        samples = samples[: args.limit]

    is_partial_run = args.limit is not None and len(samples) < full_set_size

    if is_partial_run and not args.dry_run:
        print(
            f"\n[SAFETY] --limit {args.limit} produces a partial run "
            f"({len(samples)}/{full_set_size}). Refusing to overwrite "
            f"{OVERRIDES.name} with an incomplete result.\n"
            f"          The audit log and cache will still be written so "
            f"you can iterate. Pass --dry-run to silence this message, or "
            f"drop --limit for the canonical run.",
            flush=True,
        )

    print(
        f"Cross-checking {len(samples)} samples across providers: "
        f"{', '.join(providers)}",
        flush=True,
    )

    cache = {} if args.no_cache else load_cache()
    passing_overrides: list[dict] = []
    audit_runs: list[dict] = []
    rejected_count = 0

    for i, sample in enumerate(samples, 1):
        sha = sample.get("id") or sample.get("sha256") or ""
        if not sha:
            continue
        verdicts = query_sample(
            sample, providers, cache, timeout=args.timeout, use_cache=not args.no_cache
        )
        passed, reason = consensus_passes(verdicts)
        audit_runs.append(build_audit_entry(sample, verdicts, passed, reason))
        if passed:
            passing_overrides.append(build_override_entry(sample, verdicts))
        else:
            rejected_count += 1
        if i % args.progress_every == 0 or i == len(samples):
            print(
                f"  {i}/{len(samples)}: passing={len(passing_overrides)} "
                f"rejected={rejected_count}",
                flush=True,
            )
        if not args.no_cache and not args.dry_run and i % 25 == 0:
            write_cache(cache)

    print(
        f"\nFINAL: passing={len(passing_overrides)} rejected={rejected_count} "
        f"total={len(samples)}",
        flush=True,
    )

    if args.dry_run:
        for o in passing_overrides[:5]:
            confs = ", ".join(
                f"{p}={v['confidence']:.2f}"
                for p, v in o["verdicts"].items()
                if isinstance(v, dict) and "confidence" in v
            )
            print(f"  candidate {o['sha_short']} ({confs})")
        return 0

    if is_partial_run:
        write_audit(audit_runs, providers)
        if not args.no_cache:
            write_cache(cache)
        print(
            f"Skipped overrides write (partial run). Audit: {AUDIT}",
            flush=True,
        )
        return 0

    write_overrides(passing_overrides, providers)
    write_audit(audit_runs, providers)
    if not args.no_cache:
        write_cache(cache)
    print(
        f"Wrote {len(passing_overrides)} overrides to {OVERRIDES}\n"
        f"Wrote {len(audit_runs)} audit runs to {AUDIT}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
