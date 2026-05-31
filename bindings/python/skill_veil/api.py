"""High-level scan API."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from ._runner import run_scan
from .models import ScanReport


def scan(
    path: "str | Path",
    *,
    binary: Optional[str] = None,
    use_llm: bool = False,
    use_vt: bool = False,
    use_promptintel: bool = False,
    fp_review: bool = False,
    fp_review_out: "str | Path | None" = None,
    rules_dir: "str | Path | None" = None,
    profile: Optional[str] = None,
    fail_on: Optional[str] = None,
    timeout: Optional[float] = 300,
    extra_args: Optional[Sequence[str]] = None,
) -> ScanReport:
    """Scan a skill file, package directory, or manifest and return a
    typed :class:`~skill_veil.models.ScanReport`.

    Enrichment that depends on network or local services is off by
    default; opt in with ``use_llm`` / ``use_vt`` / ``use_promptintel``.
    The verdict is always the scanner's own — ``use_llm`` and
    ``fp_review`` are advisory and never change it.
    """
    raw = run_scan(
        path,
        binary=binary,
        use_llm=use_llm,
        use_vt=use_vt,
        use_promptintel=use_promptintel,
        fp_review=fp_review,
        fp_review_out=fp_review_out,
        rules_dir=rules_dir,
        profile=profile,
        fail_on=fail_on,
        timeout=timeout,
        extra_args=extra_args,
    )
    return ScanReport.from_raw(raw)


def scan_raw(path: "str | Path", **kwargs: Any) -> List[Dict[str, Any]]:
    """Scan and return the untyped list of per-package report dicts —
    the exact JSON the scanner emits. Accepts the same keyword arguments
    as :func:`scan`."""
    return run_scan(path, **kwargs)
