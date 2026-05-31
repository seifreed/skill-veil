"""Drive the ``skill-veil`` binary and parse its JSON output.

The scanner prints the structured JSON payload first on stdout, then —
when VT / LLM / PromptIntel enrichment is active — appends human-readable
text blocks. :func:`_parse_stdout` therefore decodes only the leading
JSON document and ignores any trailing text, so the binding stays robust
whether or not the operator has enrichment configured.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from ._binary import find_binary


class ScanError(RuntimeError):
    """Raised when the scanner fails to run or returns unparseable output."""


_USAGE_OR_INTERNAL_EXIT = 2


def _subcommand_for(path: str) -> str:
    """``scan-package`` for a directory, ``scan-file`` for anything else.
    Both accept the same flag set."""
    return "scan-package" if os.path.isdir(path) else "scan-file"


def _build_argv(
    binary: str,
    path: str,
    *,
    use_llm: bool = False,
    use_vt: bool = False,
    use_promptintel: bool = False,
    fp_review: bool = False,
    fp_review_out: Optional[str] = None,
    rules_dir: Optional[str] = None,
    profile: Optional[str] = None,
    fail_on: Optional[str] = None,
    no_update_check: bool = True,
    extra_args: Optional[Sequence[str]] = None,
) -> List[str]:
    """Assemble the argv for one scan. Enrichment that pollutes stdout is
    disabled by default for clean, fast, offline parsing; opt in per
    channel. Pure — unit-tested without running the binary."""
    argv = [binary, _subcommand_for(path), str(path), "--format", "json"]
    if no_update_check:
        argv.append("--no-update-check")
    if not use_llm:
        argv.append("--no-llm-enrich")
    if not use_vt:
        argv.append("--no-vt-enrich")
    if not use_promptintel:
        argv.append("--no-promptintel-enrich")
    if fp_review:
        argv.append("--llm-fp-review")
        if fp_review_out:
            argv.extend(["--llm-fp-review-out", str(fp_review_out)])
    if rules_dir:
        argv.extend(["--rules-dir", str(rules_dir)])
    if profile:
        argv.extend(["--profile", profile])
    if fail_on:
        argv.extend(["--fail-on", fail_on])
    if extra_args:
        argv.extend(extra_args)
    return argv


def _parse_stdout(stdout: str) -> List[Dict[str, Any]]:
    """Decode the leading JSON array, ignoring any trailing enrichment
    text. Raises :class:`ScanError` if no JSON document is present."""
    text = stdout.lstrip()
    if not text:
        raise ScanError("scanner produced no output to parse")
    try:
        value, _ = json.JSONDecoder().raw_decode(text)
    except json.JSONDecodeError as exc:
        raise ScanError(f"could not parse scanner JSON output: {exc}") from exc
    if not isinstance(value, list):
        raise ScanError(
            f"expected a JSON array of package reports, got {type(value).__name__}"
        )
    return value


def run_scan(
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
) -> List[Dict[str, Any]]:
    """Run a scan and return the parsed list of per-package report dicts.

    A non-zero exit only means findings crossed the fail threshold (a
    *blocked* package) — that is a normal result, so the output is parsed
    regardless. Only a usage/internal error (exit >= 2) with no JSON on
    stdout raises :class:`ScanError`.
    """
    resolved = find_binary(binary)
    argv = _build_argv(
        resolved,
        str(path),
        use_llm=use_llm,
        use_vt=use_vt,
        use_promptintel=use_promptintel,
        fp_review=fp_review,
        fp_review_out=str(fp_review_out) if fp_review_out else None,
        rules_dir=str(rules_dir) if rules_dir else None,
        profile=profile,
        fail_on=fail_on,
        extra_args=extra_args,
    )
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ScanError(f"scanner timed out after {timeout}s") from exc

    if not completed.stdout.strip():
        if completed.returncode >= _USAGE_OR_INTERNAL_EXIT:
            raise ScanError(
                f"scanner failed (exit {completed.returncode}): "
                f"{completed.stderr.strip() or 'no stderr'}"
            )
        raise ScanError("scanner produced no output on stdout")

    return _parse_stdout(completed.stdout)
