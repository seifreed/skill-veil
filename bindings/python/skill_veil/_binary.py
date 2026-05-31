"""Locate the ``skill-veil`` binary the bindings drive."""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Optional


class BinaryNotFoundError(FileNotFoundError):
    """Raised when no ``skill-veil`` binary can be located."""


_ENV_VAR = "SKILL_VEIL_BIN"


def _candidate_target_paths() -> list[Path]:
    """Cargo build outputs relative to this file, for an in-repo checkout
    (``bindings/python/skill_veil/_binary.py`` → repo root is three
    parents up)."""
    repo_root = Path(__file__).resolve().parents[3]
    exe = "skill-veil.exe" if os.name == "nt" else "skill-veil"
    return [
        repo_root / "target" / "release" / exe,
        repo_root / "target" / "debug" / exe,
    ]


def find_binary(explicit: Optional[str] = None) -> str:
    """Resolve the ``skill-veil`` executable.

    Resolution order: explicit argument, the ``SKILL_VEIL_BIN`` env var,
    a ``skill-veil`` on ``PATH``, then the cargo ``release``/``debug``
    build outputs of an in-repo checkout. Raises
    :class:`BinaryNotFoundError` if none resolve.
    """
    for candidate in (explicit, os.environ.get(_ENV_VAR)):
        if candidate:
            path = Path(candidate)
            if path.is_file():
                return str(path)
            raise BinaryNotFoundError(
                f"skill-veil binary not found at configured path: {candidate}"
            )

    on_path = shutil.which("skill-veil")
    if on_path:
        return on_path

    for candidate in _candidate_target_paths():
        if candidate.is_file():
            return str(candidate)

    raise BinaryNotFoundError(
        "could not locate the skill-veil binary. Install it (cargo install "
        "--path crates/skill-veil-cli), put it on PATH, or set the "
        f"{_ENV_VAR} environment variable."
    )
