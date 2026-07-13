"""Subprocess wrapper around Checkov for terraform plan JSON."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Sequence

from driftarmor.packs import PACKS, Pack


class CheckovNotFoundError(RuntimeError):
    """Raised when the checkov executable is not on PATH."""


class CheckovRunError(RuntimeError):
    """Raised when checkov exits with an unexpected error or invalid JSON."""


def policies_root() -> Path:
    """Resolve policies/ relative to the repo (src layout) or install layout."""
    here = Path(__file__).resolve()
    candidates = [
        here.parents[2] / "policies",  # .../src/driftarmor -> repo
        here.parents[1] / "policies",
        Path.cwd() / "policies",
    ]
    for path in candidates:
        if path.is_dir():
            return path
    return candidates[0]


def default_policies_dir() -> Path:
    """Backward-compatible path to the AKS policy pack."""
    return policies_root() / "aks"


def policy_dirs_for_packs(packs: Sequence[Pack], *, root: Path | None = None) -> list[Path]:
    base = root or policies_root()
    dirs: list[Path] = []
    for pack in packs:
        path = base / pack.policies_subdir
        if not path.is_dir():
            raise CheckovRunError(f"policies directory not found: {path}")
        dirs.append(path)
    return dirs


def run_checkov(
    plan_path: Path,
    *,
    packs: Sequence[Pack] | None = None,
    policies_dir: Path | None = None,
    checkov_bin: str | None = None,
) -> dict[str, Any]:
    """
    Run checkov against a terraform show -json plan file.

    When ``packs`` is provided, loads each pack's external checks dir and
    filters to that pack's Checkov IDs. Legacy ``policies_dir`` still works
    for a single directory (AKS IDs only).

    Returns the parsed Checkov JSON report (single check_type object).
    """
    binary = checkov_bin or shutil.which("checkov")
    if not binary:
        raise CheckovNotFoundError(
            "checkov not found on PATH. Install with: pip install 'driftarmor' "
            "(checkov is a package dependency) or ensure the virtualenv is active."
        )

    active = list(packs) if packs is not None else [p for p in PACKS if p.id == "aks"]
    if not active:
        raise CheckovRunError("no policy packs to evaluate")

    if policies_dir is not None:
        dirs = [policies_dir]
        check_ids = list(active[0].checkov_ids)
    else:
        dirs = policy_dirs_for_packs(active)
        check_ids = [cid for pack in active for cid in pack.checkov_ids]

    cmd = [
        binary,
        "-f",
        str(plan_path),
        "--framework",
        "terraform_plan",
    ]
    for d in dirs:
        cmd.extend(["--external-checks-dir", str(d)])
    cmd.extend(
        [
            "-c",
            ",".join(check_ids),
            "-o",
            "json",
            "--compact",
        ]
    )

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise CheckovRunError(f"failed to execute checkov: {exc}") from exc

    # Checkov exits 1 when checks fail; that is expected. Other codes are errors.
    if proc.returncode not in (0, 1):
        detail = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
        raise CheckovRunError(f"checkov failed: {detail}")

    stdout = (proc.stdout or "").strip()
    if not stdout:
        raise CheckovRunError(
            f"checkov produced no JSON output. stderr: {(proc.stderr or '').strip()}"
        )

    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise CheckovRunError(f"checkov returned invalid JSON: {exc}") from exc

    # checkov may return a list when multiple frameworks; we request one.
    if isinstance(payload, list):
        if not payload:
            raise CheckovRunError("checkov returned an empty report list")
        payload = payload[0]
    if not isinstance(payload, dict):
        raise CheckovRunError("checkov JSON root must be an object or list of objects")

    # Empty / summary-only payloads mean the plan was not parsed as terraform_plan.
    if "results" not in payload:
        raise CheckovRunError(
            "checkov returned a summary without results; ensure the file is "
            "`terraform show -json` output including planned_values"
        )

    return payload
