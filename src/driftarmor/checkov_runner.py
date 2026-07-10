"""Subprocess wrapper around Checkov for terraform plan JSON."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

# Stable Checkov IDs for DriftArmor external policies (must match policies/aks/).
CHECKOV_CHECK_IDS: tuple[str, ...] = (
    "CKV_DRIFTARMOR_AKS_1",  # aks.cluster.present
    "CKV_DRIFTARMOR_AKS_2",  # aks.node_pool.present
    "CKV_DRIFTARMOR_AKS_3",  # aks.monitor.oms_or_dcr (oms_agent path)
    "CKV_DRIFTARMOR_AKS_4",  # aks.rbac.azure_rbac
    "CKV_DRIFTARMOR_AKS_5",  # aks.network.private_or_authorized
)


class CheckovNotFoundError(RuntimeError):
    """Raised when the checkov executable is not on PATH."""


class CheckovRunError(RuntimeError):
    """Raised when checkov exits with an unexpected error or invalid JSON."""


def default_policies_dir() -> Path:
    """Resolve policies/aks relative to the repo (src layout) or install layout."""
    here = Path(__file__).resolve()
    candidates = [
        here.parents[2] / "policies" / "aks",  # .../src/driftarmor -> repo
        here.parents[1] / "policies" / "aks",
        Path.cwd() / "policies" / "aks",
    ]
    for path in candidates:
        if path.is_dir():
            return path
    return candidates[0]


def run_checkov(
    plan_path: Path,
    *,
    policies_dir: Path | None = None,
    checkov_bin: str | None = None,
) -> dict[str, Any]:
    """
    Run checkov against a terraform show -json plan file.

    Returns the parsed Checkov JSON report (single check_type object).
    """
    binary = checkov_bin or shutil.which("checkov")
    if not binary:
        raise CheckovNotFoundError(
            "checkov not found on PATH. Install with: pip install 'driftarmor' "
            "(checkov is a package dependency) or ensure the virtualenv is active."
        )

    policies = policies_dir or default_policies_dir()
    if not policies.is_dir():
        raise CheckovRunError(f"policies directory not found: {policies}")

    cmd = [
        binary,
        "-f",
        str(plan_path),
        "--framework",
        "terraform_plan",
        "--external-checks-dir",
        str(policies),
        "-c",
        ",".join(CHECKOV_CHECK_IDS),
        "-o",
        "json",
        "--compact",
    ]

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
