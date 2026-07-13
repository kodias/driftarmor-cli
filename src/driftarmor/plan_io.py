"""Load terraform show -json plan files (raw validation only)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class PlanLoadError(Exception):
    """Plan file missing, unreadable, or not a JSON object."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def load_plan_json(path: Path) -> dict[str, Any]:
    """Read UTF-8 JSON plan; root must be an object.

    Does not interpret resource_changes or AKS semantics.
    """
    if not path.is_file():
        raise PlanLoadError(f"plan file not found: {path}")

    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PlanLoadError(f"cannot read plan: {exc}") from exc

    try:
        plan = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PlanLoadError(f"invalid plan JSON: {exc}") from exc

    if not isinstance(plan, dict):
        raise PlanLoadError("plan JSON root must be an object")

    return plan
