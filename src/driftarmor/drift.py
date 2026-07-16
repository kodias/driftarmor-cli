"""Plan JSON resource_changes → DriftArmor drift report (destructive-change gate)."""

from __future__ import annotations

from typing import Any, Literal

from driftarmor.packs import (
    PRODUCT_ORDER,
    PRODUCT_TITLES,
    product_for_resource_type,
)

ActionClass = Literal["create", "update", "delete", "replace"]

_SILENT_SKIP = frozenset({"read", "no-op"})
_SINGLE = frozenset({"create", "update", "delete"})


class UnknownActionsError(Exception):
    """Terraform change.actions shape we do not recognize (fail closed)."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def normalize_actions(actions: list[str] | None) -> ActionClass | None:
    """Map Terraform change.actions to action_class.

    Returns None for silent skips (read, no-op, empty/missing).
    Raises UnknownActionsError for unrecognized shapes.
    """
    if not actions:
        return None
    if not isinstance(actions, list):
        raise UnknownActionsError(f"change.actions must be a list, got {type(actions).__name__}")

    cleaned = [str(a) for a in actions]
    if len(cleaned) == 1:
        action = cleaned[0]
        if action in _SILENT_SKIP:
            return None
        if action in _SINGLE:
            return action  # type: ignore[return-value]
        raise UnknownActionsError(f"unknown action: {action!r}")

    if len(cleaned) == 2:
        pair = set(cleaned)
        if pair == {"delete", "create"}:
            return "replace"
        raise UnknownActionsError(f"unknown multi-action list: {cleaned!r}")

    raise UnknownActionsError(f"unknown multi-action list: {cleaned!r}")


def _action_summary(rows: list[dict[str, Any]]) -> dict[str, int]:
    summary = {"create": 0, "update": 0, "delete": 0, "replace": 0}
    for row in rows:
        summary[row["action_class"]] = summary.get(row["action_class"], 0) + 1
    return summary


def build_drift_report(plan: dict[str, Any]) -> dict[str, Any]:
    """Build drift report grouped by product (PRODUCT_ORDER → Other)."""
    raw = plan.get("resource_changes")
    if raw is None:
        changes: list[Any] = []
    elif not isinstance(raw, list):
        raise UnknownActionsError(
            f"resource_changes must be a list, got {type(raw).__name__}"
        )
    else:
        changes = raw

    by_product: dict[str, list[dict[str, Any]]] = {}
    for item in changes:
        if not isinstance(item, dict):
            continue
        address = item.get("address")
        if not address or not isinstance(address, str):
            continue
        change = item.get("change") or {}
        if not isinstance(change, dict):
            change = {}
        actions = change.get("actions")
        if actions is not None and not isinstance(actions, list):
            raise UnknownActionsError(
                f"change.actions must be a list at {address}"
            )
        action_class = normalize_actions(actions if isinstance(actions, list) else None)
        if action_class is None:
            continue
        rtype = item.get("type") if isinstance(item.get("type"), str) else ""
        name = item.get("name") if isinstance(item.get("name"), str) else ""
        product = product_for_resource_type(rtype)
        by_product.setdefault(product, []).append(
            {
                "product": product,
                "address": address,
                "type": rtype,
                "name": name,
                "actions": list(actions) if isinstance(actions, list) else [],
                "action_class": action_class,
            }
        )

    for rows in by_product.values():
        rows.sort(key=lambda r: r["address"])

    ordered_ids = [pid for pid in PRODUCT_ORDER if pid in by_product]
    if "other" in by_product:
        ordered_ids.append("other")
    for pid in sorted(by_product.keys()):
        if pid not in ordered_ids:
            ordered_ids.append(pid)

    products: list[dict[str, Any]] = []
    flat: list[dict[str, Any]] = []
    for pid in ordered_ids:
        rows = by_product[pid]
        products.append(
            {
                "id": pid,
                "title": PRODUCT_TITLES.get(pid, pid),
                "summary": _action_summary(rows),
                "results": rows,
            }
        )
        flat.extend(rows)

    return {
        "version": 1,
        "summary": _action_summary(flat),
        "products": products,
        "results": flat,
    }


def exit_code_for_drift(report: dict[str, Any]) -> int:
    """0 if no delete/replace; 1 if any delete or replace."""
    summary = report.get("summary") or {}
    if summary.get("delete", 0) > 0 or summary.get("replace", 0) > 0:
        return 1
    return 0
