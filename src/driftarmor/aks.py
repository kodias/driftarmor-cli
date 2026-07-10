"""AKS plan helpers: detection and attribute lookups."""

from __future__ import annotations

from typing import Any

AKS_TYPES = frozenset(
    {
        "azurerm_kubernetes_cluster",
        "azurerm_kubernetes_cluster_node_pool",
    }
)


def has_aks_resources(plan: dict[str, Any]) -> bool:
    """True if plan resource_changes include AKS cluster or node pool types."""
    for change in plan.get("resource_changes") or []:
        if change.get("type") in AKS_TYPES:
            return True
    return False


def resource_changes_of_type(plan: dict[str, Any], resource_type: str) -> list[dict[str, Any]]:
    return [
        c
        for c in (plan.get("resource_changes") or [])
        if c.get("type") == resource_type
    ]


def actions_include_create_or_update(change: dict[str, Any]) -> bool:
    actions = (change.get("change") or {}).get("actions") or []
    return any(a in ("create", "update") for a in actions)


def has_create_or_update(plan: dict[str, Any], resource_type: str) -> bool:
    return any(
        actions_include_create_or_update(c)
        for c in resource_changes_of_type(plan, resource_type)
    )


def cluster_after_blocks(plan: dict[str, Any]) -> list[dict[str, Any]]:
    """Return change.after dicts for AKS clusters (skip null after)."""
    blocks: list[dict[str, Any]] = []
    for change in resource_changes_of_type(plan, "azurerm_kubernetes_cluster"):
        after = (change.get("change") or {}).get("after")
        if isinstance(after, dict):
            blocks.append(after)
    return blocks


def plan_has_dcr(plan: dict[str, Any]) -> bool:
    return has_create_or_update(plan, "azurerm_monitor_data_collection_rule")


def plan_has_node_pool_resource(plan: dict[str, Any]) -> bool:
    return has_create_or_update(plan, "azurerm_kubernetes_cluster_node_pool")


def cluster_has_default_node_pool(after: dict[str, Any]) -> bool:
    pool = after.get("default_node_pool")
    if pool is None:
        return False
    if isinstance(pool, list):
        return any(isinstance(p, dict) and bool(p) for p in pool)
    if isinstance(pool, dict):
        return bool(pool)
    return False


def any_cluster_has_default_node_pool(plan: dict[str, Any]) -> bool:
    return any(cluster_has_default_node_pool(a) for a in cluster_after_blocks(plan))
