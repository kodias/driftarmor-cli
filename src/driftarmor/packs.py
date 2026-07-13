"""Policy pack detection for DriftArmor check."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Pack:
    id: str
    resource_types: frozenset[str]
    checkov_ids: tuple[str, ...]
    policies_subdir: str


PACKS: tuple[Pack, ...] = (
    Pack(
        id="aks",
        resource_types=frozenset(
            {
                "azurerm_kubernetes_cluster",
                "azurerm_kubernetes_cluster_node_pool",
            }
        ),
        checkov_ids=(
            "CKV_DRIFTARMOR_AKS_1",
            "CKV_DRIFTARMOR_AKS_2",
            "CKV_DRIFTARMOR_AKS_3",
            "CKV_DRIFTARMOR_AKS_4",
            "CKV_DRIFTARMOR_AKS_5",
        ),
        policies_subdir="aks",
    ),
    Pack(
        id="storage",
        resource_types=frozenset({"azurerm_storage_account"}),
        checkov_ids=(
            "CKV_DRIFTARMOR_STORAGE_1",
            "CKV_DRIFTARMOR_STORAGE_2",
            "CKV_DRIFTARMOR_STORAGE_3",
            "CKV_DRIFTARMOR_STORAGE_4",
        ),
        policies_subdir="storage",
    ),
    Pack(
        id="sql",
        resource_types=frozenset(
            {
                "azurerm_mssql_server",
                "azurerm_mssql_database",
                "azurerm_mssql_firewall_rule",
            }
        ),
        checkov_ids=(
            "CKV_DRIFTARMOR_SQL_1",
            "CKV_DRIFTARMOR_SQL_2",
            "CKV_DRIFTARMOR_SQL_3",
            "CKV_DRIFTARMOR_SQL_4",
            "CKV_DRIFTARMOR_SQL_5",
        ),
        policies_subdir="sql",
    ),
)

PACK_BY_ID = {p.id: p for p in PACKS}


def plan_resource_types(plan: dict[str, Any]) -> set[str]:
    types: set[str] = set()
    for change in plan.get("resource_changes") or []:
        t = change.get("type")
        if isinstance(t, str):
            types.add(t)
    return types


def detect_packs(plan: dict[str, Any]) -> list[Pack]:
    """Return packs that match resource types in the plan (stable order)."""
    types = plan_resource_types(plan)
    return [p for p in PACKS if types & p.resource_types]
