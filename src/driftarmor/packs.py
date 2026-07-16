"""Policy pack detection and product ordering for DriftArmor."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


# Stable report / detect order: AKS → SQL → Storage → VM → NSG
PRODUCT_ORDER: tuple[str, ...] = ("aks", "sql", "storage", "vm", "nsg")

PRODUCT_TITLES: dict[str, str] = {
    "aks": "AKS",
    "sql": "Azure SQL",
    "storage": "Storage",
    "vm": "Virtual Machines",
    "nsg": "Network Security Groups",
    "other": "Other",
}


@dataclass(frozen=True)
class Pack:
    id: str
    resource_types: frozenset[str]
    checkov_ids: tuple[str, ...]
    policies_subdir: str


_PACK_DEFS: dict[str, Pack] = {
    "aks": Pack(
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
    "sql": Pack(
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
    "storage": Pack(
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
    "vm": Pack(
        id="vm",
        resource_types=frozenset(
            {
                "azurerm_linux_virtual_machine",
                "azurerm_windows_virtual_machine",
            }
        ),
        checkov_ids=(
            "CKV_DRIFTARMOR_VM_1",
            "CKV_DRIFTARMOR_VM_2",
            "CKV_DRIFTARMOR_VM_3",
            "CKV_DRIFTARMOR_VM_4",
        ),
        policies_subdir="vm",
    ),
    "nsg": Pack(
        id="nsg",
        resource_types=frozenset(
            {
                "azurerm_network_security_group",
                "azurerm_network_security_rule",
            }
        ),
        checkov_ids=(
            "CKV_DRIFTARMOR_NSG_1",
            "CKV_DRIFTARMOR_NSG_2",
            "CKV_DRIFTARMOR_NSG_3",
        ),
        policies_subdir="nsg",
    ),
}

PACKS: tuple[Pack, ...] = tuple(_PACK_DEFS[pid] for pid in PRODUCT_ORDER)
PACK_BY_ID = dict(_PACK_DEFS)

_TYPE_TO_PRODUCT: dict[str, str] = {
    rtype: pack.id for pack in PACKS for rtype in pack.resource_types
}


def product_for_resource_type(resource_type: str) -> str:
    """Map Terraform type to product id, or ``other``."""
    return _TYPE_TO_PRODUCT.get(resource_type, "other")


def product_sort_key(product_id: str) -> tuple[int, str]:
    try:
        return (PRODUCT_ORDER.index(product_id), product_id)
    except ValueError:
        return (len(PRODUCT_ORDER), product_id)


def plan_resource_types(plan: dict[str, Any]) -> set[str]:
    types: set[str] = set()
    for change in plan.get("resource_changes") or []:
        t = change.get("type")
        if isinstance(t, str):
            types.add(t)
    return types


def detect_packs(plan: dict[str, Any]) -> list[Pack]:
    """Return packs that match resource types in the plan (product order)."""
    types = plan_resource_types(plan)
    return [p for p in PACKS if types & p.resource_types]
