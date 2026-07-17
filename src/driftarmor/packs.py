"""Policy pack detection and product ordering for DriftArmor."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


# Stable report / detect order
PRODUCT_ORDER: tuple[str, ...] = (
    "aks",
    "sql",
    "sqlmi",
    "storage",
    "keyvault",
    "acr",
    "servicebus",
    "vm",
    "nsg",
    "frontdoor",
)

PRODUCT_TITLES: dict[str, str] = {
    "aks": "AKS",
    "sql": "Azure SQL",
    "sqlmi": "SQL Managed Instance",
    "storage": "Storage",
    "keyvault": "Key Vault",
    "acr": "Azure Container Registry",
    "servicebus": "Service Bus",
    "vm": "Virtual Machines",
    "nsg": "Network Security Groups",
    "frontdoor": "Front Door",
    "other": "Other",
}


@dataclass(frozen=True)
class Pack:
    id: str
    resource_types: frozenset[str]
    checkov_ids: tuple[str, ...]
    policies_subdir: str
    check_resource_types: frozenset[str] | None = None

    @property
    def detection_resource_types(self) -> frozenset[str]:
        """Types that activate checks, independent of drift classification."""
        if self.check_resource_types is not None:
            return self.check_resource_types
        return self.resource_types


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
    "sqlmi": Pack(
        id="sqlmi",
        resource_types=frozenset({"azurerm_mssql_managed_instance"}),
        checkov_ids=(
            "CKV_DRIFTARMOR_SQLMI_1",
            "CKV_DRIFTARMOR_SQLMI_2",
            "CKV_DRIFTARMOR_SQLMI_3",
            "CKV_DRIFTARMOR_SQLMI_4",
        ),
        policies_subdir="sqlmi",
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
    "keyvault": Pack(
        id="keyvault",
        resource_types=frozenset({"azurerm_key_vault"}),
        checkov_ids=(
            "CKV_DRIFTARMOR_KV_1",
            "CKV_DRIFTARMOR_KV_2",
            "CKV_DRIFTARMOR_KV_3",
        ),
        policies_subdir="keyvault",
    ),
    "acr": Pack(
        id="acr",
        resource_types=frozenset({"azurerm_container_registry"}),
        checkov_ids=(
            "CKV_DRIFTARMOR_ACR_1",
            "CKV_DRIFTARMOR_ACR_2",
            "CKV_DRIFTARMOR_ACR_3",
        ),
        policies_subdir="acr",
    ),
    "servicebus": Pack(
        id="servicebus",
        resource_types=frozenset(
            {
                "azurerm_servicebus_namespace",
                "azurerm_servicebus_namespace_network_rule_set",
                "azurerm_servicebus_queue",
                "azurerm_servicebus_topic",
                "azurerm_servicebus_subscription",
            }
        ),
        checkov_ids=(
            "CKV_DRIFTARMOR_SB_1",
            "CKV_DRIFTARMOR_SB_2",
            "CKV_DRIFTARMOR_SB_3",
        ),
        policies_subdir="servicebus",
        check_resource_types=frozenset({"azurerm_servicebus_namespace"}),
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
    "frontdoor": Pack(
        id="frontdoor",
        resource_types=frozenset(
            {
                "azurerm_cdn_frontdoor_profile",
                "azurerm_cdn_frontdoor_firewall_policy",
                "azurerm_cdn_frontdoor_security_policy",
            }
        ),
        checkov_ids=(
            "CKV_DRIFTARMOR_FD_1",
            "CKV_DRIFTARMOR_FD_2",
            "CKV_DRIFTARMOR_FD_3",
        ),
        policies_subdir="frontdoor",
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
    """Return managed resource types that remain after the plan.

    Data-source reads, deletes, and state-only forget actions have no post-plan
    managed resource for Checkov to evaluate, so they must not activate a pack.
    """
    types: set[str] = set()
    for change in plan.get("resource_changes") or []:
        if not isinstance(change, dict):
            continue
        if change.get("mode") == "data":
            continue
        change_body = change.get("change") or {}
        actions = change_body.get("actions") if isinstance(change_body, dict) else None
        if actions in (["read"], ["delete"], ["forget"]):
            continue
        t = change.get("type")
        if isinstance(t, str):
            types.add(t)
    return types


def detect_packs(plan: dict[str, Any]) -> list[Pack]:
    """Return packs that match resource types in the plan (product order)."""
    types = plan_resource_types(plan)
    return [p for p in PACKS if types & p.detection_resource_types]
