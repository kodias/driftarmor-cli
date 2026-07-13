"""Pack detection unit tests."""

from __future__ import annotations

from driftarmor.packs import detect_packs


def test_detect_storage_and_sql():
    plan = {
        "resource_changes": [
            {"type": "azurerm_storage_account", "change": {"actions": ["create"]}},
            {"type": "azurerm_mssql_server", "change": {"actions": ["create"]}},
        ]
    }
    packs = detect_packs(plan)
    assert [p.id for p in packs] == ["sql", "storage"]


def test_detect_all_products_order():
    plan = {
        "resource_changes": [
            {"type": "azurerm_storage_account", "change": {"actions": ["create"]}},
            {
                "type": "azurerm_kubernetes_cluster",
                "change": {"actions": ["create"]},
            },
            {"type": "azurerm_mssql_server", "change": {"actions": ["create"]}},
        ]
    }
    assert [p.id for p in detect_packs(plan)] == ["aks", "sql", "storage"]


def test_detect_aks_only():
    plan = {
        "resource_changes": [
            {
                "type": "azurerm_kubernetes_cluster",
                "change": {"actions": ["create"]},
            }
        ]
    }
    packs = detect_packs(plan)
    assert [p.id for p in packs] == ["aks"]


def test_detect_none():
    plan = {
        "resource_changes": [
            {"type": "azurerm_resource_group", "change": {"actions": ["create"]}}
        ]
    }
    assert detect_packs(plan) == []
