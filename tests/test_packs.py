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
            {"type": "azurerm_key_vault", "change": {"actions": ["create"]}},
            {"type": "azurerm_container_registry", "change": {"actions": ["create"]}},
            {"type": "azurerm_servicebus_namespace", "change": {"actions": ["create"]}},
            {
                "type": "azurerm_kubernetes_cluster",
                "change": {"actions": ["create"]},
            },
            {"type": "azurerm_mssql_server", "change": {"actions": ["create"]}},
            {
                "type": "azurerm_mssql_managed_instance",
                "change": {"actions": ["create"]},
            },
            {
                "type": "azurerm_linux_virtual_machine",
                "change": {"actions": ["create"]},
            },
            {
                "type": "azurerm_network_security_group",
                "change": {"actions": ["create"]},
            },
            {
                "type": "azurerm_cdn_frontdoor_profile",
                "change": {"actions": ["create"]},
            },
        ]
    }
    assert [p.id for p in detect_packs(plan)] == [
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
    ]


def test_detect_vm_and_nsg():
    plan = {
        "resource_changes": [
            {
                "type": "azurerm_windows_virtual_machine",
                "change": {"actions": ["create"]},
            },
            {
                "type": "azurerm_network_security_rule",
                "change": {"actions": ["create"]},
            },
        ]
    }
    assert [p.id for p in detect_packs(plan)] == ["vm", "nsg"]


def test_detect_sqlmi_and_frontdoor():
    plan = {
        "resource_changes": [
            {
                "type": "azurerm_mssql_managed_instance",
                "change": {"actions": ["create"]},
            },
            {
                "type": "azurerm_cdn_frontdoor_firewall_policy",
                "change": {"actions": ["create"]},
            },
        ]
    }
    assert [p.id for p in detect_packs(plan)] == ["sqlmi", "frontdoor"]


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


def test_detect_ignores_data_sources_and_resources_absent_after_plan():
    plan = {
        "resource_changes": [
            {
                "mode": "data",
                "type": "azurerm_key_vault",
                "change": {"actions": ["read"]},
            },
            {
                "mode": "managed",
                "type": "azurerm_storage_account",
                "change": {"actions": ["delete"], "after": None},
            },
            {
                "mode": "managed",
                "type": "azurerm_container_registry",
                "change": {"actions": ["forget"], "after": None},
            },
        ]
    }

    assert detect_packs(plan) == []


def test_servicebus_entity_without_namespace_does_not_activate_empty_pack():
    plan = {
        "resource_changes": [
            {
                "mode": "managed",
                "type": "azurerm_servicebus_queue",
                "change": {"actions": ["create"]},
            }
        ]
    }

    assert detect_packs(plan) == []
