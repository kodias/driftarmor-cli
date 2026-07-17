"""Unit tests for drift normalizer and report builder."""

from __future__ import annotations

import pytest

from driftarmor.drift import (
    UnknownActionsError,
    build_drift_report,
    exit_code_for_drift,
    normalize_actions,
)


def test_normalize_singles():
    assert normalize_actions(["create"]) == "create"
    assert normalize_actions(["update"]) == "update"
    assert normalize_actions(["delete"]) == "delete"


def test_normalize_replace_both_orders():
    assert normalize_actions(["delete", "create"]) == "replace"
    assert normalize_actions(["create", "delete"]) == "replace"


def test_normalize_silent_skip():
    assert normalize_actions(["read"]) is None
    assert normalize_actions(["no-op"]) is None
    assert normalize_actions([]) is None
    assert normalize_actions(None) is None


def test_normalize_unknown_raises():
    with pytest.raises(UnknownActionsError):
        normalize_actions(["create", "update"])
    with pytest.raises(UnknownActionsError):
        normalize_actions(["explode"])


def test_build_report_sorts_and_omits_secrets():
    plan = {
        "resource_changes": [
            {
                "address": "b.res",
                "type": "t",
                "name": "res",
                "change": {
                    "actions": ["update"],
                    "before": {"password": "secret"},
                    "after": {"password": "secret2"},
                },
            },
            {
                "address": "a.res",
                "type": "t",
                "name": "res",
                "change": {"actions": ["create"]},
            },
        ]
    }
    report = build_drift_report(plan)
    assert [r["address"] for r in report["results"]] == ["a.res", "b.res"]
    assert [p["id"] for p in report["products"]] == ["other"]
    blob = str(report)
    assert "password" not in blob
    assert "secret" not in blob
    assert report["summary"]["create"] == 1
    assert report["summary"]["update"] == 1
    assert exit_code_for_drift(report) == 0


def test_build_report_groups_by_product_order():
    plan = {
        "resource_changes": [
            {
                "address": "azurerm_storage_account.sa",
                "type": "azurerm_storage_account",
                "name": "sa",
                "change": {"actions": ["create"]},
            },
            {
                "address": "azurerm_mssql_server.sql",
                "type": "azurerm_mssql_server",
                "name": "sql",
                "change": {"actions": ["update"]},
            },
            {
                "address": "azurerm_kubernetes_cluster.aks",
                "type": "azurerm_kubernetes_cluster",
                "name": "aks",
                "change": {"actions": ["create"]},
            },
            {
                "address": "azurerm_resource_group.rg",
                "type": "azurerm_resource_group",
                "name": "rg",
                "change": {"actions": ["create"]},
            },
        ]
    }
    report = build_drift_report(plan)
    assert [p["id"] for p in report["products"]] == [
        "aks",
        "sql",
        "storage",
        "other",
    ]
    assert [r["product"] for r in report["results"]] == [
        "aks",
        "sql",
        "storage",
        "other",
    ]


def test_servicebus_entity_changes_remain_grouped_for_drift():
    plan = {
        "resource_changes": [
            {
                "address": "azurerm_servicebus_queue.orders",
                "type": "azurerm_servicebus_queue",
                "name": "orders",
                "change": {"actions": ["delete"]},
            }
        ]
    }

    report = build_drift_report(plan)

    assert [product["id"] for product in report["products"]] == ["servicebus"]
    assert report["results"][0]["product"] == "servicebus"
    assert exit_code_for_drift(report) == 1


def test_exit_code_replace():
    report = {
        "summary": {"create": 0, "update": 0, "delete": 0, "replace": 1},
        "results": [],
    }
    assert exit_code_for_drift(report) == 1


def test_malformed_resource_changes_type():
    with pytest.raises(UnknownActionsError):
        build_drift_report({"resource_changes": "nope"})
