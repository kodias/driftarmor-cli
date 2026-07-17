"""Unit tests for Service Bus cross-resource report mapping."""

from __future__ import annotations

import json
from pathlib import Path

from driftarmor.packs import PACK_BY_ID
from driftarmor.report import load_citations, map_checkov_to_report


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "servicebus-plan"


def _failed_checkov_report() -> dict:
    return {
        "results": {
            "failed_checks": [
                {"check_id": "CKV_DRIFTARMOR_SB_1"},
                {"check_id": "CKV_DRIFTARMOR_SB_2"},
                {"check_id": "CKV_DRIFTARMOR_SB_3"},
            ],
            "passed_checks": [],
        }
    }


def test_legacy_standalone_deny_does_not_override_namespace_warning():
    plan = json.loads((FIXTURES / "fail.json").read_text(encoding="utf-8"))
    plan["resource_changes"].append(
        {
            "address": "azurerm_servicebus_namespace_network_rule_set.main",
            "mode": "managed",
            "type": "azurerm_servicebus_namespace_network_rule_set",
            "name": "main",
            "change": {
                "actions": ["create"],
                "after": {"default_action": "Deny"},
            },
        }
    )

    report = map_checkov_to_report(
        _failed_checkov_report(),
        plan,
        packs=[PACK_BY_ID["servicebus"]],
        citations=load_citations(ROOT / "policies" / "citations.json"),
    )

    by_id = {row["id"]: row for row in report["results"]}
    assert by_id["servicebus.network_restricted"]["severity"] == "warn"


def test_deny_rule_set_does_not_mask_another_open_namespace():
    plan = json.loads((FIXTURES / "fail.json").read_text(encoding="utf-8"))
    plan["resource_changes"].extend(
        [
            {
                "address": "azurerm_servicebus_namespace.protected",
                "mode": "managed",
                "type": "azurerm_servicebus_namespace",
                "name": "protected",
                "change": {
                    "actions": ["create"],
                    "after": {"public_network_access_enabled": True},
                },
            },
            {
                "address": "azurerm_servicebus_namespace_network_rule_set.protected",
                "mode": "managed",
                "type": "azurerm_servicebus_namespace_network_rule_set",
                "name": "protected",
                "change": {
                    "actions": ["create"],
                    "after": {"default_action": "Deny"},
                },
            },
        ]
    )

    report = map_checkov_to_report(
        _failed_checkov_report(),
        plan,
        packs=[PACK_BY_ID["servicebus"]],
        citations=load_citations(ROOT / "policies" / "citations.json"),
    )

    by_id = {row["id"]: row for row in report["results"]}
    assert by_id["servicebus.network_restricted"]["severity"] == "warn"
