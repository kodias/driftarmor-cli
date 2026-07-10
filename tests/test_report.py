"""Unit tests for Checkov → Report mapper (no live checkov required)."""

from __future__ import annotations

import json
from pathlib import Path

from driftarmor.report import exit_code_for_report, load_citations, map_checkov_to_report

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "aks-plan"
CKV_FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_map_fail_snippet_includes_oms_fail_and_manual_prometheus():
    checkov = _load(CKV_FIXTURES / "checkov_fail_snippet.json")
    plan = _load(FIXTURES / "fail.json")
    citations = load_citations(ROOT / "policies" / "citations.json")

    report = map_checkov_to_report(checkov, plan, citations=citations)

    by_id = {r["id"]: r for r in report["results"]}
    assert by_id["aks.monitor.oms_or_dcr"]["severity"] == "fail"
    assert by_id["aks.monitor.prometheus_manual"]["severity"] == "manual"
    assert by_id["aks.network.private_or_authorized"]["severity"] == "warn"
    assert by_id["aks.rbac.azure_rbac"]["severity"] == "fail"
    assert report["summary"]["fail"] >= 1
    assert exit_code_for_report(report) == 1
    for row in report["results"]:
        assert row["citation_url"]
        assert row["citation_verified"]


def test_map_pass_snippet_exit_zero():
    checkov = _load(CKV_FIXTURES / "checkov_pass_snippet.json")
    plan = _load(FIXTURES / "pass.json")
    citations = load_citations(ROOT / "policies" / "citations.json")

    report = map_checkov_to_report(checkov, plan, citations=citations)

    assert report["summary"]["fail"] == 0
    assert exit_code_for_report(report) == 0
    by_id = {r["id"]: r for r in report["results"]}
    assert by_id["aks.monitor.oms_or_dcr"]["severity"] == "pass"
    assert by_id["aks.monitor.prometheus_manual"]["severity"] == "pass"


def test_dcr_in_plan_rescues_oms_fail():
    checkov = _load(CKV_FIXTURES / "checkov_fail_snippet.json")
    plan = _load(FIXTURES / "fail.json")
    plan["resource_changes"].append(
        {
            "address": "azurerm_monitor_data_collection_rule.aks",
            "mode": "managed",
            "type": "azurerm_monitor_data_collection_rule",
            "name": "aks",
            "change": {
                "actions": ["create"],
                "after": {"name": "dcr-aks"},
            },
        }
    )
    citations = load_citations(ROOT / "policies" / "citations.json")
    report = map_checkov_to_report(checkov, plan, citations=citations)
    by_id = {r["id"]: r for r in report["results"]}
    assert by_id["aks.monitor.oms_or_dcr"]["severity"] == "pass"
    assert by_id["aks.monitor.prometheus_manual"]["severity"] == "pass"
