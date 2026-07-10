"""Map Checkov results + plan context to the DriftArmor Report schema."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from driftarmor.aks import (
    any_cluster_has_default_node_pool,
    has_create_or_update,
    plan_has_dcr,
    plan_has_node_pool_resource,
)

Severity = Literal["pass", "fail", "warn", "manual"]

# Checkov ID -> product rule id
CHECKOV_TO_PRODUCT: dict[str, str] = {
    "CKV_DRIFTARMOR_AKS_1": "aks.cluster.present",
    "CKV_DRIFTARMOR_AKS_2": "aks.node_pool.present",
    "CKV_DRIFTARMOR_AKS_3": "aks.monitor.oms_or_dcr",
    "CKV_DRIFTARMOR_AKS_4": "aks.rbac.azure_rbac",
    "CKV_DRIFTARMOR_AKS_5": "aks.network.private_or_authorized",
}

# Product rules evaluated via Checkov (prometheus is CLI-derived).
AUTO_RULE_ORDER: tuple[str, ...] = (
    "aks.cluster.present",
    "aks.node_pool.present",
    "aks.monitor.oms_or_dcr",
    "aks.rbac.azure_rbac",
    "aks.network.private_or_authorized",
)

# When Checkov marks FAILED, map to this DriftArmor severity.
FAIL_SEVERITY: dict[str, Severity] = {
    "aks.cluster.present": "fail",
    "aks.node_pool.present": "fail",
    "aks.monitor.oms_or_dcr": "fail",
    "aks.rbac.azure_rbac": "fail",
    "aks.network.private_or_authorized": "warn",
}

DEFAULT_TITLES: dict[str, str] = {
    "aks.cluster.present": "AKS cluster resource present",
    "aks.node_pool.present": "Node pool present (default or dedicated)",
    "aks.monitor.oms_or_dcr": "Cluster metrics agent or DCR present",
    "aks.monitor.prometheus_manual": "Confirm Azure Monitor managed Prometheus",
    "aks.rbac.azure_rbac": "Azure RBAC / Kubernetes RBAC enabled",
    "aks.network.private_or_authorized": "Private cluster or authorized API IP ranges",
}

DEFAULT_FAIL_DETAIL: dict[str, str] = {
    "aks.cluster.present": "No azurerm_kubernetes_cluster create/update in plan",
    "aks.node_pool.present": "No default_node_pool and no azurerm_kubernetes_cluster_node_pool",
    "aks.monitor.oms_or_dcr": "No oms_agent block and no azurerm_monitor_data_collection_rule in plan",
    "aks.rbac.azure_rbac": "azure_rbac_enabled / role_based_access_control not enabled",
    "aks.network.private_or_authorized": "Neither private_cluster_enabled nor authorized_ip_ranges set",
}


def default_citations_path() -> Path:
    here = Path(__file__).resolve()
    candidates = [
        here.parents[2] / "policies" / "citations.json",
        here.parents[1] / "policies" / "citations.json",
        Path.cwd() / "policies" / "citations.json",
    ]
    for path in candidates:
        if path.is_file():
            return path
    return candidates[0]


def load_citations(path: Path | None = None) -> dict[str, dict[str, str]]:
    citations_path = path or default_citations_path()
    with citations_path.open(encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("citations.json must be an object keyed by rule id")
    return data


def _checkov_outcome_by_product(checkov_report: dict[str, Any]) -> dict[str, str]:
    """
    Collapse Checkov passed/failed lists to product_id -> PASSED|FAILED.

    If any resource fails a check, the product rule is FAILED.
    If at least one passes and none fail, PASSED.
    """
    results = checkov_report.get("results") or {}
    outcomes: dict[str, str] = {}

    def consider(check_id: str, result: str) -> None:
        product = CHECKOV_TO_PRODUCT.get(check_id)
        if not product:
            return
        current = outcomes.get(product)
        if current == "FAILED":
            return
        if result == "FAILED":
            outcomes[product] = "FAILED"
        elif result == "PASSED":
            outcomes[product] = "PASSED"

    for item in results.get("failed_checks") or []:
        consider(item.get("check_id", ""), "FAILED")
    for item in results.get("passed_checks") or []:
        consider(item.get("check_id", ""), "PASSED")

    return outcomes


def _apply_plan_ors(
    plan: dict[str, Any],
    outcomes: dict[str, str],
) -> dict[str, str]:
    """CLI-side OR logic that Checkov single-resource checks cannot express."""
    adjusted = dict(outcomes)

    # cluster.present: require create/update of azurerm_kubernetes_cluster
    if has_create_or_update(plan, "azurerm_kubernetes_cluster"):
        adjusted["aks.cluster.present"] = "PASSED"
    else:
        adjusted["aks.cluster.present"] = "FAILED"

    # node_pool: Checkov default_node_pool OR dedicated node pool resource
    node_ok = (
        adjusted.get("aks.node_pool.present") == "PASSED"
        or any_cluster_has_default_node_pool(plan)
        or plan_has_node_pool_resource(plan)
    )
    adjusted["aks.node_pool.present"] = "PASSED" if node_ok else "FAILED"

    # oms_or_dcr: Checkov oms_agent OR DCR resource in plan
    oms_ok = adjusted.get("aks.monitor.oms_or_dcr") == "PASSED" or plan_has_dcr(plan)
    adjusted["aks.monitor.oms_or_dcr"] = "PASSED" if oms_ok else "FAILED"

    return adjusted


def _result_row(
    rule_id: str,
    severity: Severity,
    *,
    citations: dict[str, dict[str, str]],
    detail: str,
    title: str | None = None,
) -> dict[str, Any]:
    meta = citations.get(rule_id) or {}
    return {
        "id": rule_id,
        "severity": severity,
        "title": title or meta.get("title") or DEFAULT_TITLES.get(rule_id, rule_id),
        "detail": detail,
        "citation_url": meta.get("citation_url", ""),
        "citation_verified": meta.get("citation_verified", ""),
    }


def map_checkov_to_report(
    checkov_report: dict[str, Any],
    plan: dict[str, Any],
    *,
    citations: dict[str, dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Build DriftArmor Report JSON from Checkov output and plan context."""
    cites = citations if citations is not None else load_citations()
    outcomes = _apply_plan_ors(plan, _checkov_outcome_by_product(checkov_report))

    results: list[dict[str, Any]] = []
    for rule_id in AUTO_RULE_ORDER:
        outcome = outcomes.get(rule_id, "FAILED")
        if outcome == "PASSED":
            severity: Severity = "pass"
            detail = "Check passed"
        else:
            severity = FAIL_SEVERITY[rule_id]
            detail = DEFAULT_FAIL_DETAIL[rule_id]
        results.append(_result_row(rule_id, severity, citations=cites, detail=detail))

    oms = next(r for r in results if r["id"] == "aks.monitor.oms_or_dcr")
    if oms["severity"] == "fail":
        results.append(
            _result_row(
                "aks.monitor.prometheus_manual",
                "manual",
                citations=cites,
                detail=(
                    "OMS/DCR missing — manually confirm Azure Monitor managed Prometheus "
                    "is planned outside this root or enable Container Insights / DCR"
                ),
            )
        )
    else:
        results.append(
            _result_row(
                "aks.monitor.prometheus_manual",
                "pass",
                citations=cites,
                detail="OMS/DCR present; Prometheus still worth confirming in Azure Monitor",
            )
        )

    summary = {"pass": 0, "fail": 0, "warn": 0, "manual": 0}
    for row in results:
        summary[row["severity"]] = summary.get(row["severity"], 0) + 1

    return {"version": 1, "summary": summary, "results": results}


def exit_code_for_report(report: dict[str, Any]) -> int:
    """0 if no fail severities; 1 if any fail."""
    if (report.get("summary") or {}).get("fail", 0) > 0:
        return 1
    return 0


def empty_report() -> dict[str, Any]:
    return {
        "version": 1,
        "summary": {"pass": 0, "fail": 0, "warn": 0, "manual": 0},
        "results": [],
    }
