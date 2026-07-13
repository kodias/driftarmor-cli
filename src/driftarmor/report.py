"""Map Checkov results + plan context to the DriftArmor Report schema."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal, Sequence

from driftarmor.aks import (
    any_cluster_has_default_node_pool,
    has_create_or_update,
    plan_has_dcr,
    plan_has_node_pool_resource,
)
from driftarmor.packs import Pack, plan_resource_types

Severity = Literal["pass", "fail", "warn", "manual"]

# Checkov ID -> product rule id
CHECKOV_TO_PRODUCT: dict[str, str] = {
    "CKV_DRIFTARMOR_AKS_1": "aks.cluster.present",
    "CKV_DRIFTARMOR_AKS_2": "aks.node_pool.present",
    "CKV_DRIFTARMOR_AKS_3": "aks.monitor.oms_or_dcr",
    "CKV_DRIFTARMOR_AKS_4": "aks.rbac.azure_rbac",
    "CKV_DRIFTARMOR_AKS_5": "aks.network.private_or_authorized",
    "CKV_DRIFTARMOR_STORAGE_1": "storage.https_only",
    "CKV_DRIFTARMOR_STORAGE_2": "storage.min_tls",
    "CKV_DRIFTARMOR_STORAGE_3": "storage.blob_public_access",
    "CKV_DRIFTARMOR_STORAGE_4": "storage.network_restricted",
    "CKV_DRIFTARMOR_SQL_1": "sql.public_network",
    "CKV_DRIFTARMOR_SQL_2": "sql.entra_admin",
    "CKV_DRIFTARMOR_SQL_3": "sql.min_tls",
    "CKV_DRIFTARMOR_SQL_4": "sql.firewall_any_ip",
    "CKV_DRIFTARMOR_SQL_5": "sql.tde",
}

# Product rules evaluated via Checkov, ordered per pack.
PACK_AUTO_RULES: dict[str, tuple[str, ...]] = {
    "aks": (
        "aks.cluster.present",
        "aks.node_pool.present",
        "aks.monitor.oms_or_dcr",
        "aks.rbac.azure_rbac",
        "aks.network.private_or_authorized",
    ),
    "storage": (
        "storage.https_only",
        "storage.min_tls",
        "storage.blob_public_access",
        "storage.network_restricted",
    ),
    "sql": (
        "sql.public_network",
        "sql.entra_admin",
        "sql.min_tls",
        "sql.firewall_any_ip",
        "sql.tde",
    ),
}

# Only emit the rule when the plan contains at least one of these types.
# Omitted key = always emit when the pack is active.
RULE_REQUIRES_TYPES: dict[str, frozenset[str]] = {
    "sql.public_network": frozenset({"azurerm_mssql_server"}),
    "sql.entra_admin": frozenset({"azurerm_mssql_server"}),
    "sql.min_tls": frozenset({"azurerm_mssql_server"}),
    "sql.firewall_any_ip": frozenset({"azurerm_mssql_firewall_rule"}),
    "sql.tde": frozenset({"azurerm_mssql_database"}),
}

# When Checkov marks FAILED, map to this DriftArmor severity.
FAIL_SEVERITY: dict[str, Severity] = {
    "aks.cluster.present": "fail",
    "aks.node_pool.present": "fail",
    "aks.monitor.oms_or_dcr": "fail",
    "aks.rbac.azure_rbac": "fail",
    "aks.network.private_or_authorized": "warn",
    "storage.https_only": "fail",
    "storage.min_tls": "fail",
    "storage.blob_public_access": "fail",
    "storage.network_restricted": "warn",
    "sql.public_network": "fail",
    "sql.entra_admin": "fail",
    "sql.min_tls": "fail",
    "sql.firewall_any_ip": "fail",
    "sql.tde": "fail",
}

DEFAULT_TITLES: dict[str, str] = {
    "aks.cluster.present": "AKS cluster resource present",
    "aks.node_pool.present": "Node pool present (default or dedicated)",
    "aks.monitor.oms_or_dcr": "Cluster metrics agent or DCR present",
    "aks.monitor.prometheus_manual": "Confirm Azure Monitor managed Prometheus",
    "aks.rbac.azure_rbac": "Azure RBAC / Kubernetes RBAC enabled",
    "aks.network.private_or_authorized": "Private cluster or authorized API IP ranges",
    "storage.https_only": "Storage account requires HTTPS (secure transfer)",
    "storage.min_tls": "Storage account minimum TLS 1.2+",
    "storage.blob_public_access": "Storage account disallows public blob access",
    "storage.network_restricted": "Storage public network disabled or network rules Deny",
    "sql.public_network": "Azure SQL server public network access disabled",
    "sql.entra_admin": "Azure SQL server has Microsoft Entra administrator",
    "sql.min_tls": "Azure SQL server minimum TLS 1.2+",
    "sql.firewall_any_ip": "Azure SQL firewall must not allow 0.0.0.0-255.255.255.255",
    "sql.tde": "Azure SQL database transparent data encryption enabled",
}

DEFAULT_FAIL_DETAIL: dict[str, str] = {
    "aks.cluster.present": "No azurerm_kubernetes_cluster create/update in plan",
    "aks.node_pool.present": "No default_node_pool and no azurerm_kubernetes_cluster_node_pool",
    "aks.monitor.oms_or_dcr": "No oms_agent block and no azurerm_monitor_data_collection_rule in plan",
    "aks.rbac.azure_rbac": "azure_rbac_enabled / role_based_access_control not enabled",
    "aks.network.private_or_authorized": "Neither private_cluster_enabled nor authorized_ip_ranges set",
    "storage.https_only": "https_traffic_only_enabled is false",
    "storage.min_tls": "min_tls_version is below TLS 1.2 or unset",
    "storage.blob_public_access": "allow_nested_items_to_be_public / allow_blob_public_access not disabled",
    "storage.network_restricted": "public_network_access_enabled and network_rules default_action not Deny",
    "sql.public_network": "public_network_access_enabled is not false",
    "sql.entra_admin": "azuread_administrator block missing on azurerm_mssql_server",
    "sql.min_tls": "minimum_tls_version is below 1.2 or unset",
    "sql.firewall_any_ip": "firewall rule allows 0.0.0.0-255.255.255.255",
    "sql.tde": "transparent_data_encryption_enabled is false",
}

# Backward-compatible alias used by older tests / imports.
AUTO_RULE_ORDER: tuple[str, ...] = PACK_AUTO_RULES["aks"]


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
    *,
    pack_ids: set[str],
) -> dict[str, str]:
    """CLI-side OR logic that Checkov single-resource checks cannot express."""
    adjusted = dict(outcomes)

    if "aks" in pack_ids:
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


def _rules_for_packs(packs: Sequence[Pack], plan: dict[str, Any]) -> list[str]:
    types = plan_resource_types(plan)
    rules: list[str] = []
    for pack in packs:
        for rule_id in PACK_AUTO_RULES.get(pack.id, ()):
            required = RULE_REQUIRES_TYPES.get(rule_id)
            if required is not None and not (types & required):
                continue
            rules.append(rule_id)
    return rules


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
    packs: Sequence[Pack] | None = None,
    citations: dict[str, dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Build DriftArmor Report JSON from Checkov output and plan context."""
    from driftarmor.packs import PACK_BY_ID

    cites = citations if citations is not None else load_citations()
    active = list(packs) if packs is not None else [PACK_BY_ID["aks"]]
    pack_ids = {p.id for p in active}
    outcomes = _apply_plan_ors(
        plan,
        _checkov_outcome_by_product(checkov_report),
        pack_ids=pack_ids,
    )

    results: list[dict[str, Any]] = []
    for rule_id in _rules_for_packs(active, plan):
        outcome = outcomes.get(rule_id, "FAILED")
        if outcome == "PASSED":
            severity: Severity = "pass"
            detail = "Check passed"
        else:
            severity = FAIL_SEVERITY[rule_id]
            detail = DEFAULT_FAIL_DETAIL[rule_id]
        results.append(_result_row(rule_id, severity, citations=cites, detail=detail))

    if "aks" in pack_ids:
        oms = next(
            (r for r in results if r["id"] == "aks.monitor.oms_or_dcr"),
            None,
        )
        if oms is not None:
            if oms["severity"] == "fail":
                results.append(
                    _result_row(
                        "aks.monitor.prometheus_manual",
                        "manual",
                        citations=cites,
                        detail=(
                            "OMS/DCR missing — manually confirm Azure Monitor managed "
                            "Prometheus is planned outside this root or enable "
                            "Container Insights / DCR"
                        ),
                    )
                )
            else:
                results.append(
                    _result_row(
                        "aks.monitor.prometheus_manual",
                        "pass",
                        citations=cites,
                        detail=(
                            "OMS/DCR present; Prometheus still worth confirming "
                            "in Azure Monitor"
                        ),
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
