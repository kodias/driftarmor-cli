"""Unit tests for Key Vault Checkov-result mapping."""

from __future__ import annotations

import json
from pathlib import Path

from driftarmor.packs import PACK_BY_ID
from driftarmor.report import load_citations, map_checkov_to_report


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "keyvault-plan"
CHECK_IDS = (
    "CKV_DRIFTARMOR_KV_1",
    "CKV_DRIFTARMOR_KV_2",
    "CKV_DRIFTARMOR_KV_3",
)


def _plan(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _checkov_report(*, outcome: str) -> dict:
    key = "passed_checks" if outcome == "PASSED" else "failed_checks"
    other = "failed_checks" if outcome == "PASSED" else "passed_checks"
    return {
        "results": {
            key: [{"check_id": check_id} for check_id in CHECK_IDS],
            other: [],
        }
    }


def test_keyvault_failed_results_map_to_fail_fail_warn_with_citations():
    report = map_checkov_to_report(
        _checkov_report(outcome="FAILED"),
        _plan("fail.json"),
        packs=[PACK_BY_ID["keyvault"]],
        citations=load_citations(ROOT / "policies" / "citations.json"),
    )

    by_id = {row["id"]: row for row in report["results"]}
    assert by_id["keyvault.rbac_authorization"]["severity"] == "fail"
    assert by_id["keyvault.purge_protection"]["severity"] == "fail"
    assert by_id["keyvault.network_restricted"]["severity"] == "warn"
    assert all(row["citation_url"] for row in report["results"])
    assert all(row["citation_verified"] == "2026-07-17" for row in report["results"])


def test_keyvault_passed_results_exit_without_failures():
    report = map_checkov_to_report(
        _checkov_report(outcome="PASSED"),
        _plan("pass.json"),
        packs=[PACK_BY_ID["keyvault"]],
        citations=load_citations(ROOT / "policies" / "citations.json"),
    )

    assert report["summary"] == {"pass": 3, "fail": 0, "warn": 0, "manual": 0}
    assert [product["id"] for product in report["products"]] == ["keyvault"]
