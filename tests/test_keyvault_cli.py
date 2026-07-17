"""Key Vault pack CLI tests against Terraform plan fixtures."""

from __future__ import annotations

import json
from pathlib import Path

from driftarmor.cli import main
from driftarmor.packs import detect_packs


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "keyvault-plan"
KEYVAULT_RULE_IDS = {
    "keyvault.rbac_authorization",
    "keyvault.purge_protection",
    "keyvault.network_restricted",
}


def test_keyvault_pass_exit_0_and_all_rules_present(capsys):
    code = main(["check", "--plan", str(FIXTURES / "pass.json"), "--json"])

    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["summary"] == {"pass": 3, "fail": 0, "warn": 0, "manual": 0}
    assert {result["id"] for result in report["results"]} == KEYVAULT_RULE_IDS


def test_keyvault_fail_exit_1_with_expected_severities(capsys):
    code = main(["check", "--plan", str(FIXTURES / "fail.json"), "--json"])

    assert code == 1
    report = json.loads(capsys.readouterr().out)
    by_id = {result["id"]: result for result in report["results"]}
    assert set(by_id) == KEYVAULT_RULE_IDS
    assert by_id["keyvault.rbac_authorization"]["severity"] == "fail"
    assert by_id["keyvault.purge_protection"]["severity"] == "fail"
    assert by_id["keyvault.network_restricted"]["severity"] == "warn"


def test_keyvault_fixture_detects_only_keyvault_pack():
    plan = json.loads((FIXTURES / "pass.json").read_text(encoding="utf-8"))

    assert [pack.id for pack in detect_packs(plan)] == ["keyvault"]
