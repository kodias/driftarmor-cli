"""Azure Container Registry pack CLI tests against Terraform plan fixtures."""

from __future__ import annotations

import json
from pathlib import Path

from driftarmor.cli import main
from driftarmor.packs import detect_packs


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "acr-plan"
ACR_RULE_IDS = {
    "acr.admin_disabled",
    "acr.anonymous_pull_disabled",
    "acr.network_restricted",
}


def test_acr_pass_exit_0_and_all_rules_present(capsys):
    code = main(["check", "--plan", str(FIXTURES / "pass.json"), "--json"])

    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["summary"] == {"pass": 3, "fail": 0, "warn": 0, "manual": 0}
    assert {result["id"] for result in report["results"]} == ACR_RULE_IDS


def test_acr_fail_exit_1_with_expected_severities(capsys):
    code = main(["check", "--plan", str(FIXTURES / "fail.json"), "--json"])

    assert code == 1
    report = json.loads(capsys.readouterr().out)
    assert report["summary"] == {"pass": 0, "fail": 2, "warn": 1, "manual": 0}
    by_id = {result["id"]: result for result in report["results"]}
    assert set(by_id) == ACR_RULE_IDS
    assert by_id["acr.admin_disabled"]["severity"] == "fail"
    assert by_id["acr.anonymous_pull_disabled"]["severity"] == "fail"
    assert by_id["acr.network_restricted"]["severity"] == "warn"


def test_acr_fixture_detects_only_acr_pack():
    plan = json.loads((FIXTURES / "pass.json").read_text(encoding="utf-8"))

    assert [pack.id for pack in detect_packs(plan)] == ["acr"]
