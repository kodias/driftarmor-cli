"""CLI exit-code tests against plan fixtures."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from driftarmor.cli import main

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "aks-plan"


def test_fail_fixture_exit_1_and_oms_fail(capsys):
    code = main(["check", "--plan", str(FIXTURES / "fail.json"), "--json"])
    assert code == 1
    report = json.loads(capsys.readouterr().out)
    by_id = {r["id"]: r for r in report["results"]}
    assert by_id["aks.monitor.oms_or_dcr"]["severity"] == "fail"


def test_pass_fixture_exit_0(capsys):
    code = main(["check", "--plan", str(FIXTURES / "pass.json"), "--json"])
    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["fail"] == 0


def test_invalid_json_exit_2(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{not-json", encoding="utf-8")
    code = main(["check", "--plan", str(bad)])
    assert code == 2
    err = capsys.readouterr().err
    assert "invalid plan JSON" in err


def test_missing_file_exit_2(capsys):
    code = main(["check", "--plan", "/nonexistent/plan.json"])
    assert code == 2
    assert "not found" in capsys.readouterr().err


def test_non_aks_plan_exit_0(capsys):
    code = main(["check", "--plan", str(FIXTURES / "no_aks.json")])
    assert code == 0
    out = capsys.readouterr().out
    assert "nothing to check" in out


def test_storage_pass_exit_0(capsys):
    storage = ROOT / "fixtures" / "storage-plan" / "pass.json"
    code = main(["check", "--plan", str(storage), "--json"])
    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["fail"] == 0
    ids = {r["id"] for r in report["results"]}
    assert "storage.https_only" in ids


def test_storage_fail_exit_1(capsys):
    storage = ROOT / "fixtures" / "storage-plan" / "fail.json"
    code = main(["check", "--plan", str(storage), "--json"])
    assert code == 1
    report = json.loads(capsys.readouterr().out)
    by_id = {r["id"]: r for r in report["results"]}
    assert by_id["storage.https_only"]["severity"] == "fail"
    assert by_id["storage.network_restricted"]["severity"] == "warn"


def test_sql_pass_exit_0(capsys):
    sql = ROOT / "fixtures" / "sql-plan" / "pass.json"
    code = main(["check", "--plan", str(sql), "--json"])
    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["fail"] == 0
    ids = {r["id"] for r in report["results"]}
    assert "sql.public_network" in ids
    assert "sql.tde" in ids


def test_sql_fail_exit_1(capsys):
    sql = ROOT / "fixtures" / "sql-plan" / "fail.json"
    code = main(["check", "--plan", str(sql), "--json"])
    assert code == 1
    report = json.loads(capsys.readouterr().out)
    by_id = {r["id"]: r for r in report["results"]}
    assert by_id["sql.public_network"]["severity"] == "fail"
    assert by_id["sql.firewall_any_ip"]["severity"] == "fail"
    assert by_id["sql.tde"]["severity"] == "fail"


@pytest.mark.integration
def test_checkov_available():
    assert shutil.which("checkov"), "checkov must be on PATH for integration tests"
