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


def test_vm_pass_exit_0(capsys):
    vm = ROOT / "fixtures" / "vm-plan" / "pass.json"
    code = main(["check", "--plan", str(vm), "--json"])
    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["fail"] == 0
    ids = {r["id"] for r in report["results"]}
    assert "vm.encryption_at_host" in ids
    assert "vm.trusted_launch" in ids
    assert "vm.linux_password_auth" in ids


def test_vm_fail_exit_1(capsys):
    vm = ROOT / "fixtures" / "vm-plan" / "fail.json"
    code = main(["check", "--plan", str(vm), "--json"])
    assert code == 1
    report = json.loads(capsys.readouterr().out)
    by_id = {r["id"]: r for r in report["results"]}
    assert by_id["vm.encryption_at_host"]["severity"] == "fail"
    assert by_id["vm.trusted_launch"]["severity"] == "fail"
    assert by_id["vm.linux_password_auth"]["severity"] == "fail"
    assert by_id["vm.managed_identity"]["severity"] == "warn"


def test_nsg_pass_exit_0(capsys):
    nsg = ROOT / "fixtures" / "nsg-plan" / "pass.json"
    code = main(["check", "--plan", str(nsg), "--json"])
    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["fail"] == 0
    ids = {r["id"] for r in report["results"]}
    assert "nsg.open_ssh_internet" in ids


def test_nsg_fail_exit_1(capsys):
    nsg = ROOT / "fixtures" / "nsg-plan" / "fail.json"
    code = main(["check", "--plan", str(nsg), "--json"])
    assert code == 1
    report = json.loads(capsys.readouterr().out)
    by_id = {r["id"]: r for r in report["results"]}
    assert by_id["nsg.open_ssh_internet"]["severity"] == "fail"
    assert by_id["nsg.open_rdp_internet"]["severity"] == "fail"
    assert by_id["nsg.open_all_internet"]["severity"] == "fail"


def test_sqlmi_pass_exit_0(capsys):
    path = ROOT / "fixtures" / "sqlmi-plan" / "pass.json"
    code = main(["check", "--plan", str(path), "--json"])
    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["fail"] == 0
    ids = {r["id"] for r in report["results"]}
    assert "sqlmi.public_data_endpoint" in ids
    assert "sqlmi.entra_admin" in ids


def test_sqlmi_fail_exit_1(capsys):
    path = ROOT / "fixtures" / "sqlmi-plan" / "fail.json"
    code = main(["check", "--plan", str(path), "--json"])
    assert code == 1
    report = json.loads(capsys.readouterr().out)
    by_id = {r["id"]: r for r in report["results"]}
    assert by_id["sqlmi.public_data_endpoint"]["severity"] == "fail"
    assert by_id["sqlmi.min_tls"]["severity"] == "fail"
    assert by_id["sqlmi.entra_admin"]["severity"] == "fail"
    assert by_id["sqlmi.identity"]["severity"] == "warn"


def test_frontdoor_pass_exit_0(capsys):
    path = ROOT / "fixtures" / "frontdoor-plan" / "pass.json"
    code = main(["check", "--plan", str(path), "--json"])
    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["fail"] == 0
    ids = {r["id"] for r in report["results"]}
    assert "frontdoor.waf_attached" in ids
    assert "frontdoor.waf_prevention" in ids


def test_frontdoor_fail_exit_1(capsys):
    path = ROOT / "fixtures" / "frontdoor-plan" / "fail.json"
    code = main(["check", "--plan", str(path), "--json"])
    assert code == 1
    report = json.loads(capsys.readouterr().out)
    by_id = {r["id"]: r for r in report["results"]}
    assert by_id["frontdoor.waf_attached"]["severity"] == "pass"
    assert by_id["frontdoor.waf_enabled"]["severity"] == "fail"
    assert by_id["frontdoor.waf_prevention"]["severity"] == "fail"
    assert by_id["frontdoor.waf_managed_rules"]["severity"] == "fail"


def test_redis_pass_exit_0(capsys):
    path = ROOT / "fixtures" / "redis-plan" / "pass.json"
    code = main(["check", "--plan", str(path), "--json"])
    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["fail"] == 0
    ids = {r["id"] for r in report["results"]}
    assert "redis.public_network" in ids
    assert "redis.client_protocol" in ids


def test_redis_fail_exit_1(capsys):
    path = ROOT / "fixtures" / "redis-plan" / "fail.json"
    code = main(["check", "--plan", str(path), "--json"])
    assert code == 1
    report = json.loads(capsys.readouterr().out)
    by_id = {r["id"]: r for r in report["results"]}
    assert by_id["redis.public_network"]["severity"] == "fail"
    assert by_id["redis.client_protocol"]["severity"] == "fail"
    assert by_id["redis.access_keys_auth"]["severity"] == "fail"
    assert by_id["redis.identity"]["severity"] == "warn"


@pytest.mark.integration
def test_checkov_available():
    assert shutil.which("checkov"), "checkov must be on PATH for integration tests"
