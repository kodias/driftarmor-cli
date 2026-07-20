"""Tests for terraform plan JSON materialization."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from driftarmor.cli import main
from driftarmor.terraform_plan import (
    TerraformError,
    find_terraform,
    is_plan_json,
    materialize_plan_json,
    run_plan,
    show_plan_json,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_JSON = ROOT / "fixtures" / "aks-plan" / "pass.json"


def test_is_plan_json_true_for_fixture():
    assert is_plan_json(FIXTURE_JSON) is True


def test_is_plan_json_false_for_binaryish(tmp_path):
    binary = tmp_path / "tfplan"
    binary.write_bytes(b"\x00\x01not-json")
    assert is_plan_json(binary) is False


def test_materialize_json_plan_passthrough():
    with materialize_plan_json(plan=FIXTURE_JSON) as path:
        assert path == FIXTURE_JSON


def test_materialize_requires_exactly_one():
    with pytest.raises(TerraformError, match="exactly one"):
        with materialize_plan_json():
            pass
    with pytest.raises(TerraformError, match="exactly one"):
        with materialize_plan_json(plan=FIXTURE_JSON, module_dir=Path(".")):
            pass


def test_find_terraform_missing():
    with patch("driftarmor.terraform_plan.shutil.which", return_value=None):
        with pytest.raises(TerraformError, match="terraform not found"):
            find_terraform()


def test_show_plan_json_writes_file(tmp_path):
    binary = tmp_path / "tfplan"
    binary.write_bytes(b"fake-plan")
    payload = {"format_version": "1.2", "resource_changes": []}
    dest = tmp_path / "out"
    dest.mkdir()

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = json.dumps(payload)
    mock_proc.stderr = ""

    with (
        patch("driftarmor.terraform_plan.find_terraform", return_value=Path("terraform")),
        patch("driftarmor.terraform_plan.subprocess.run", return_value=mock_proc) as run,
    ):
        out = show_plan_json(binary, dest_dir=dest)

    assert out == dest / "plan.json"
    assert json.loads(out.read_text(encoding="utf-8")) == payload
    assert run.call_args.args[0][:3] == ["terraform", "show", "-json"]


def test_show_plan_json_nonzero_exit(tmp_path):
    binary = tmp_path / "tfplan"
    binary.write_bytes(b"fake")
    dest = tmp_path / "out"
    dest.mkdir()
    mock_proc = MagicMock()
    mock_proc.returncode = 1
    mock_proc.stdout = ""
    mock_proc.stderr = "bad plan\n"

    with (
        patch("driftarmor.terraform_plan.find_terraform", return_value=Path("terraform")),
        patch("driftarmor.terraform_plan.subprocess.run", return_value=mock_proc),
    ):
        with pytest.raises(TerraformError, match="terraform show -json failed"):
            show_plan_json(binary, dest_dir=dest)


def test_run_plan_then_show(tmp_path):
    module = tmp_path / "mod"
    module.mkdir()
    dest = tmp_path / "out"
    dest.mkdir()
    payload = {"format_version": "1.2", "resource_changes": []}

    plan_proc = MagicMock()
    plan_proc.returncode = 0
    plan_proc.stdout = "Plan: 0 to add\n"
    plan_proc.stderr = ""

    show_proc = MagicMock()
    show_proc.returncode = 0
    show_proc.stdout = json.dumps(payload)
    show_proc.stderr = ""

    with (
        patch("driftarmor.terraform_plan.find_terraform", return_value=Path("terraform")),
        patch(
            "driftarmor.terraform_plan.subprocess.run",
            side_effect=[plan_proc, show_proc],
        ) as run,
    ):
        # show_plan_json checks binary exists — create it when plan "runs"
        def _run(cmd, **kwargs):
            if cmd[1] == "plan":
                Path(cmd[2].removeprefix("-out=")).write_bytes(b"bin")
                return plan_proc
            return show_proc

        run.side_effect = _run
        out = run_plan(module, dest_dir=dest)

    assert json.loads(out.read_text(encoding="utf-8")) == payload
    assert run.call_count == 2


def test_materialize_binary_plan_calls_show(tmp_path):
    binary = tmp_path / "tfplan"
    binary.write_bytes(b"\x00binary")
    payload = {"format_version": "1.0", "resource_changes": []}

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = json.dumps(payload)
    mock_proc.stderr = ""

    with (
        patch("driftarmor.terraform_plan.find_terraform", return_value=Path("terraform")),
        patch("driftarmor.terraform_plan.subprocess.run", return_value=mock_proc),
    ):
        with materialize_plan_json(plan=binary) as path:
            assert is_plan_json(path)
            assert json.loads(path.read_text(encoding="utf-8")) == payload


def test_cli_dir_missing_terraform(tmp_path, capsys):
    module = tmp_path / "mod"
    module.mkdir()
    with patch("driftarmor.terraform_plan.shutil.which", return_value=None):
        code = main(["check", "--dir", str(module)])
    assert code == 2
    assert "terraform not found" in capsys.readouterr().err


def test_cli_mutually_exclusive_plan_and_dir(capsys):
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "check",
                "--plan",
                str(FIXTURE_JSON),
                "--dir",
                ".",
            ]
        )
    assert exc.value.code == 2
