"""CLI tests for drift subcommand and color flags."""

from __future__ import annotations

import json
from pathlib import Path

from driftarmor.cli import main

ROOT = Path(__file__).resolve().parents[1]
DRIFT = ROOT / "fixtures" / "drift-plan"
AKS = ROOT / "fixtures" / "aks-plan"


def test_drift_empty_exit_0(capsys):
    code = main(["drift", "--plan", str(DRIFT / "empty.json"), "--json"])
    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["results"] == []
    assert report["summary"]["create"] == 0


def test_drift_unknown_actions_exit_2(capsys):
    code = main(["drift", "--plan", str(DRIFT / "unknown_actions.json")])
    assert code == 2
    err = capsys.readouterr().err.lower()
    assert "unknown" in err or "multi-action" in err


def test_drift_create_update_exit_0(capsys):
    code = main(["drift", "--plan", str(DRIFT / "create_update.json"), "--json"])
    assert code == 0
    out = capsys.readouterr().out
    report = json.loads(out)
    assert report["summary"]["create"] == 1
    assert report["summary"]["update"] == 1
    assert "secret" not in out
    assert "MUST_NOT_APPEAR" not in out


def test_drift_destroy_exit_1(capsys):
    code = main(["drift", "--plan", str(DRIFT / "destroy.json"), "--json"])
    assert code == 1
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["delete"] == 1


def test_drift_replace_exit_1(capsys):
    code = main(["drift", "--plan", str(DRIFT / "replace.json"), "--json"])
    assert code == 1
    report = json.loads(capsys.readouterr().out)
    assert report["results"][0]["action_class"] == "replace"
    assert report["results"][0]["actions"] == ["delete", "create"]


def test_drift_noop_read_exit_0(capsys):
    code = main(["drift", "--plan", str(DRIFT / "noop_read.json"), "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["results"] == []


def test_drift_malformed_resource_changes_exit_2(capsys):
    code = main(["drift", "--plan", str(DRIFT / "malformed_resource_changes.json")])
    assert code == 2
    err = capsys.readouterr().err
    assert "resource_changes" in err


def test_drift_human_no_color_no_ansi(capsys):
    code = main(
        [
            "drift",
            "--plan",
            str(DRIFT / "create_update.json"),
            "--no-color",
        ]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert "\033[" not in out
    assert "create" in out
    assert "update" in out


def test_check_human_no_color_no_ansi(capsys):
    code = main(
        [
            "check",
            "--plan",
            str(AKS / "no_aks.json"),
            "--no-color",
        ]
    )
    assert code == 0
    assert "\033[" not in capsys.readouterr().out


def test_drift_json_no_ansi(capsys):
    main(["drift", "--plan", str(DRIFT / "destroy.json"), "--json"])
    out = capsys.readouterr().out
    assert "\033[" not in out
    assert "MUST_NOT_APPEAR" not in out
