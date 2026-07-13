"""Unit tests for drift normalizer and report builder."""

from __future__ import annotations

import pytest

from driftarmor.drift import (
    UnknownActionsError,
    build_drift_report,
    exit_code_for_drift,
    normalize_actions,
)


def test_normalize_singles():
    assert normalize_actions(["create"]) == "create"
    assert normalize_actions(["update"]) == "update"
    assert normalize_actions(["delete"]) == "delete"


def test_normalize_replace_both_orders():
    assert normalize_actions(["delete", "create"]) == "replace"
    assert normalize_actions(["create", "delete"]) == "replace"


def test_normalize_silent_skip():
    assert normalize_actions(["read"]) is None
    assert normalize_actions(["no-op"]) is None
    assert normalize_actions([]) is None
    assert normalize_actions(None) is None


def test_normalize_unknown_raises():
    with pytest.raises(UnknownActionsError):
        normalize_actions(["create", "update"])
    with pytest.raises(UnknownActionsError):
        normalize_actions(["explode"])


def test_build_report_sorts_and_omits_secrets():
    plan = {
        "resource_changes": [
            {
                "address": "b.res",
                "type": "t",
                "name": "res",
                "change": {
                    "actions": ["update"],
                    "before": {"password": "secret"},
                    "after": {"password": "secret2"},
                },
            },
            {
                "address": "a.res",
                "type": "t",
                "name": "res",
                "change": {"actions": ["create"]},
            },
        ]
    }
    report = build_drift_report(plan)
    assert [r["address"] for r in report["results"]] == ["a.res", "b.res"]
    blob = str(report)
    assert "password" not in blob
    assert "secret" not in blob
    assert report["summary"]["create"] == 1
    assert report["summary"]["update"] == 1
    assert exit_code_for_drift(report) == 0


def test_exit_code_replace():
    report = {
        "summary": {"create": 0, "update": 0, "delete": 0, "replace": 1},
        "results": [],
    }
    assert exit_code_for_drift(report) == 1


def test_malformed_resource_changes_type():
    with pytest.raises(UnknownActionsError):
        build_drift_report({"resource_changes": "nope"})
