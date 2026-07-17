"""Focused behavior tests for the Azure Container Registry Checkov policies."""

from checkov.common.models.enums import CheckResult

from policies.acr.acr_admin_disabled import check as admin_disabled
from policies.acr.acr_anonymous_pull_disabled import (
    check as anonymous_pull_disabled,
)
from policies.acr.acr_network_restricted import check as network_restricted


def test_admin_disabled_accepts_missing_default_and_explicit_false():
    assert admin_disabled.scan_resource_conf({}) is CheckResult.PASSED
    assert (
        admin_disabled.scan_resource_conf({"admin_enabled": [False]})
        is CheckResult.PASSED
    )
    assert (
        admin_disabled.scan_resource_conf({"admin_enabled": ["false"]})
        is CheckResult.PASSED
    )


def test_admin_disabled_fails_explicit_true():
    assert (
        admin_disabled.scan_resource_conf({"admin_enabled": [True]})
        is CheckResult.FAILED
    )
    assert (
        admin_disabled.scan_resource_conf({"admin_enabled": ["true"]})
        is CheckResult.FAILED
    )


def test_anonymous_pull_disabled_accepts_missing_default_and_explicit_false():
    assert anonymous_pull_disabled.scan_resource_conf({}) is CheckResult.PASSED
    assert (
        anonymous_pull_disabled.scan_resource_conf(
            {"anonymous_pull_enabled": [False]}
        )
        is CheckResult.PASSED
    )
    assert (
        anonymous_pull_disabled.scan_resource_conf(
            {"anonymous_pull_enabled": ["false"]}
        )
        is CheckResult.PASSED
    )


def test_anonymous_pull_disabled_fails_explicit_true():
    assert (
        anonymous_pull_disabled.scan_resource_conf(
            {"anonymous_pull_enabled": [True]}
        )
        is CheckResult.FAILED
    )
    assert (
        anonymous_pull_disabled.scan_resource_conf(
            {"anonymous_pull_enabled": ["true"]}
        )
        is CheckResult.FAILED
    )


def test_network_restriction_accepts_disabled_public_access_or_deny_rule_set():
    assert (
        network_restricted.scan_resource_conf(
            {"public_network_access_enabled": [False]}
        )
        is CheckResult.PASSED
    )
    assert (
        network_restricted.scan_resource_conf(
            {
                "public_network_access_enabled": [True],
                "network_rule_set": [{"default_action": ["Deny"]}],
            }
        )
        is CheckResult.PASSED
    )


def test_network_restriction_fails_open_or_missing_configuration():
    assert (
        network_restricted.scan_resource_conf(
            {
                "public_network_access_enabled": [True],
                "network_rule_set": [{"default_action": ["Allow"]}],
            }
        )
        is CheckResult.FAILED
    )
    assert network_restricted.scan_resource_conf({}) is CheckResult.FAILED
