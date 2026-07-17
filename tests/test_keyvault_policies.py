"""Focused behavior tests for the Key Vault Checkov policies."""

from checkov.common.models.enums import CheckResult

from policies.keyvault.keyvault_network_restricted import (
    check as network_restricted,
)
from policies.keyvault.keyvault_purge_protection import (
    check as purge_protection,
)
from policies.keyvault.keyvault_rbac_authorization import (
    check as rbac_authorization,
)


def test_rbac_accepts_modern_and_legacy_list_wrapped_true_values():
    assert (
        rbac_authorization.scan_resource_conf({"rbac_authorization_enabled": [True]})
        is CheckResult.PASSED
    )
    assert (
        rbac_authorization.scan_resource_conf({"enable_rbac_authorization": ["true"]})
        is CheckResult.PASSED
    )


def test_rbac_fails_false_or_missing_values():
    assert (
        rbac_authorization.scan_resource_conf({"rbac_authorization_enabled": [False]})
        is CheckResult.FAILED
    )
    assert rbac_authorization.scan_resource_conf({}) is CheckResult.FAILED


def test_purge_protection_requires_true():
    assert (
        purge_protection.scan_resource_conf({"purge_protection_enabled": [True]})
        is CheckResult.PASSED
    )
    assert (
        purge_protection.scan_resource_conf({"purge_protection_enabled": [False]})
        is CheckResult.FAILED
    )
    assert purge_protection.scan_resource_conf({}) is CheckResult.FAILED


def test_network_restriction_accepts_disabled_public_access_or_deny_acl():
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
                "network_acls": [{"default_action": ["Deny"]}],
            }
        )
        is CheckResult.PASSED
    )


def test_network_restriction_fails_open_or_missing_configuration():
    assert (
        network_restricted.scan_resource_conf(
            {
                "public_network_access_enabled": [True],
                "network_acls": [{"default_action": ["Allow"]}],
            }
        )
        is CheckResult.FAILED
    )
    assert network_restricted.scan_resource_conf({}) is CheckResult.FAILED
