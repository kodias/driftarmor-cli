"""Focused behavior tests for the Service Bus Checkov policies."""

from checkov.common.models.enums import CheckResult

from policies.servicebus.servicebus_local_authentication import (
    check as local_authentication,
)
from policies.servicebus.servicebus_min_tls import check as min_tls
from policies.servicebus.servicebus_network_restricted import (
    check as network_restricted,
)


def test_local_authentication_accepts_scalar_and_wrapped_false_values():
    assert (
        local_authentication.scan_resource_conf({"local_auth_enabled": False})
        is CheckResult.PASSED
    )
    assert (
        local_authentication.scan_resource_conf({"local_auth_enabled": ["false"]})
        is CheckResult.PASSED
    )


def test_local_authentication_fails_enabled_or_missing_values():
    assert (
        local_authentication.scan_resource_conf({"local_auth_enabled": [True]})
        is CheckResult.FAILED
    )
    assert local_authentication.scan_resource_conf({}) is CheckResult.FAILED


def test_min_tls_accepts_scalar_and_wrapped_version_1_2():
    assert (
        min_tls.scan_resource_conf({"minimum_tls_version": "1.2"})
        is CheckResult.PASSED
    )
    assert (
        min_tls.scan_resource_conf({"minimum_tls_version": [1.2]})
        is CheckResult.PASSED
    )


def test_min_tls_fails_older_or_missing_values():
    assert (
        min_tls.scan_resource_conf({"minimum_tls_version": ["1.1"]})
        is CheckResult.FAILED
    )
    assert min_tls.scan_resource_conf({}) is CheckResult.FAILED


def test_network_restriction_accepts_scalar_and_wrapped_false_values():
    assert (
        network_restricted.scan_resource_conf(
            {"public_network_access_enabled": False}
        )
        is CheckResult.PASSED
    )
    assert (
        network_restricted.scan_resource_conf(
            {"public_network_access_enabled": ["false"]}
        )
        is CheckResult.PASSED
    )


def test_network_restriction_accepts_inline_default_deny_rule_set():
    assert (
        network_restricted.scan_resource_conf(
            {
                "public_network_access_enabled": [True],
                "network_rule_set": [{"default_action": ["Deny"]}],
            }
        )
        is CheckResult.PASSED
    )


def test_network_restriction_fails_enabled_or_missing_values():
    assert (
        network_restricted.scan_resource_conf(
            {"public_network_access_enabled": [True]}
        )
        is CheckResult.FAILED
    )
    assert network_restricted.scan_resource_conf({}) is CheckResult.FAILED
