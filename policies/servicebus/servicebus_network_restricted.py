"""CKV_DRIFTARMOR_SB_3 — servicebus.network_restricted."""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _is_false(value) -> bool:  # type: ignore[no-untyped-def]
    if isinstance(value, list):
        return bool(value) and _is_false(value[0])
    return value is False or (
        isinstance(value, str) and value.strip().lower() == "false"
    )


def _scalar(value):  # type: ignore[no-untyped-def]
    while isinstance(value, list) and value:
        value = value[0]
    return value


class ServiceBusNetworkRestricted(BaseResourceCheck):
    """Require disabled public access or an inline default-Deny rule set."""

    def __init__(self) -> None:
        super().__init__(
            name=(
                "Service Bus public access disabled or network rules deny by default"
            ),
            id="CKV_DRIFTARMOR_SB_3",
            categories=[CheckCategories.NETWORKING],
            supported_resources=["azurerm_servicebus_namespace"],
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        if _is_false(conf.get("public_network_access_enabled")):
            self.evaluated_keys = ["public_network_access_enabled"]
            return CheckResult.PASSED

        rule_set = _scalar(conf.get("network_rule_set"))
        if isinstance(rule_set, dict):
            default_action = _scalar(rule_set.get("default_action"))
            if str(default_action or "").lower() == "deny":
                self.evaluated_keys = ["network_rule_set/[0]/default_action"]
                return CheckResult.PASSED

        self.evaluated_keys = ["public_network_access_enabled", "network_rule_set"]
        return CheckResult.FAILED


check = ServiceBusNetworkRestricted()
