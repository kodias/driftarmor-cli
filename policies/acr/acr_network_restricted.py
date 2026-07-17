"""CKV_DRIFTARMOR_ACR_3 — acr.network_restricted."""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _scalar(value):  # type: ignore[no-untyped-def]
    while isinstance(value, list) and value:
        value = value[0]
    return value


class AcrNetworkRestricted(BaseResourceCheck):
    """Require disabled public access or a default-deny network rule set."""

    def __init__(self) -> None:
        super().__init__(
            name="Container Registry public access disabled or network rules deny by default",
            id="CKV_DRIFTARMOR_ACR_3",
            categories=[CheckCategories.NETWORKING],
            supported_resources=["azurerm_container_registry"],
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        public_access = _scalar(conf.get("public_network_access_enabled"))
        if public_access is False or (
            isinstance(public_access, str) and public_access.lower() == "false"
        ):
            self.evaluated_keys = ["public_network_access_enabled"]
            return CheckResult.PASSED

        rule_set = _scalar(conf.get("network_rule_set"))
        if isinstance(rule_set, dict):
            default_action = _scalar(rule_set.get("default_action"))
            if isinstance(default_action, str) and default_action.lower() == "deny":
                self.evaluated_keys = ["network_rule_set/[0]/default_action"]
                return CheckResult.PASSED

        self.evaluated_keys = ["public_network_access_enabled", "network_rule_set"]
        return CheckResult.FAILED


check = AcrNetworkRestricted()
