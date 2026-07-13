"""CKV_DRIFTARMOR_STORAGE_4 — storage.network_restricted (warn on fail in mapper)."""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _scalar(value):  # type: ignore[no-untyped-def]
    if isinstance(value, list) and value:
        return value[0]
    return value


class StorageNetworkRestricted(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="Storage public network disabled or network rules Deny",
            id="CKV_DRIFTARMOR_STORAGE_4",
            categories=[CheckCategories.NETWORKING],
            supported_resources=["azurerm_storage_account"],
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        pna = _scalar(conf.get("public_network_access_enabled"))
        if pna is False or str(pna).lower() == "false":
            self.evaluated_keys = ["public_network_access_enabled"]
            return CheckResult.PASSED

        rules = conf.get("network_rules")
        if rules:
            block = rules[0] if isinstance(rules, list) else rules
            if isinstance(block, dict):
                action = _scalar(block.get("default_action"))
                if str(action).lower() == "deny":
                    self.evaluated_keys = ["network_rules/[0]/default_action"]
                    return CheckResult.PASSED

        self.evaluated_keys = ["public_network_access_enabled", "network_rules"]
        return CheckResult.FAILED


check = StorageNetworkRestricted()
