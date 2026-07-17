"""CKV_DRIFTARMOR_KV_3 — keyvault.network_restricted"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _scalar(value):  # type: ignore[no-untyped-def]
    if isinstance(value, list) and value:
        return value[0]
    return value


class KeyVaultNetworkRestricted(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="Key Vault public access disabled or network ACLs deny by default",
            id="CKV_DRIFTARMOR_KV_3",
            categories=[CheckCategories.NETWORKING],
            supported_resources=["azurerm_key_vault"],
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        public_access = _scalar(conf.get("public_network_access_enabled"))
        if public_access is False or str(public_access).lower() == "false":
            self.evaluated_keys = ["public_network_access_enabled"]
            return CheckResult.PASSED

        network_acls = conf.get("network_acls")
        if network_acls:
            block = network_acls[0] if isinstance(network_acls, list) else network_acls
            if isinstance(block, dict):
                default_action = _scalar(block.get("default_action"))
                if str(default_action).lower() == "deny":
                    self.evaluated_keys = ["network_acls/[0]/default_action"]
                    return CheckResult.PASSED

        self.evaluated_keys = ["public_network_access_enabled", "network_acls"]
        return CheckResult.FAILED


check = KeyVaultNetworkRestricted()
