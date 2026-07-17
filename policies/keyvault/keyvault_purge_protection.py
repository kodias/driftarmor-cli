"""CKV_DRIFTARMOR_KV_2 — keyvault.purge_protection"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _is_true(value) -> bool:  # type: ignore[no-untyped-def]
    if isinstance(value, list):
        return bool(value) and _is_true(value[0])
    return value is True or str(value).lower() == "true"


class KeyVaultPurgeProtection(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="Key Vault purge protection enabled",
            id="CKV_DRIFTARMOR_KV_2",
            categories=[CheckCategories.ENCRYPTION],
            supported_resources=["azurerm_key_vault"],
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        self.evaluated_keys = ["purge_protection_enabled"]
        if _is_true(conf.get("purge_protection_enabled")):
            return CheckResult.PASSED
        return CheckResult.FAILED


check = KeyVaultPurgeProtection()
