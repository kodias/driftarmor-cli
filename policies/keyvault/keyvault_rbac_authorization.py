"""CKV_DRIFTARMOR_KV_1 — keyvault.rbac_authorization"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _is_true(value) -> bool:  # type: ignore[no-untyped-def]
    if isinstance(value, list):
        return bool(value) and _is_true(value[0])
    return value is True or str(value).lower() == "true"


class KeyVaultRbacAuthorization(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="Key Vault uses Azure RBAC authorization",
            id="CKV_DRIFTARMOR_KV_1",
            categories=[CheckCategories.IAM],
            supported_resources=["azurerm_key_vault"],
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        if _is_true(conf.get("rbac_authorization_enabled")):
            self.evaluated_keys = ["rbac_authorization_enabled"]
            return CheckResult.PASSED

        if _is_true(conf.get("enable_rbac_authorization")):
            self.evaluated_keys = ["enable_rbac_authorization"]
            return CheckResult.PASSED

        self.evaluated_keys = [
            "rbac_authorization_enabled",
            "enable_rbac_authorization",
        ]
        return CheckResult.FAILED


check = KeyVaultRbacAuthorization()
