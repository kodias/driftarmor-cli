"""CKV_DRIFTARMOR_ACR_1 — acr.admin_disabled."""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _is_true(value) -> bool:  # type: ignore[no-untyped-def]
    if isinstance(value, list):
        return bool(value) and _is_true(value[0])
    return value is True or (isinstance(value, str) and value.lower() == "true")


class AcrAdminDisabled(BaseResourceCheck):
    """Fail only when the registry admin account is explicitly enabled."""

    def __init__(self) -> None:
        super().__init__(
            name="Container Registry admin account is disabled",
            id="CKV_DRIFTARMOR_ACR_1",
            categories=[CheckCategories.IAM],
            supported_resources=["azurerm_container_registry"],
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        self.evaluated_keys = ["admin_enabled"]
        if _is_true(conf.get("admin_enabled")):
            return CheckResult.FAILED
        return CheckResult.PASSED


check = AcrAdminDisabled()
