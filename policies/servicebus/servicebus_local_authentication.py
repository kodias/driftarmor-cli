"""CKV_DRIFTARMOR_SB_1 — servicebus.local_authentication."""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _is_false(value) -> bool:  # type: ignore[no-untyped-def]
    if isinstance(value, list):
        return bool(value) and _is_false(value[0])
    return value is False or (
        isinstance(value, str) and value.strip().lower() == "false"
    )


class ServiceBusLocalAuthentication(BaseResourceCheck):
    """Require Microsoft Entra authentication by disabling local SAS access."""

    def __init__(self) -> None:
        super().__init__(
            name="Service Bus local authentication is disabled",
            id="CKV_DRIFTARMOR_SB_1",
            categories=[CheckCategories.IAM],
            supported_resources=["azurerm_servicebus_namespace"],
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        self.evaluated_keys = ["local_auth_enabled"]
        if _is_false(conf.get("local_auth_enabled")):
            return CheckResult.PASSED
        return CheckResult.FAILED


check = ServiceBusLocalAuthentication()
