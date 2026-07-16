"""CKV_DRIFTARMOR_VM_3 — vm.linux_password_auth"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _truthy(value) -> bool:  # type: ignore[no-untyped-def]
    if isinstance(value, list):
        return bool(value) and _truthy(value[0])
    return bool(value)


class VmLinuxPasswordAuth(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="Linux VM disables password authentication",
            id="CKV_DRIFTARMOR_VM_3",
            categories=[CheckCategories.IAM],
            supported_resources=["azurerm_linux_virtual_machine"],
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        # Explicit false fails; missing defaults to true on azurerm — treat missing as pass
        val = conf.get("disable_password_authentication")
        if val is None:
            self.evaluated_keys = ["disable_password_authentication"]
            return CheckResult.PASSED
        if _truthy(val):
            self.evaluated_keys = ["disable_password_authentication"]
            return CheckResult.PASSED
        self.evaluated_keys = ["disable_password_authentication"]
        return CheckResult.FAILED


check = VmLinuxPasswordAuth()
