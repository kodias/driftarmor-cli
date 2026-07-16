"""CKV_DRIFTARMOR_VM_2 — vm.trusted_launch"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

_VM_TYPES = [
    "azurerm_linux_virtual_machine",
    "azurerm_windows_virtual_machine",
]


def _truthy(value) -> bool:  # type: ignore[no-untyped-def]
    if isinstance(value, list):
        return bool(value) and _truthy(value[0])
    return bool(value)


class VmTrustedLaunch(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="VM Trusted Launch (secure boot + vTPM)",
            id="CKV_DRIFTARMOR_VM_2",
            categories=[CheckCategories.ENCRYPTION],
            supported_resources=_VM_TYPES,
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        secure = _truthy(conf.get("secure_boot_enabled"))
        vtpm = _truthy(conf.get("vtpm_enabled"))
        if secure and vtpm:
            self.evaluated_keys = ["secure_boot_enabled", "vtpm_enabled"]
            return CheckResult.PASSED
        self.evaluated_keys = ["secure_boot_enabled", "vtpm_enabled"]
        return CheckResult.FAILED


check = VmTrustedLaunch()
