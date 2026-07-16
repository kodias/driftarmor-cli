"""CKV_DRIFTARMOR_VM_1 — vm.encryption_at_host"""

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


class VmEncryptionAtHost(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="VM encryption at host enabled",
            id="CKV_DRIFTARMOR_VM_1",
            categories=[CheckCategories.ENCRYPTION],
            supported_resources=_VM_TYPES,
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        if _truthy(conf.get("encryption_at_host_enabled")):
            self.evaluated_keys = ["encryption_at_host_enabled"]
            return CheckResult.PASSED
        self.evaluated_keys = ["encryption_at_host_enabled"]
        return CheckResult.FAILED


check = VmEncryptionAtHost()
