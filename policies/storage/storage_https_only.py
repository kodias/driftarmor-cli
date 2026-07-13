"""CKV_DRIFTARMOR_STORAGE_1 — storage.https_only"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _truthy(value) -> bool:  # type: ignore[no-untyped-def]
    if isinstance(value, list):
        return bool(value) and _truthy(value[0])
    return bool(value)


class StorageHttpsOnly(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="Storage account requires HTTPS (secure transfer)",
            id="CKV_DRIFTARMOR_STORAGE_1",
            categories=[CheckCategories.ENCRYPTION],
            supported_resources=["azurerm_storage_account"],
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        # Explicit false fails; missing defaults to true on modern API — treat missing as pass
        val = conf.get("https_traffic_only_enabled")
        if val is None:
            val = conf.get("enable_https_traffic_only")
        if val is None:
            self.evaluated_keys = ["https_traffic_only_enabled"]
            return CheckResult.PASSED
        if _truthy(val):
            self.evaluated_keys = ["https_traffic_only_enabled"]
            return CheckResult.PASSED
        self.evaluated_keys = ["https_traffic_only_enabled", "enable_https_traffic_only"]
        return CheckResult.FAILED


check = StorageHttpsOnly()
