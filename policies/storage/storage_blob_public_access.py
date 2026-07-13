"""CKV_DRIFTARMOR_STORAGE_3 — storage.blob_public_access"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _scalar(value):  # type: ignore[no-untyped-def]
    if isinstance(value, list) and value:
        return value[0]
    return value


class StorageBlobPublicAccess(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="Storage account disallows public blob access",
            id="CKV_DRIFTARMOR_STORAGE_3",
            categories=[CheckCategories.NETWORKING],
            supported_resources=["azurerm_storage_account"],
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        # allow_nested_items_to_be_public=false is the secure setting
        nested = _scalar(conf.get("allow_nested_items_to_be_public"))
        if nested is False or nested == "false":
            self.evaluated_keys = ["allow_nested_items_to_be_public"]
            return CheckResult.PASSED
        if nested is True or nested == "true":
            self.evaluated_keys = ["allow_nested_items_to_be_public"]
            return CheckResult.FAILED

        # Legacy name
        legacy = _scalar(conf.get("allow_blob_public_access"))
        if legacy is False or legacy == "false":
            self.evaluated_keys = ["allow_blob_public_access"]
            return CheckResult.PASSED
        if legacy is True or legacy == "true":
            self.evaluated_keys = ["allow_blob_public_access"]
            return CheckResult.FAILED

        # Unset — insecure default historically true
        self.evaluated_keys = ["allow_nested_items_to_be_public"]
        return CheckResult.FAILED


check = StorageBlobPublicAccess()
