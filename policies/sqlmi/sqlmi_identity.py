"""CKV_DRIFTARMOR_SQLMI_4 — sqlmi.identity (warn on fail in mapper)."""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _scalar(value):  # type: ignore[no-untyped-def]
    if isinstance(value, list) and value:
        return value[0]
    return value


class SqlMiIdentity(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="SQL Managed Instance has a managed identity",
            id="CKV_DRIFTARMOR_SQLMI_4",
            categories=[CheckCategories.IAM],
            supported_resources=["azurerm_mssql_managed_instance"],
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        identity = conf.get("identity")
        if not identity:
            self.evaluated_keys = ["identity"]
            return CheckResult.FAILED
        block = identity[0] if isinstance(identity, list) else identity
        if not isinstance(block, dict):
            self.evaluated_keys = ["identity"]
            return CheckResult.FAILED
        itype = str(_scalar(block.get("type")) or "").lower().replace(" ", "")
        if itype in (
            "systemassigned",
            "userassigned",
            "systemassigned,userassigned",
        ):
            self.evaluated_keys = ["identity/[0]/type"]
            return CheckResult.PASSED
        self.evaluated_keys = ["identity/[0]/type"]
        return CheckResult.FAILED


check = SqlMiIdentity()
