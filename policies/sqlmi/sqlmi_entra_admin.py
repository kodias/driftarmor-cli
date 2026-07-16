"""CKV_DRIFTARMOR_SQLMI_3 — sqlmi.entra_admin"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _scalar(value):  # type: ignore[no-untyped-def]
    if isinstance(value, list) and value:
        return value[0]
    return value


class SqlMiEntraAdmin(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="SQL Managed Instance has Microsoft Entra administrator",
            id="CKV_DRIFTARMOR_SQLMI_3",
            categories=[CheckCategories.IAM],
            supported_resources=["azurerm_mssql_managed_instance"],
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        block = conf.get("azuread_administrator")
        if block:
            entry = block[0] if isinstance(block, list) else block
            if isinstance(entry, dict):
                login = _scalar(entry.get("login_username")) or _scalar(
                    entry.get("login")
                )
                oid = _scalar(entry.get("object_id"))
                if login or oid:
                    self.evaluated_keys = ["azuread_administrator"]
                    return CheckResult.PASSED
        self.evaluated_keys = ["azuread_administrator"]
        return CheckResult.FAILED


check = SqlMiEntraAdmin()
