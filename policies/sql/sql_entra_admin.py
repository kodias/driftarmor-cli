"""CKV_DRIFTARMOR_SQL_2 — sql.entra_admin"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _scalar(value):  # type: ignore[no-untyped-def]
    if isinstance(value, list) and value:
        return value[0]
    return value


class SqlEntraAdmin(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="Azure SQL server has Microsoft Entra administrator",
            id="CKV_DRIFTARMOR_SQL_2",
            categories=[CheckCategories.IAM],
            supported_resources=["azurerm_mssql_server"],
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        # Nested azuread_administrator block (provider 3.x+)
        block = conf.get("azuread_administrator")
        if block:
            entry = block[0] if isinstance(block, list) else block
            if isinstance(entry, dict):
                login = _scalar(entry.get("login_username")) or _scalar(entry.get("login"))
                oid = _scalar(entry.get("object_id"))
                if login or oid:
                    self.evaluated_keys = ["azuread_administrator"]
                    return CheckResult.PASSED

        self.evaluated_keys = ["azuread_administrator"]
        return CheckResult.FAILED


check = SqlEntraAdmin()
