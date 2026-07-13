"""CKV_DRIFTARMOR_SQL_5 — sql.tde"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _scalar(value):  # type: ignore[no-untyped-def]
    if isinstance(value, list) and value:
        return value[0]
    return value


class SqlTde(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="Azure SQL database transparent data encryption enabled",
            id="CKV_DRIFTARMOR_SQL_5",
            categories=[CheckCategories.ENCRYPTION],
            supported_resources=["azurerm_mssql_database"],
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        # transparent_data_encryption_enabled defaults true; explicit false fails
        tde = _scalar(conf.get("transparent_data_encryption_enabled"))
        if tde is False or str(tde).lower() == "false":
            self.evaluated_keys = ["transparent_data_encryption_enabled"]
            return CheckResult.FAILED
        self.evaluated_keys = ["transparent_data_encryption_enabled"]
        return CheckResult.PASSED


check = SqlTde()
