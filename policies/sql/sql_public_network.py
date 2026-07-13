"""CKV_DRIFTARMOR_SQL_1 — sql.public_network"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _scalar(value):  # type: ignore[no-untyped-def]
    if isinstance(value, list) and value:
        return value[0]
    return value


class SqlPublicNetwork(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="Azure SQL server public network access disabled",
            id="CKV_DRIFTARMOR_SQL_1",
            categories=[CheckCategories.NETWORKING],
            supported_resources=["azurerm_mssql_server"],
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        pna = _scalar(conf.get("public_network_access_enabled"))
        if pna is False or str(pna).lower() == "false":
            self.evaluated_keys = ["public_network_access_enabled"]
            return CheckResult.PASSED
        self.evaluated_keys = ["public_network_access_enabled"]
        return CheckResult.FAILED


check = SqlPublicNetwork()
