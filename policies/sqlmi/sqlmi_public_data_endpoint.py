"""CKV_DRIFTARMOR_SQLMI_1 — sqlmi.public_data_endpoint"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _scalar(value):  # type: ignore[no-untyped-def]
    if isinstance(value, list) and value:
        return value[0]
    return value


def _truthy(value) -> bool:  # type: ignore[no-untyped-def]
    if isinstance(value, list):
        return bool(value) and _truthy(value[0])
    return bool(value)


class SqlMiPublicDataEndpoint(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="SQL Managed Instance public data endpoint disabled",
            id="CKV_DRIFTARMOR_SQLMI_1",
            categories=[CheckCategories.NETWORKING],
            supported_resources=["azurerm_mssql_managed_instance"],
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        # Default is false — missing is pass; explicit true fails
        val = conf.get("public_data_endpoint_enabled")
        if val is None:
            self.evaluated_keys = ["public_data_endpoint_enabled"]
            return CheckResult.PASSED
        if _truthy(val):
            self.evaluated_keys = ["public_data_endpoint_enabled"]
            return CheckResult.FAILED
        pna = _scalar(val)
        if pna is False or str(pna).lower() == "false":
            self.evaluated_keys = ["public_data_endpoint_enabled"]
            return CheckResult.PASSED
        self.evaluated_keys = ["public_data_endpoint_enabled"]
        return CheckResult.FAILED


check = SqlMiPublicDataEndpoint()
