"""CKV_DRIFTARMOR_SQL_3 — sql.min_tls"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _scalar(value):  # type: ignore[no-untyped-def]
    if isinstance(value, list) and value:
        return value[0]
    return value


class SqlMinTls(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="Azure SQL server minimum TLS 1.2+",
            id="CKV_DRIFTARMOR_SQL_3",
            categories=[CheckCategories.ENCRYPTION],
            supported_resources=["azurerm_mssql_server"],
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        raw = _scalar(conf.get("minimum_tls_version"))
        if raw is None:
            self.evaluated_keys = ["minimum_tls_version"]
            return CheckResult.FAILED
        text = str(raw).strip()
        # Values like "1.2", "1.3", or "Version12"
        if text in ("1.2", "1.3", "12", "Version12", "TLS1_2", "TLS1_3"):
            self.evaluated_keys = ["minimum_tls_version"]
            return CheckResult.PASSED
        try:
            if float(text) >= 1.2:
                self.evaluated_keys = ["minimum_tls_version"]
                return CheckResult.PASSED
        except ValueError:
            pass
        self.evaluated_keys = ["minimum_tls_version"]
        return CheckResult.FAILED


check = SqlMinTls()
