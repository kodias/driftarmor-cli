"""CKV_DRIFTARMOR_SQL_4 — sql.firewall_any_ip"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _scalar(value):  # type: ignore[no-untyped-def]
    if isinstance(value, list) and value:
        return value[0]
    return value


class SqlFirewallAnyIp(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="Azure SQL firewall must not allow 0.0.0.0-255.255.255.255",
            id="CKV_DRIFTARMOR_SQL_4",
            categories=[CheckCategories.NETWORKING],
            supported_resources=["azurerm_mssql_firewall_rule"],
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        start = str(_scalar(conf.get("start_ip_address")) or "")
        end = str(_scalar(conf.get("end_ip_address")) or "")
        # Azure "Allow Azure services" uses 0.0.0.0-0.0.0.0 — allow that; block full internet
        if start == "0.0.0.0" and end == "255.255.255.255":
            self.evaluated_keys = ["start_ip_address", "end_ip_address"]
            return CheckResult.FAILED
        self.evaluated_keys = ["start_ip_address", "end_ip_address"]
        return CheckResult.PASSED


check = SqlFirewallAnyIp()
