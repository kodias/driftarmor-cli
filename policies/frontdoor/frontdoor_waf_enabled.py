"""CKV_DRIFTARMOR_FD_1 — frontdoor.waf_enabled"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _truthy(value) -> bool:  # type: ignore[no-untyped-def]
    if isinstance(value, list):
        return bool(value) and _truthy(value[0])
    return bool(value)


class FrontdoorWafEnabled(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="Front Door WAF policy is enabled",
            id="CKV_DRIFTARMOR_FD_1",
            categories=[CheckCategories.NETWORKING],
            supported_resources=["azurerm_cdn_frontdoor_firewall_policy"],
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        # Default when unset is typically enabled; explicit false fails
        val = conf.get("enabled")
        if val is None:
            self.evaluated_keys = ["enabled"]
            return CheckResult.PASSED
        if _truthy(val):
            self.evaluated_keys = ["enabled"]
            return CheckResult.PASSED
        self.evaluated_keys = ["enabled"]
        return CheckResult.FAILED


check = FrontdoorWafEnabled()
