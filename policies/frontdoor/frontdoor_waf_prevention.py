"""CKV_DRIFTARMOR_FD_2 — frontdoor.waf_prevention"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _scalar(value):  # type: ignore[no-untyped-def]
    if isinstance(value, list) and value:
        return value[0]
    return value


class FrontdoorWafPrevention(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="Front Door WAF policy mode is Prevention",
            id="CKV_DRIFTARMOR_FD_2",
            categories=[CheckCategories.NETWORKING],
            supported_resources=["azurerm_cdn_frontdoor_firewall_policy"],
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        mode = str(_scalar(conf.get("mode")) or "").strip().lower()
        if mode == "prevention":
            self.evaluated_keys = ["mode"]
            return CheckResult.PASSED
        self.evaluated_keys = ["mode"]
        return CheckResult.FAILED


check = FrontdoorWafPrevention()
