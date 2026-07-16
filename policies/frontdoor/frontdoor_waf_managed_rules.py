"""CKV_DRIFTARMOR_FD_3 — frontdoor.waf_managed_rules"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class FrontdoorWafManagedRules(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="Front Door WAF policy has managed rule sets",
            id="CKV_DRIFTARMOR_FD_3",
            categories=[CheckCategories.NETWORKING],
            supported_resources=["azurerm_cdn_frontdoor_firewall_policy"],
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        rules = conf.get("managed_rule")
        if rules:
            if isinstance(rules, list) and any(isinstance(r, dict) for r in rules):
                self.evaluated_keys = ["managed_rule"]
                return CheckResult.PASSED
            if isinstance(rules, dict):
                self.evaluated_keys = ["managed_rule"]
                return CheckResult.PASSED
        self.evaluated_keys = ["managed_rule"]
        return CheckResult.FAILED


check = FrontdoorWafManagedRules()
