"""CKV_DRIFTARMOR_NSG_2 — nsg.open_rdp_internet"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

from nsg_common import (  # type: ignore[import-not-found]
    iter_nsg_inline_rules,
    opens_port_from_internet,
)


class NsgOpenRdpInternet(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="NSG must not allow RDP (3389) from the Internet",
            id="CKV_DRIFTARMOR_NSG_2",
            categories=[CheckCategories.NETWORKING],
            supported_resources=[
                "azurerm_network_security_group",
                "azurerm_network_security_rule",
            ],
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        if "direction" in conf and "access" in conf:
            if opens_port_from_internet(conf, "3389"):
                self.evaluated_keys = [
                    "direction",
                    "access",
                    "source_address_prefix",
                    "destination_port_range",
                ]
                return CheckResult.FAILED
            self.evaluated_keys = ["direction", "access"]
            return CheckResult.PASSED

        for rule in iter_nsg_inline_rules(conf):
            if opens_port_from_internet(rule, "3389"):
                self.evaluated_keys = ["security_rule"]
                return CheckResult.FAILED
        self.evaluated_keys = ["security_rule"]
        return CheckResult.PASSED


check = NsgOpenRdpInternet()
