"""CKV_DRIFTARMOR_AKS_3 — aks.monitor.oms_or_dcr (oms_agent path; DCR OR'd in CLI)."""

import dpath

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class AKSMonitorOms(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="AKS OMS agent or monitoring configured",
            id="CKV_DRIFTARMOR_AKS_3",
            categories=[CheckCategories.LOGGING],
            supported_resources=["azurerm_kubernetes_cluster"],
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        # azurerm >= 3.x
        if dpath.search(conf, "oms_agent/[0]/log_analytics_workspace_id"):
            self.evaluated_keys = ["oms_agent/[0]/log_analytics_workspace_id"]
            return CheckResult.PASSED
        if conf.get("oms_agent"):
            self.evaluated_keys = ["oms_agent"]
            return CheckResult.PASSED
        # azurerm < 3.x addon_profile
        if dpath.search(conf, "addon_profile/[0]/oms_agent/[0]/enabled"):
            enabled = dpath.get(conf, "addon_profile/[0]/oms_agent/[0]/enabled")
            self.evaluated_keys = ["addon_profile/[0]/oms_agent/[0]/enabled"]
            if enabled and enabled[0]:
                return CheckResult.PASSED
        self.evaluated_keys = ["oms_agent"]
        return CheckResult.FAILED


check = AKSMonitorOms()
