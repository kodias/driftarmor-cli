"""CKV_DRIFTARMOR_AKS_1 — aks.cluster.present"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class AKSClusterPresent(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="AKS cluster resource present",
            id="CKV_DRIFTARMOR_AKS_1",
            categories=[CheckCategories.KUBERNETES],
            supported_resources=["azurerm_kubernetes_cluster"],
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        # Presence of the resource in the plan is sufficient.
        self.evaluated_keys = []
        return CheckResult.PASSED


check = AKSClusterPresent()
