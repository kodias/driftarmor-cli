"""CKV_DRIFTARMOR_AKS_2 — aks.node_pool.present (default_node_pool on cluster)."""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class AKSNodePoolPresent(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="AKS default node pool present",
            id="CKV_DRIFTARMOR_AKS_2",
            categories=[CheckCategories.KUBERNETES],
            supported_resources=["azurerm_kubernetes_cluster"],
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        self.evaluated_keys = ["default_node_pool"]
        pool = conf.get("default_node_pool")
        if not pool:
            return CheckResult.FAILED
        # Terraform conf values are typically list-wrapped.
        first = pool[0] if isinstance(pool, list) else pool
        if isinstance(first, dict) and first:
            return CheckResult.PASSED
        if first:
            return CheckResult.PASSED
        return CheckResult.FAILED


check = AKSNodePoolPresent()
