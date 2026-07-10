"""CKV_DRIFTARMOR_AKS_4 — aks.rbac.azure_rbac"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _truthy(value) -> bool:  # type: ignore[no-untyped-def]
    if isinstance(value, list):
        return bool(value) and _truthy(value[0])
    return bool(value)


class AKSAzureRbac(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="AKS Azure RBAC or Kubernetes RBAC enabled",
            id="CKV_DRIFTARMOR_AKS_4",
            categories=[CheckCategories.IAM],
            supported_resources=["azurerm_kubernetes_cluster"],
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        # Modern: azure_active_directory_role_based_access_control.azure_rbac_enabled
        aad = conf.get("azure_active_directory_role_based_access_control")
        if aad:
            block = aad[0] if isinstance(aad, list) else aad
            if isinstance(block, dict):
                enabled = block.get("azure_rbac_enabled")
                if _truthy(enabled):
                    self.evaluated_keys = [
                        "azure_active_directory_role_based_access_control/[0]/azure_rbac_enabled"
                    ]
                    return CheckResult.PASSED

        # Legacy: role_based_access_control.enabled
        rbac = conf.get("role_based_access_control")
        if rbac:
            block = rbac[0] if isinstance(rbac, list) else rbac
            if isinstance(block, dict) and _truthy(block.get("enabled")):
                self.evaluated_keys = ["role_based_access_control/[0]/enabled"]
                return CheckResult.PASSED

        # azurerm >= 2.99 flat flag (Kubernetes RBAC)
        if _truthy(conf.get("role_based_access_control_enabled")):
            self.evaluated_keys = ["role_based_access_control_enabled"]
            return CheckResult.PASSED

        self.evaluated_keys = [
            "azure_active_directory_role_based_access_control",
            "role_based_access_control",
        ]
        return CheckResult.FAILED


check = AKSAzureRbac()
