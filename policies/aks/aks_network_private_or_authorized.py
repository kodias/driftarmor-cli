"""CKV_DRIFTARMOR_AKS_5 — aks.network.private_or_authorized (warn on fail in mapper)."""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _truthy(value) -> bool:  # type: ignore[no-untyped-def]
    if isinstance(value, list):
        return bool(value) and _truthy(value[0])
    return bool(value)


def _non_empty_list(value) -> bool:  # type: ignore[no-untyped-def]
    if value is None:
        return False
    if isinstance(value, list):
        if not value:
            return False
        inner = value[0]
        if isinstance(inner, list):
            return bool(inner)
        return bool(inner)
    return bool(value)


class AKSNetworkPrivateOrAuthorized(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="AKS private cluster or authorized API IP ranges",
            id="CKV_DRIFTARMOR_AKS_5",
            categories=[CheckCategories.NETWORKING],
            supported_resources=["azurerm_kubernetes_cluster"],
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        if _truthy(conf.get("private_cluster_enabled")):
            self.evaluated_keys = ["private_cluster_enabled"]
            return CheckResult.PASSED

        # Legacy top-level attribute
        if _non_empty_list(conf.get("api_server_authorized_ip_ranges")):
            self.evaluated_keys = ["api_server_authorized_ip_ranges"]
            return CheckResult.PASSED

        profile = conf.get("api_server_access_profile")
        if profile:
            block = profile[0] if isinstance(profile, list) else profile
            if isinstance(block, dict) and _non_empty_list(block.get("authorized_ip_ranges")):
                self.evaluated_keys = [
                    "api_server_access_profile/[0]/authorized_ip_ranges"
                ]
                return CheckResult.PASSED

        self.evaluated_keys = [
            "private_cluster_enabled",
            "api_server_access_profile",
        ]
        return CheckResult.FAILED


check = AKSNetworkPrivateOrAuthorized()
