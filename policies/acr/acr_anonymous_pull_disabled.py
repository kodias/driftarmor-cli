"""CKV_DRIFTARMOR_ACR_2 — acr.anonymous_pull_disabled."""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _is_true(value) -> bool:  # type: ignore[no-untyped-def]
    if isinstance(value, list):
        return bool(value) and _is_true(value[0])
    return value is True or (isinstance(value, str) and value.lower() == "true")


class AcrAnonymousPullDisabled(BaseResourceCheck):
    """Fail only when unauthenticated image pulls are explicitly enabled."""

    def __init__(self) -> None:
        super().__init__(
            name="Container Registry anonymous pull is disabled",
            id="CKV_DRIFTARMOR_ACR_2",
            categories=[CheckCategories.IAM],
            supported_resources=["azurerm_container_registry"],
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        self.evaluated_keys = ["anonymous_pull_enabled"]
        if _is_true(conf.get("anonymous_pull_enabled")):
            return CheckResult.FAILED
        return CheckResult.PASSED


check = AcrAnonymousPullDisabled()
