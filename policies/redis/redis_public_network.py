"""CKV_DRIFTARMOR_REDIS_1 — redis.public_network"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _scalar(value):  # type: ignore[no-untyped-def]
    if isinstance(value, list) and value:
        return value[0]
    return value


class RedisPublicNetwork(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="Managed Redis public network access disabled",
            id="CKV_DRIFTARMOR_REDIS_1",
            categories=[CheckCategories.NETWORKING],
            supported_resources=["azurerm_managed_redis"],
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        # Defaults to Enabled — require explicit Disabled
        raw = _scalar(conf.get("public_network_access"))
        if raw is None:
            self.evaluated_keys = ["public_network_access"]
            return CheckResult.FAILED
        if str(raw).strip().lower() == "disabled":
            self.evaluated_keys = ["public_network_access"]
            return CheckResult.PASSED
        self.evaluated_keys = ["public_network_access"]
        return CheckResult.FAILED


check = RedisPublicNetwork()
