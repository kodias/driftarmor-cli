"""CKV_DRIFTARMOR_REDIS_2 — redis.client_protocol"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _scalar(value):  # type: ignore[no-untyped-def]
    if isinstance(value, list) and value:
        return value[0]
    return value


def _default_database(conf):  # type: ignore[no-untyped-def]
    block = conf.get("default_database")
    if not block:
        return None
    entry = block[0] if isinstance(block, list) else block
    return entry if isinstance(entry, dict) else None


class RedisClientProtocol(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="Managed Redis client protocol is Encrypted",
            id="CKV_DRIFTARMOR_REDIS_2",
            categories=[CheckCategories.ENCRYPTION],
            supported_resources=["azurerm_managed_redis"],
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        db = _default_database(conf)
        if db is None:
            # Missing database is a separate plan problem; treat protocol as fail closed
            self.evaluated_keys = ["default_database"]
            return CheckResult.FAILED
        proto = _scalar(db.get("client_protocol"))
        if proto is None:
            # Provider default is Encrypted
            self.evaluated_keys = ["default_database/[0]/client_protocol"]
            return CheckResult.PASSED
        if str(proto).strip().lower() == "encrypted":
            self.evaluated_keys = ["default_database/[0]/client_protocol"]
            return CheckResult.PASSED
        self.evaluated_keys = ["default_database/[0]/client_protocol"]
        return CheckResult.FAILED


check = RedisClientProtocol()
