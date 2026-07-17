"""CKV_DRIFTARMOR_REDIS_3 — redis.access_keys_auth"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _truthy(value) -> bool:  # type: ignore[no-untyped-def]
    if isinstance(value, list):
        return bool(value) and _truthy(value[0])
    return bool(value)


def _default_database(conf):  # type: ignore[no-untyped-def]
    block = conf.get("default_database")
    if not block:
        return None
    entry = block[0] if isinstance(block, list) else block
    return entry if isinstance(entry, dict) else None


class RedisAccessKeysAuth(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="Managed Redis access key authentication disabled",
            id="CKV_DRIFTARMOR_REDIS_3",
            categories=[CheckCategories.IAM],
            supported_resources=["azurerm_managed_redis"],
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        db = _default_database(conf)
        if db is None:
            self.evaluated_keys = ["default_database"]
            return CheckResult.PASSED
        val = db.get("access_keys_authentication_enabled")
        if val is None:
            # Provider default is false
            self.evaluated_keys = [
                "default_database/[0]/access_keys_authentication_enabled"
            ]
            return CheckResult.PASSED
        if _truthy(val):
            self.evaluated_keys = [
                "default_database/[0]/access_keys_authentication_enabled"
            ]
            return CheckResult.FAILED
        self.evaluated_keys = [
            "default_database/[0]/access_keys_authentication_enabled"
        ]
        return CheckResult.PASSED


check = RedisAccessKeysAuth()
