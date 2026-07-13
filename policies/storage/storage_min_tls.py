"""CKV_DRIFTARMOR_STORAGE_2 — storage.min_tls"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _scalar(value):  # type: ignore[no-untyped-def]
    if isinstance(value, list) and value:
        return value[0]
    return value


class StorageMinTls(BaseResourceCheck):
    def __init__(self) -> None:
        super().__init__(
            name="Storage account minimum TLS 1.2+",
            id="CKV_DRIFTARMOR_STORAGE_2",
            categories=[CheckCategories.ENCRYPTION],
            supported_resources=["azurerm_storage_account"],
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        raw = _scalar(conf.get("min_tls_version"))
        if raw is None:
            # Provider default is often TLS1_2 now; fail closed if unset in plan values
            self.evaluated_keys = ["min_tls_version"]
            return CheckResult.FAILED
        text = str(raw).upper().replace("-", "_")
        if text in ("TLS1_2", "TLS1_3", "TLSV1_2", "TLSV1_3"):
            self.evaluated_keys = ["min_tls_version"]
            return CheckResult.PASSED
        self.evaluated_keys = ["min_tls_version"]
        return CheckResult.FAILED


check = StorageMinTls()
