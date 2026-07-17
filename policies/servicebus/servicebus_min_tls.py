"""CKV_DRIFTARMOR_SB_2 — servicebus.min_tls."""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _scalar(value):  # type: ignore[no-untyped-def]
    while isinstance(value, list) and value:
        value = value[0]
    return value


class ServiceBusMinTls(BaseResourceCheck):
    """Require the namespace minimum TLS version to be explicitly set to 1.2."""

    def __init__(self) -> None:
        super().__init__(
            name="Service Bus minimum TLS version is 1.2",
            id="CKV_DRIFTARMOR_SB_2",
            categories=[CheckCategories.ENCRYPTION],
            supported_resources=["azurerm_servicebus_namespace"],
        )

    def scan_resource_conf(self, conf):  # type: ignore[no-untyped-def]
        self.evaluated_keys = ["minimum_tls_version"]
        value = _scalar(conf.get("minimum_tls_version"))
        if value is not None and str(value).strip() == "1.2":
            return CheckResult.PASSED
        return CheckResult.FAILED


check = ServiceBusMinTls()
