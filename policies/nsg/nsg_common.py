"""Shared NSG helpers (no Checkov ``check`` export — not a policy module)."""

from __future__ import annotations

from typing import Any


def scalar(value: Any) -> Any:
    if isinstance(value, list) and value:
        return value[0]
    return value


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def is_internet_source(prefix: Any) -> bool:
    text = str(scalar(prefix) or "").strip().lower()
    return text in {"*", "0.0.0.0/0", "internet", "any"}


def port_matches(port_fields: list[Any], target: str) -> bool:
    for raw in port_fields:
        for item in as_list(raw):
            text = str(item or "").strip().lower()
            if not text:
                continue
            if text in {"*", target}:
                return True
            if "-" in text and text[0].isdigit():
                try:
                    lo_s, hi_s = text.split("-", 1)
                    lo, hi = int(lo_s), int(hi_s)
                    t = int(target)
                    if lo <= t <= hi:
                        return True
                except ValueError:
                    continue
    return False


def is_inbound_allow(rule: dict[str, Any]) -> bool:
    direction = str(scalar(rule.get("direction")) or "").lower()
    access = str(scalar(rule.get("access")) or "").lower()
    return direction == "inbound" and access == "allow"


def iter_nsg_inline_rules(conf: dict[str, Any]) -> list[dict[str, Any]]:
    rules = conf.get("security_rule")
    if not rules:
        return []
    if isinstance(rules, list):
        return [r for r in rules if isinstance(r, dict)]
    if isinstance(rules, dict):
        return [rules]
    return []


def rule_destination_ports(rule: dict[str, Any]) -> list[Any]:
    fields: list[Any] = []
    if "destination_port_range" in rule:
        fields.append(rule.get("destination_port_range"))
    if "destination_port_ranges" in rule:
        fields.extend(as_list(rule.get("destination_port_ranges")))
    return fields


def rule_source_prefixes(rule: dict[str, Any]) -> list[Any]:
    fields: list[Any] = []
    if "source_address_prefix" in rule:
        fields.append(rule.get("source_address_prefix"))
    if "source_address_prefixes" in rule:
        fields.extend(as_list(rule.get("source_address_prefixes")))
    return fields


def opens_port_from_internet(rule: dict[str, Any], port: str) -> bool:
    if not is_inbound_allow(rule):
        return False
    if not any(is_internet_source(p) for p in rule_source_prefixes(rule)):
        return False
    return port_matches(rule_destination_ports(rule), port)


def opens_all_ports_from_internet(rule: dict[str, Any]) -> bool:
    if not is_inbound_allow(rule):
        return False
    if not any(is_internet_source(p) for p in rule_source_prefixes(rule)):
        return False
    for raw in rule_destination_ports(rule):
        for item in as_list(raw):
            text = str(item or "").strip()
            if text == "*":
                return True
    return False
