"""Consistency checks for the rule metadata registry."""

from driftarmor.report import (
    DEFAULT_FAIL_DETAIL,
    DEFAULT_TITLES,
    FAIL_SEVERITY,
    PACK_AUTO_RULES,
    load_citations,
)


def test_every_automatic_rule_has_complete_report_metadata():
    rule_ids = {rule_id for rules in PACK_AUTO_RULES.values() for rule_id in rules}
    citations = load_citations()

    assert rule_ids <= FAIL_SEVERITY.keys()
    assert rule_ids <= DEFAULT_TITLES.keys()
    assert rule_ids <= DEFAULT_FAIL_DETAIL.keys()
    assert rule_ids <= citations.keys()
    for rule_id in rule_ids:
        assert citations[rule_id].get("citation_url")
        assert citations[rule_id].get("citation_verified")
