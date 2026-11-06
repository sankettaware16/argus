"""E0: what a rule says about itself (tactics, stages, family) and a lineage that survives the
rule being recreated and changes nothing when it is renamed."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus import site
from argus.risk import rulemeta
from argus.risk.config import STAGES

pytestmark = pytest.mark.unit
T0 = datetime(2026, 10, 1, tzinfo=UTC)
THREAT = [
    {"framework": "MITRE ATT&CK", "tactic": {"id": "TA0011", "name": "Command and Control"}},
    {"framework": "MITRE ATT&CK", "tactic": {"id": "TA0010", "name": "Exfiltration"}},
    {"framework": "MITRE ATT&CK", "tactic": {"id": "TA0011", "name": "command and  control"}},
]


def bit(stage: str) -> int:
    return 1 << STAGES.index(stage)


def test_tactics_are_read_once_each_in_lower_case() -> None:
    assert rulemeta.tactics_of(THREAT) == ("command and control", "exfiltration")
    assert rulemeta.tactics_of(None) == ()
    assert rulemeta.tactics_of([{"tactic": {"name": ""}}, "junk", 3]) == ()


def test_every_attack_tactic_has_a_stage_and_a_rule_may_cover_two() -> None:
    assert rulemeta.stage_mask(("command and control", "exfiltration")) == (
        bit("foothold") | bit("actions")
    )
    assert rulemeta.stage_mask(("reconnaissance", "resource development")) == bit("recon")
    assert rulemeta.stage_mask(("initial access",)) == bit("access")
    assert rulemeta.stage_mask(("a tactic nobody knows",)) == 0
    assert set(rulemeta.TACTIC_STAGE.values()) == set(STAGES)


def test_meta_reads_dotted_and_nested_rule_fields_and_the_source_index() -> None:
    dotted = {"kibana.alert.rule.threat": THREAT, "kibana.alert.rule.indices": ["acme-logs-dns-*"]}
    nested = {"kibana": {"alert": {"rule": {"threat": THREAT, "parameters": {"index": ["x-*"]}}}}}
    ancestors = [{"index": "acme-logs-*"}, {"index": "acme-logs-squid-2026.10.15"}]
    assert rulemeta.meta_from(dotted, ancestors) == (
        ("command and control", "exfiltration"), ("acme-logs-dns-*",),
        "acme-logs-squid-2026.10.15",
    )  # fmt: skip
    assert rulemeta.meta_from(nested, None)[1] == ("x-*",)
    assert rulemeta.meta_from(None, "junk") == ((), (), None)


def test_a_rule_has_a_family_only_when_every_index_entry_names_that_one() -> None:
    families = site.active().families
    assert rulemeta.family_of(["acme-logs-squid*"], families) == "squid"
    assert rulemeta.family_of(["acme-logs-dns-*"], families) == "dns"
    # a rule that reads everything names no family, whatever its newest alert's index was:
    # each of its alert groups takes its own alerts' family (index_family)
    assert rulemeta.family_of(["acme-logs-*"], families) is None
    assert rulemeta.family_of(["acme-logs-squid-*", "acme-logs-*"], families) is None
    # two families named: none (the engine counts one rule as one family at most)
    assert rulemeta.family_of(["acme-logs-squid-*", "acme-logs-dns-*"], families) is None
    assert rulemeta.family_of([], families) is None


def test_an_alert_groups_family_is_the_one_its_own_alerts_indices_belong_to() -> None:
    families = site.active().families
    assert rulemeta.index_family(["acme-logs-squid-2026.10.30"], families) == "squid"
    assert rulemeta.index_family(
        [".ds-acme-logs-dns-2026.10.30-000001", "acme-logs-dns-2026.10.31"], families
    ) == "dns"  # fmt: skip
    assert rulemeta.index_family(["acme-logs-squid-2026.10.30", "acme-logs-dns-2026.10.30"],
                                 families) is None  # two families: none  # fmt: skip
    assert rulemeta.index_family(["an-unrelated-index"], families) is None
    assert rulemeta.index_family([], families) is None
    assert rulemeta.source_index([{"index": "acme-logs-*"}, {"index": "x-1"}]) == "x-1"
    assert rulemeta.source_index("junk") is None


def row(rule_id: str, name: str | None, lineage: str | None = None, days: int = 0) -> rulemeta._Row:
    return rulemeta._Row(rule_id, name, lineage, T0 + timedelta(days=days))


def test_a_recreated_rule_takes_the_lineage_of_the_rule_with_its_name() -> None:
    first = rulemeta.assign_lineages([row("old", "Beacon  Rule")])
    assert first == {"old": rulemeta.new_lineage("old")}
    again = rulemeta.assign_lineages(
        [row("old", "Beacon Rule", first["old"]), row("new", "beacon rule", days=5)]
    )
    assert again == {"new": first["old"]}


def test_a_renamed_rule_keeps_its_lineage_and_a_new_name_gets_its_own() -> None:
    known = rulemeta.new_lineage("r1")
    assert rulemeta.assign_lineages([row("r1", "A new name", known)]) == {}
    out = rulemeta.assign_lineages([row("r1", "A", known), row("r2", "B", days=1)])
    assert out == {"r2": rulemeta.new_lineage("r2")}


def test_two_new_rules_with_one_name_share_the_older_ones_lineage() -> None:
    out = rulemeta.assign_lineages([row("b", "Same", days=2), row("a", "same", days=1)])
    assert out == {"a": rulemeta.new_lineage("a"), "b": rulemeta.new_lineage("a")}
    nameless = rulemeta.assign_lineages([row("x", None), row("y", "  ")])
    assert nameless == {"x": rulemeta.new_lineage("x"), "y": rulemeta.new_lineage("y")}


@given(
    st.lists(
        st.tuples(st.sampled_from("abcdef"), st.integers(min_value=0, max_value=20)),
        min_size=1, max_size=12, unique_by=lambda t: t,
    )
)  # fmt: skip
def test_lineages_follow_names_and_ignore_the_rule_ids(rules: list[tuple[str, int]]) -> None:
    """Rules with one name share one lineage, rules with different names never do, whatever
    the ids are called (the id only seeds the first lineage of a name)."""
    rows = [row(f"id-{n}", name, days=day) for n, (name, day) in enumerate(rules)]
    out = rulemeta.assign_lineages(rows)
    by_name: dict[str, set[str]] = {}
    for r in rows:
        assert r.name is not None
        by_name.setdefault(r.name, set()).add(out[r.rule_id])
    assert all(len(v) == 1 for v in by_name.values())
    lineages = [next(iter(v)) for v in by_name.values()]
    assert len(set(lineages)) == len(lineages)
