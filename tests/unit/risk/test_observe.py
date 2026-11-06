"""E1 step 1: an alert group and its dossier become observations on campus objects."""

from __future__ import annotations

import pytest

from argus import site
from argus.risk import observe as ob
from argus.risk.config import STAGES
from argus.risk.observe import ObjectRef
from argus.risk.roles import MAX_VALUE
from argus.risk.rulemeta import RuleMeta
from tests.unit.risk.conftest import CONFIG, context, group, meta

pytestmark = pytest.mark.unit
OUTSIDE = "flagged by outside threat intel"


def sources(seen: ob.Observed, ref: ObjectRef | None = None) -> set[str]:
    return {o.source_key for o in seen.observations if ref is None or o.object == ref}


def test_an_outbound_group_gives_a_rule_and_an_evidence_observation_per_kind() -> None:
    g = group(severity="medium", signals={"proxy.regularity": 0.1, "ports.risky": 2,
                                          "ti.listed": 0}, flags=(OUTSIDE,),
              fields={"destination.ip": ["45.138.12.9"]})  # fmt: skip
    seen = ob.observe(g, meta(stages=1 << STAGES.index("foothold")), context())
    device = ObjectRef("device", "ip:10.1.1.1")
    assert seen.direction == "outbound"
    assert seen.objects == (device,)
    assert sources(seen) == {"rule:L-rule-a", "ev:beacon", "ev:ports", "ev:outside"}
    rule = next(o for o in seen.observations if o.source_kind == "rule")
    assert (rule.base, rule.family, rule.role, rule.threats) == (
        20.0, "squid", "actor", ("ip:45.138.12.9",)
    )  # fmt: skip
    strong = {o.source_key for o in seen.observations if o.strong}
    assert strong == {"ev:outside"}


def test_the_risk_score_scales_the_base_within_bounds() -> None:
    assert ob.rule_base(CONFIG, "low", 35) == pytest.approx(10 * 35 / 21)
    assert ob.rule_base(CONFIG, "LOW", None) == 10
    assert ob.rule_base(CONFIG, "critical", 99) == 60
    assert ob.rule_base(CONFIG, "high", 1000) == 70  # twice at most
    assert ob.rule_base(CONFIG, "high", 1) == 17.5  # half at least
    assert ob.rule_base(CONFIG, "info", 50) == CONFIG.unknown_severity_base


def test_blocked_or_failed_halves_the_rule_and_unknown_outcomes_do_not() -> None:
    assert ob.outcome_factor(("failure", "failure")) == 0.5
    assert ob.outcome_factor(("failure", "success")) == 1.0
    assert ob.outcome_factor(()) == 1.0
    seen = ob.observe(group(outcomes=("failure",), signals={"ports.risky": 1}), meta(), context())
    assert {o.source_kind: o.outcome for o in seen.observations} == {"rule": 0.5, "evidence": 1.0}


def test_a_stale_feed_gives_the_stale_base_and_is_not_strong() -> None:
    g = group(signals={"ti.listed": 3})
    fresh = ob.observe(g, meta(), context(fresh_feeds=frozenset({"mirror"})))
    stale = ob.observe(g, meta(), context(fresh_feeds=frozenset({"lookup"})))
    ti = [next(o for o in s.observations if o.source_key == "ev:ti") for s in (fresh, stale)]
    assert [(o.base, o.strong) for o in ti] == [(40, True), (20, False)]


def test_an_inbound_group_without_a_campus_target_has_no_object() -> None:
    seen = ob.observe(group(actor="45.138.12.7", severity="high",
                            signals={"web.successes_after": 4}), meta(), context())  # fmt: skip
    assert seen.direction == "inbound"
    assert seen.objects == ()
    assert seen.observations == ()


def test_an_inbound_group_puts_its_observations_on_the_campus_site() -> None:
    targets = {"url.domain": ["www.example.edu"], "destination.ip": ["131.21.124.10"]}
    g = group(actor="45.138.12.7", severity="high", signals={"web.successes_after": 4},
              fields=targets)  # fmt: skip
    seen = ob.observe(g, meta(), context())
    assert set(seen.objects) == {ObjectRef("site", "domain:www.example.edu"),
                                 ObjectRef("site", "ip:131.21.124.10")}  # fmt: skip
    assert {o.role for o in seen.observations} == {"target"}
    assert sources(seen) == {"rule:L-rule-a", "ev:success"}


def test_a_key_listing_many_sources_gives_one_device_each_up_to_the_cap() -> None:
    many = [f"10.9.{n // 250}.{n % 250 + 1}" for n in range(100)]
    seen = ob.observe(group(actor=many, signals={"dns.tunnel_suspected": True}), meta(), context())
    assert len(seen.objects) == CONFIG.max_actors
    assert len(seen.observations) == 2 * CONFIG.max_actors
    tunnel = [o for o in seen.observations if o.source_key == "ev:tunnel"]
    assert len(tunnel) == CONFIG.max_actors


def test_hosts_and_accounts_are_objects_and_generic_accounts_are_not() -> None:
    seen = ob.observe(group(actor="Lab-PC-7", field="host.name"), meta(), context())
    assert seen.objects == (ObjectRef("device", "host:lab-pc-7"),)
    seen = ob.observe(group(fields={"user.name": ["dana", "root"]}), meta(), context())
    assert set(seen.objects) == {ObjectRef("device", "ip:10.1.1.1"), ObjectRef("account", "dana")}
    seen = ob.observe(group(actor="Erin", field="user.name"), meta(), context())
    assert seen.objects == (ObjectRef("account", "erin"),)


def test_a_host_name_longer_than_a_value_may_be_is_no_object() -> None:
    long = "h" * (MAX_VALUE + 1)
    assert ob.observe(group(actor=long, field="host.name"), meta(), context()).objects == ()
    fits = "h" * MAX_VALUE
    assert ob.observe(group(actor=fits, field="host.name"), meta(), context()).objects == (
        ObjectRef("device", f"host:{fits}"),
    )


def test_a_rule_over_several_families_takes_each_groups_own_alerts_family() -> None:
    ctx = context(families=site.active().families)
    wide = meta(family=None)
    dns = group(indices=("acme-logs-dns-2026.10.20",))
    squid = group(indices=("acme-logs-squid-2026.10.20", "acme-logs-squid-2026.10.19"))
    both = group(indices=("acme-logs-squid-2026.10.20", "acme-logs-dns-2026.10.20"))

    def family(g: ob.Group, rule: RuleMeta | None = wide) -> str | None:
        return next(o.family for o in ob.observe(g, rule, ctx).observations
                    if o.source_kind == "rule")  # fmt: skip

    assert (family(dns), family(squid), family(both), family(group())) == (
        "dns", "squid", None, None
    )  # fmt: skip
    assert family(dns, meta(family="squid")) == "squid"  # a single-family rule's own family
    assert family(dns, None) == "dns"  # a rule without metadata yet


def test_a_known_infection_gives_no_observation_but_keeps_its_entities() -> None:
    seen = ob.observe(group(known=True, fields={"destination.ip": ["45.138.12.9"]}), meta(),
                      context())  # fmt: skip
    assert seen.observations == ()
    assert seen.objects == ()
    assert {e.value for e in seen.entities} == {"10.1.1.1", "45.138.12.9"}


def test_a_singleton_key_and_a_rule_without_metadata_still_observe() -> None:
    g = group()
    lone = ob.observe(ob.Group(**{**g.__dict__, "key": "alert:abc"}), None, context())
    assert lone.objects == ()
    seen = ob.observe(g, None, context())
    rule = next(o for o in seen.observations if o.source_kind == "rule")
    assert rule.source_key.startswith("rule:L")
    assert rule.stages == 0
    assert rule.family is None


def test_evidence_tests_read_known_values_only() -> None:
    seen = ob.observe(group(signals={"proxy.regularity": 0.5, "proxy.hosts_to_destination": 1,
                                     "ports.risky": "2", "dns.tunnel_suspected": False}),
                      meta(), context())  # fmt: skip
    assert sources(seen) == {"rule:L-rule-a", "ev:rare_dest"}
