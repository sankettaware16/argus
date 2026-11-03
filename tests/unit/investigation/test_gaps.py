"""Q-F3: the gap ranking (plan §7.3 point 2), one table per kind of gap, the order between the
kinds, determinism, and that no gap or check is found by a rule's name."""

from __future__ import annotations

import random
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.investigation import catalogue, gaps
from argus.investigation.gaps import Assessed, Kind, Profile
from argus.report import facts as fx
from tests.unit.investigation.kit import DNS, NGINX, SQUID, body, ref, step, unknown
from tests.unit.report.kit import signal

pytestmark = pytest.mark.unit
SQUID_RULE = Profile("query", SQUID)
NGINX_RULE = Profile("query", NGINX)


def keyed(found: tuple[gaps.Gap, ...]) -> dict[str, gaps.Gap]:
    return {g.key: g for g in found}


# ----------------------------------------------------------------------------- floor signals


@pytest.mark.parametrize(
    ("name", "reason", "profile", "closers", "blocked"),
    [
        ("ti.listed", "source_not_checked", SQUID_RULE, ("ti.lookup",), False),
        ("ti.listed_remote", "timeout", NGINX_RULE, ("ti.lookup",), False),
        ("ti.listed", "source_stale", SQUID_RULE, ("ti.lookup",), True),
        ("proxy.regularity", "timeout", SQUID_RULE, ("proxy.host",), False),
        ("proxy.regularity", "skipped_budget", NGINX_RULE, (), True),  # it reads no proxy log
        ("proxy.regularity", "no_value", SQUID_RULE, ("proxy.host",), True),
        ("proxy.hosts_to_destination", "failed", SQUID_RULE, ("proxy.destination",), False),
        ("web.successes_after", "deferred", NGINX_RULE, ("web.followups",), False),
        ("web.successes_after", "ingest_not_verified", NGINX_RULE, ("web.followups",), True),
        ("ports.risky", "no_fields", SQUID_RULE, (), True),
        ("ports.risky", "partial_coverage", SQUID_RULE, (), True),
    ],
)
def test_floor_signals(name: str, reason: str, profile: Profile, closers: tuple[str, ...],
                       blocked: bool) -> None:  # fmt: skip
    found = gaps.find(body([unknown(name, reason)]), profile)
    (gap,) = found
    assert gap.kind is Kind.FLOOR
    assert gap.key == f"signal:{name}"
    assert gap.floor
    assert gap.closers == closers
    assert (gap.blocker is not None) is blocked
    assert gap.closable is not blocked
    assert gap.what.endswith("could not tell.")


def test_a_zero_that_is_not_trusted_yet_is_never_asked_again() -> None:
    (gap,) = gaps.find(body([unknown("web.successes_after", "ingest_not_verified")]), NGINX_RULE)
    assert gap.blocker == fx.plain("ingest_not_verified")


def test_floor_gaps_come_in_the_floors_own_order() -> None:
    names = list(reversed(fx.FLOOR))
    found = gaps.find(body([unknown(n, "timeout") for n in names]), SQUID_RULE)
    assert [g.key for g in found] == [f"signal:{n}" for n in fx.FLOOR]
    assert [g.rank for g in found] == list(range(1, len(fx.FLOOR) + 1))


def test_a_known_floor_signal_is_no_gap() -> None:
    assert gaps.find(body([signal("ti.listed", 0)]), SQUID_RULE) == ()


# ----------------------------------------------------------------------------- note steps


@pytest.mark.parametrize(
    ("needs", "profile", "closers", "blocked"),
    [
        (["timeline"], SQUID_RULE, ("proxy.host", "proxy.pair"), False),
        (["prevalence"], SQUID_RULE, ("proxy.destination",), False),
        (["reputation"], NGINX_RULE, ("ti.lookup",), False),
        (["log_pivot"], SQUID_RULE, ("proxy.host",), False),
        (["log_pivot"], NGINX_RULE, ("web.followups",), False),
        (["timeline", "prevalence"], SQUID_RULE,
         ("proxy.destination", "proxy.host", "proxy.pair"), False),
        (["timeline"], NGINX_RULE, (), True),  # nothing the rule reads could answer it
        (["log_pivot"], Profile("query", DNS), (), True),
    ],
)  # fmt: skip
def test_deferred_steps(needs: list[str], profile: Profile, closers: tuple[str, ...],
                        blocked: bool) -> None:  # fmt: skip
    (gap,) = gaps.find(body(steps=[step(3, "deferred", needs)]), profile)
    assert gap.kind is Kind.DEFERRED
    assert gap.key == "step:3"
    assert set(gap.closers) == set(closers)
    assert list(gap.closers) == sorted(gap.closers, key=lambda t: (catalogue.CHECKS[t].weight, t))
    assert (gap.blocker is not None) is blocked
    assert not gap.floor


def test_a_deferred_step_whose_first_closer_answered_waits_for_the_next() -> None:
    evidence = [ref("proxy.host", "ok")]
    (gap,) = gaps.find(body(steps=[step(2, "deferred", ["timeline"])], evidence=evidence),
                       SQUID_RULE)  # fmt: skip
    assert gap.exhausted == ("proxy.host",)
    assert gap.open == ("proxy.pair",)
    assert gap.closable


def test_a_deferred_step_whose_closers_all_answered_is_blocked() -> None:
    evidence = [ref("proxy.host", "ok"), ref("proxy.pair", "empty")]
    (gap,) = gaps.find(body(steps=[step(2, "deferred", ["timeline"])], evidence=evidence),
                       SQUID_RULE)  # fmt: skip
    assert gap.blocker == "it was asked already and the answer did not settle it"


def test_a_failed_answer_does_not_use_a_closer_up() -> None:
    evidence = [ref("proxy.host", "timeout")]
    (gap,) = gaps.find(body(steps=[step(2, "deferred", ["timeline"])], evidence=evidence),
                       SQUID_RULE)  # fmt: skip
    assert gap.exhausted == ()
    assert gap.open[0] == "proxy.host"


@pytest.mark.parametrize(
    ("rule_type", "profile_indices", "closers", "blocked"),
    [
        ("threshold", SQUID, ("logs.source_events",), False),
        ("esql", NGINX, ("logs.source_events",), False),
        ("threshold", ("other-index-*",), (), True),  # a source the rule does not read
        ("query", SQUID, (), True),  # an event alert: its ancestors, which ARGUS cannot look up
        ("eql", SQUID, (), True),
        (None, SQUID, (), True),
    ],
)
def test_unknown_steps(rule_type: str | None, profile_indices: tuple[str, ...],
                       closers: tuple[str, ...], blocked: bool) -> None:  # fmt: skip
    (gap,) = gaps.find(body(steps=[step(1, "unknown")]), Profile(rule_type, profile_indices))
    assert gap.kind is Kind.UNKNOWN_STEP
    assert gap.closers == closers
    assert (gap.blocker is not None) is blocked
    assert not gap.floor


def test_answered_and_manual_steps_are_no_gaps() -> None:
    steps = [step(1, "answered"), step(2, "manual")]
    assert gaps.find(body(steps=steps), SQUID_RULE) == ()


# ----------------------------------------------------------------------------- unknown signals


@pytest.mark.parametrize(
    ("name", "reason", "closers", "blocked"),
    [
        ("pair.beats", "timeout", ("proxy.pair",), False),
        ("contact.hosts", "failed", ("proxy.contact",), False),
        ("proxy.destinations", "deferred", ("proxy.host",), False),
        ("alerts.cadence_cv", "too_few_alerts", (), True),
        ("nat.hint", "no_fields", (), True),
        ("pair.period_s", "no_value", ("proxy.pair",), True),
    ],
)
def test_unknown_signals(name: str, reason: str, closers: tuple[str, ...], blocked: bool) -> None:
    (gap,) = gaps.find(body([unknown(name, reason)]), SQUID_RULE)
    assert gap.kind is Kind.SIGNAL
    assert gap.key == f"signal:{name}"
    assert gap.closers == closers
    assert (gap.blocker is not None) is blocked
    assert not gap.floor


def test_unknown_signals_come_in_name_order_after_the_floor_and_the_steps() -> None:
    signals = [unknown("pair.beats", "timeout"), unknown("nat.hint", "no_fields"),
               unknown("ti.listed", "timeout")]  # fmt: skip
    found = gaps.find(body(signals, [step(1, "deferred", ["prevalence"])]), SQUID_RULE)
    assert [g.key for g in found] == ["signal:ti.listed", "step:1", "signal:nat.hint",
                                       "signal:pair.beats"]  # fmt: skip


def test_the_count_signals_are_not_gaps() -> None:
    assert gaps.find(body([signal("steps.deferred", 0)]), SQUID_RULE) == ()


# ----------------------------------------------------------------------------- the decision


@pytest.mark.parametrize(
    ("outcome", "confidence", "found"),
    [
        ("benign_expected", 0.4, True),
        ("benign_expected", 0.59, True),
        ("benign_expected", 0.6, False),
        ("true_positive", 0.95, False),
        ("inconclusive", 0.9, True),
        ("inconclusive", None, True),
        (None, 0.1, False),  # no decision: not a low confidence, an undecided item
    ],
)
def test_low_confidence(outcome: str | None, confidence: float | None, found: bool) -> None:
    got = gaps.find(body(), SQUID_RULE, Assessed(outcome=outcome, confidence=confidence,
                                                  assessor="agent@1"))  # fmt: skip
    kinds = [g.kind for g in got]
    assert (Kind.CONFIDENCE in kinds) is found
    if found:
        gap = next(g for g in got if g.kind is Kind.CONFIDENCE)
        assert set(gap.closers) <= set(catalogue.INDEPENDENT)
        assert gap.closable


def test_a_calm_signal_and_a_threat_together_are_a_conflict() -> None:
    signals = [signal("ti.listed", 2), signal("proxy.hosts_to_destination", 40)]
    (gap,) = gaps.find(body(signals), SQUID_RULE)
    assert gap.kind is Kind.CONFLICT
    assert "points to a threat" in gap.what
    assert gap.closers == ("proxy.destination", "proxy.contact", "proxy.pair")


@pytest.mark.parametrize(
    "signals",
    [
        [signal("ti.listed", 2), signal("web.successes_after", 3)],  # two threats
        [signal("ti.listed", 0), signal("proxy.hosts_to_destination", 40)],  # two calms
        [signal("ti.listed", 2)],
    ],
)
def test_signals_that_agree_are_no_conflict(signals: list[dict[str, Any]]) -> None:
    assert gaps.find(body(signals), SQUID_RULE) == ()


def test_keys_that_disagree_are_a_conflict() -> None:
    a = Assessed(reasons=("keys disagree: benign_expected, true_positive",))
    (gap,) = gaps.find(body(), SQUID_RULE, a)
    assert gap.kind is Kind.CONFLICT


@pytest.mark.parametrize(
    ("assessed", "found"),
    [
        (Assessed("true_positive", 0.9, "agent@1"), True),
        (Assessed("true_positive", 0.8, "agent@1"), True),
        (Assessed("true_positive", 0.79, "agent@1"), False),
        (Assessed("true_positive", None, "person", by_person=True), True),
        (Assessed("benign_expected", 0.99, "agent@1"), False),
        (None, False),
    ],
)
def test_scope_after_a_verified_true_positive(assessed: Assessed | None, found: bool) -> None:
    got = gaps.find(body(), SQUID_RULE, assessed)
    assert (Kind.SCOPE in [g.kind for g in got]) is found
    if found:
        gap = next(g for g in got if g.kind is Kind.SCOPE)
        assert gap.closers == ("proxy.contact", "proxy.pair")


def test_scope_is_closed_once_the_reach_and_the_activity_are_known() -> None:
    signals = [signal("contact.hosts", 3), signal("pair.still_active", True)]
    assert gaps.find(body(signals), SQUID_RULE, Assessed("true_positive", 0.9)) == ()
    only_reach = [signal("contact.hosts", 3)]
    (gap,) = gaps.find(body(only_reach), SQUID_RULE, Assessed("true_positive", 0.9))
    assert gap.kind is Kind.SCOPE


def test_scope_waits_for_a_rule_that_reads_a_proxy_log() -> None:
    (gap,) = gaps.find(body(indices=NGINX), NGINX_RULE, Assessed("true_positive", 0.95))
    assert gap.kind is Kind.SCOPE
    assert gap.blocker == "the rule reads no log that could answer it"


# ----------------------------------------------------------------------------- the order


def everything() -> dict[str, Any]:
    return body(
        [
            signal("ti.listed", 2),
            signal("proxy.hosts_to_destination", 40),  # with the listing: a conflict
            unknown("web.successes_after", "timeout"),
            unknown("pair.beats", "timeout"),
        ],
        [step(1, "unknown"), step(2, "deferred", ["timeline"])],
    )


def test_the_kinds_come_in_the_plans_order() -> None:
    found = gaps.find(everything(), Profile("threshold", SQUID),
                      Assessed("true_positive", 0.9, "agent@1"))  # fmt: skip
    assert [g.kind for g in found] == [
        Kind.FLOOR, Kind.DEFERRED, Kind.UNKNOWN_STEP, Kind.SIGNAL, Kind.CONFLICT, Kind.SCOPE
    ]  # fmt: skip
    assert [g.rank for g in found] == [1, 2, 3, 4, 5, 6]


def test_low_confidence_comes_between_the_signals_and_the_conflicts() -> None:
    found = gaps.find(everything(), SQUID_RULE, Assessed("benign_expected", 0.3, "agent@1"))
    kinds = [g.kind for g in found]
    assert kinds.index(Kind.SIGNAL) < kinds.index(Kind.CONFIDENCE) < kinds.index(Kind.CONFLICT)


@given(st.randoms(use_true_random=False))
def test_the_ranking_ignores_the_order_a_body_lists_things_in(rng: random.Random) -> None:
    base = everything()
    mixed = {**base, "signals": list(base["signals"]), "report": dict(base["report"])}
    rng.shuffle(mixed["signals"])
    mixed["report"]["steps"] = list(base["report"]["steps"])
    rng.shuffle(mixed["report"]["steps"])
    a = Assessed("true_positive", 0.9, "agent@1")
    assert gaps.find(mixed, SQUID_RULE, a) == gaps.find(base, SQUID_RULE, a)


def test_the_same_dossier_always_gives_the_same_ranking() -> None:
    one = gaps.find(everything(), SQUID_RULE, Assessed("true_positive", 0.9))
    two = gaps.find(everything(), SQUID_RULE, Assessed("true_positive", 0.9))
    assert one == two


# ----------------------------------------------------------------------------- never by name


def test_a_rules_name_changes_nothing() -> None:
    a, b = everything(), everything()
    a["facts"] = {**a["facts"], "rule_name": "Squid beaconing"}
    b["facts"] = {**b["facts"], "rule_name": "Anything else", "rule_id": "other"}
    assert gaps.find(a, SQUID_RULE) == gaps.find(b, SQUID_RULE)


@pytest.mark.parametrize(
    ("indices", "sources"),
    [
        (("acme-logs-squid-*",), {"squid"}),
        (("acme-logs-dns-*", "acme-logs-nginx-*"), {"dns", "nginx"}),
        (("logs-squid.access-default",), {"squid"}),
        (("acme-logs-ddnsx-*", "squidward"), set()),  # a source is a whole word
        ((), set()),
    ],
)
def test_sources_come_from_the_rules_own_indices(
    indices: tuple[str, ...], sources: set[str]
) -> None:
    assert catalogue.sources_of(indices) == sources


def test_every_closer_a_gap_names_is_a_catalogue_template_its_rule_can_have_asked() -> None:
    named = [k.removeprefix("signal:") for c in catalogue.CHECKS.values()
             for k in c.closes if k.startswith("signal:")]  # fmt: skip
    every = [unknown(n, "timeout") for n in named]
    steps = [step(i, "deferred", [n]) for i, n in
             enumerate(("reputation", "prevalence", "timeline", "log_pivot"), start=1)]  # fmt: skip
    for indices in (SQUID, NGINX, DNS, SQUID + NGINX + DNS, ()):
        profile = Profile("threshold", indices)
        for gap in gaps.find(body(every, steps), profile, Assessed("true_positive", 0.9)):
            for template in gap.closers:
                spec = catalogue.CHECKS[template]
                assert catalogue.reads_needed(spec, profile.sources)
