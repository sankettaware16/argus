"""The engine's own evidence for its outbound incidents (D-323), pure: which incidents are checked
and in which order, once a material version, reused answers, the switch, the pass's caps; the
answers read into verdicts; what they change in the incident's checks, alternatives and certainty
word (never its priority); and the signals they give an alert group. Made-up values only (ACME's
site: private space and 131.21.124.0/22 are its own)."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from argus.context import beacon, dns
from argus.gateway.gateway import Result
from argus.risk import alternatives as alt
from argus.risk import observe as ob
from argus.risk import outbound, outbound_db, present
from argus.risk.config import Outbound, passes
from argus.risk.observe import ObjectRef
from argus.risk.outbound import Ask, Budget, Inputs, Pair, Spent, Stored, Target
from tests.unit.risk.conftest import CONFIG, NOW, context, group, meta

pytestmark = pytest.mark.unit
OB = CONFIG.outbound
ALL = outbound.TEMPLATES
DEVICE, C2, OTHER = "10.1.1.1", "45.138.12.9", "45.138.12.10"


def target(iid: int = 1, *, version: int = 1, band: str = "P1", hours: float = 2.0,
           pairs: tuple[Pair, ...] | None = None, devices: tuple[str, ...] = (DEVICE,),
           domains: bool = False, tunnel: bool = False, priority: int = 70) -> Target:  # fmt: skip
    at = NOW - timedelta(hours=hours)
    found = (Pair(DEVICE, C2, at, beat=True),) if pairs is None else pairs
    return Target(iid, version, band, priority, at, at, found, devices, domains, tunnel)


def kinds(asks: list[Ask]) -> list[tuple[int, str]]:
    return [(a.target.id, a.kind) for a in asks]


# --------------------------------------------------------------------------- planning


def test_a_beaconing_incident_gets_its_pair_and_its_destinations_contact() -> None:
    asks = outbound.plan(Inputs([target()]), NOW, OB, ALL)
    assert kinds(asks) == [(1, "pair"), (1, "contact")]
    pair, contact = asks
    params = pair.task.params if pair.task else None
    assert isinstance(params, beacon.PairParams)
    assert (params.host, params.destination) == (DEVICE, C2)
    assert params.end - params.start == timedelta(hours=OB.pair_hours)  # 1-minute buckets
    assert params.end == NOW - timedelta(hours=2) + outbound.AFTER
    contact_params = contact.task.params if contact.task else None
    assert isinstance(contact_params, beacon.ContactParams)
    assert contact_params.destination == C2
    assert contact_params.start.date() == (NOW - timedelta(hours=2)).date()  # one day's index


def test_the_top_band_first_then_the_newest_material_version() -> None:
    older = replace(target(1, band="P2"), material_at=NOW - timedelta(hours=9))
    newer = replace(target(2, band="P2"), material_at=NOW - timedelta(hours=1))
    top = replace(target(3, band="P1"), material_at=NOW - timedelta(days=2))
    low = target(4, band="P4")
    asks = outbound.plan(Inputs([older, low, newer, top]), NOW, OB, ALL)
    assert [i for i, k in kinds(asks) if k == "pair"] == [3, 2, 1]  # P4 is not checked


def test_once_a_material_version_and_again_after_a_new_one() -> None:
    t = target()
    done = {(1, 1, "pair", f"{DEVICE} {C2}"), (1, 1, "contact", C2)}
    assert outbound.plan(Inputs([t], done=done), NOW, OB, ALL) == []
    again = outbound.plan(Inputs([replace(t, version=2)], done=done), NOW, OB, ALL)
    assert kinds(again) == [(1, "pair"), (1, "contact")]


def test_one_question_once_a_pass_even_when_two_incidents_ask_it() -> None:
    a, b = target(1), target(2)
    asks = outbound.plan(Inputs([a, b]), NOW, OB, ALL)
    assert kinds(asks) == [(1, "pair"), (1, "contact"), (2, "pair"), (2, "contact")]
    assert len({(a.target.id, a.kind, a.subject) for a in asks}) == len(asks)


def test_a_recent_answer_about_the_same_subject_and_day_is_reused() -> None:
    day = (NOW - timedelta(hours=2) + outbound.AFTER).date()
    held = Stored(9, 1, "pair", f"{DEVICE} {C2}", DEVICE, C2, day, "regular",
                  {"period_s": 300}, NOW - timedelta(hours=1))  # fmt: skip
    asks = outbound.plan(Inputs([target()], reusable={("pair", held.subject, day): held}), NOW,
                         OB, ALL)  # fmt: skip
    pair = asks[0]
    assert (pair.kind, pair.task, pair.reuse) == ("pair", None, held)
    row = outbound.reused_row(pair)
    assert (row.verdict, row.took_ms, row.facts["reused_from"]) == ("regular", None, 9)


def test_only_the_switched_on_templates_are_asked() -> None:
    assert kinds(outbound.plan(Inputs([target()]), NOW, OB, frozenset({"proxy.contact"}))) == [
        (1, "contact")
    ]
    assert outbound.plan(Inputs([target()]), NOW, OB, frozenset()) == []


def test_the_most_telling_pair_beacon_timed_then_flagged_then_newest() -> None:
    at = NOW - timedelta(hours=1)
    plain = Pair(DEVICE, OTHER, at)
    flagged = Pair("10.1.1.2", OTHER, at - timedelta(hours=1), flagged=True)
    timed = Pair("10.1.1.3", C2, at - timedelta(hours=3), beat=True)
    assert outbound.ranked([plain, flagged, timed]) == [timed, flagged, plain]
    asks = outbound.plan(Inputs([target(pairs=(plain, flagged, timed))]), NOW, OB, ALL)
    assert [(a.kind, a.subject) for a in asks] == [("pair", f"10.1.1.3 {C2}"), ("contact", C2)]
    two = OB.model_copy(update={"pairs": 2})
    asks = outbound.plan(Inputs([target(pairs=(plain, flagged, timed))]), NOW, two, ALL)
    assert [a.subject for a in asks if a.kind == "contact"] == [C2, OTHER]


def test_the_lookups_only_when_there_is_no_address_to_time() -> None:
    assert outbound.plan(Inputs([target(pairs=())]), NOW, OB, ALL) == []
    asks = outbound.plan(Inputs([target(pairs=(), domains=True)]), NOW, OB, ALL)
    assert kinds(asks) == [(1, "dns")]
    params = asks[0].task.params if asks[0].task else None
    assert isinstance(params, dns.DomainsParams)
    assert params.ip == DEVICE
    assert kinds(outbound.plan(Inputs([target(pairs=(), tunnel=True)]), NOW, OB, ALL)) == [
        (1, "dns")
    ]
    assert outbound.plan(Inputs([target(pairs=(), devices=(), domains=True)]), NOW, OB, ALL) == []


def test_nothing_is_asked_about_a_window_the_logs_do_not_hold_yet() -> None:
    just_now = target(hours=0)  # the window ends before the ingest margin
    asks = outbound.plan(Inputs([just_now]), NOW, OB, ALL)
    pair = asks[0].task.params if asks and asks[0].task else None
    assert isinstance(pair, beacon.PairParams)
    assert pair.end <= NOW - timedelta(minutes=15)


@given(
    st.lists(
        st.tuples(st.integers(1, 6), st.integers(1, 3), st.sampled_from(["P1", "P2", "P3", "P4"]),
                  st.integers(0, 3), st.floats(0.5, 30)),
        max_size=8,
    ),
    st.sets(st.integers(1, 6)),
)  # fmt: skip
def test_planning_never_repeats_a_check_nor_asks_a_done_one(
    rows: list[tuple[int, int, str, int, float]], done_ids: set[int]
) -> None:
    targets = []
    for iid, version, band, n, hours in rows:
        at = NOW - timedelta(hours=hours)
        pairs = tuple(Pair(f"10.1.1.{i + 1}", f"45.138.12.{i + 1}", at, beat=i == 0)
                      for i in range(n))  # fmt: skip
        targets.append(Target(iid, version, band, 50, at, at, pairs, (DEVICE,), True))
    done = {(t.id, t.version, "pair", f"{p.device} {p.destination}") for t in targets
            if t.id in done_ids for p in t.pairs}  # fmt: skip
    asks = outbound.plan(Inputs(targets, done=done), NOW, OB, ALL)
    keys = [(a.target.id, a.target.version, a.kind, a.subject) for a in asks]
    assert len(keys) == len(set(keys))
    assert not set(keys) & done
    assert all(a.target.band in OB.bands for a in asks)
    assert sum(a.kind == "pair" for a in asks) <= len(targets) * OB.pairs


# --------------------------------------------------------------------------- the pass's caps


def ask(timeout: bool = True) -> Ask:
    asks = outbound.plan(Inputs([target()]), NOW, OB, ALL)
    return asks[0] if timeout else replace(asks[0], task=None)


def test_the_pass_holds_its_limits_and_the_lanes_day() -> None:
    a = ask()
    assert a.timeout_ms == 10_000
    lane = 600_000
    assert Budget(OB, lane, Spent()).refuses(a) is None
    assert Budget(OB, lane, Spent(), sent=OB.pass_requests).refuses(a) == "the pass's request limit"
    assert "requests" in str(Budget(OB, lane, Spent(requests=OB.day_requests)).refuses(a))
    assert "incidents' evidence" in str(
        Budget(OB, lane, Spent(ms=OB.day_ms - 9_999)).refuses(a)
    )  # the whole timeout must fit
    assert "checking lane" in str(Budget(OB, lane, Spent(lane_ms=lane - 5_000)).refuses(a))


def test_the_settings_fit_the_lane_on_the_measured_costs() -> None:
    """Sizing (D-323): a heavy proxy aggregation takes about 0.9 s at p95 and 3.9 s at most; 10-20
    incidents a day at two or three checks fit the day's requests, all of them at the slowest
    stay inside this share, and the share leaves the exposure checks most of the lane's day."""
    assert 20 * 2 <= OB.day_requests <= 100  # 100: the lane's heavy queries a day (default)
    assert OB.day_requests * 3_900 <= OB.day_ms
    assert OB.day_ms <= CONFIG.exposure.day_ms // 2
    assert OB.pass_requests * 1_000 <= 30_000  # a pass fits the lane's burst at p95
    assert set(OB.bands) == {"P1", "P2", "P3"}


# --------------------------------------------------------------------------- reading answers


def beats(start: datetime, end: datetime, every_min: int, *, skip: int = 0) -> dict[str, Any]:
    keys = []
    at = start
    n = 0
    while at < end:
        if not skip or n % skip:
            keys.append(int(at.timestamp() * 1000))
        at += timedelta(minutes=every_min)
        n += 1
    return {"buckets": [{"key": k, "doc_count": 2} for k in keys]}


def pair_answer(start: datetime, end: datetime, every: int, *, n: int | None = None,
                odd: bool = False) -> dict[str, Any]:  # fmt: skip
    found = beats(start, end, every)
    if odd:  # busy at no rhythm
        found = {
            "buckets": [
                {"key": int((start + timedelta(minutes=m)).timestamp() * 1000), "doc_count": 1}
                for m in (1, 2, 9, 10, 31, 33, 70, 140, 141, 300)
            ]
        }
    if n is not None:
        found = {"buckets": found["buckets"][:n]}
    count = sum(b["doc_count"] for b in found["buckets"])
    return {"aggregations": {"requests": {"value": count}, "bytes": {"value": 4096 * count},
                             "first": {"value": None}, "last": {"value": None},
                             "beats": found}}  # fmt: skip


def pair_params() -> beacon.PairParams:
    end = datetime(2026, 10, 20, 10, 30, tzinfo=UTC)
    return beacon.PairParams(host=DEVICE, destination=C2, start=end - timedelta(hours=6), end=end)


def test_a_pair_answer_says_regular_irregular_few_or_none() -> None:
    p = pair_params()
    verdict, facts = outbound.read_pair(p, pair_answer(p.start, p.end, 5))
    assert verdict == "regular"
    assert (facts["period_s"], facts["hours"], facts["day"]) == (300, "6", "2026-10-20")
    assert facts["requests"] == 144
    assert facts["bytes"] == 4096 * 144
    assert outbound.read_pair(p, pair_answer(p.start, p.end, 5, odd=True))[0] == "irregular"
    assert outbound.read_pair(p, pair_answer(p.start, p.end, 5, n=3))[0] == "few"
    assert outbound.read_pair(p, {"aggregations": {}})[0] == "none"


def contact_answer(devices: int, listed: tuple[str, ...] = (DEVICE,)) -> dict[str, Any]:
    return {
        "aggregations": {
            "requests": {"value": 10 * devices},
            "first": {"value": None},
            "last": {"value": None},
            "host_count": {"value": devices},
            "hosts": {"buckets": [{"key": h, "doc_count": 3} for h in listed]},
        }
    }


def test_a_contact_answer_says_how_common_the_address_is() -> None:
    start = datetime(2026, 10, 20, 1, 0, tzinfo=UTC)
    p = beacon.ContactParams(destination=C2, start=start, end=start + timedelta(hours=10))
    assert outbound.read_contact(p, contact_answer(1), DEVICE) == (
        "rare", {"devices": 1, "requests": 10, "first": None, "last": None, "day": "2026-10-20",
                 "window": ["2026-10-20T01:00:00Z", "2026-10-20T11:00:00Z"],
                 "with_device": True, "complete": False},
    )  # fmt: skip
    assert outbound.read_contact(p, contact_answer(300))[0] == "common"
    assert outbound.read_contact(p, contact_answer(11))[0] == "some"
    assert outbound.read_contact(p, contact_answer(0, ()))[0] == "none"


def test_a_lookup_answer_says_tunnel_plain_or_none() -> None:
    end = datetime(2026, 10, 20, 11, 0, tzinfo=UTC)
    p = dns.DomainsParams(ip=DEVICE, start=end - timedelta(hours=2), end=end)
    rare = [{"key": f"{'a1b2c3d4e5' * 3}{i}.tunnel.example.net", "doc_count": 1}
            for i in range(8)]  # fmt: skip
    tunnel = {"aggregations": {"queries": {"value": 9000}, "named": {"value": 9000},
                               "names": {"value": 8000}, "rare": {"buckets": rare}}}  # fmt: skip
    assert outbound.read_dns(p, tunnel)[0] == "tunnel"
    plain = {"aggregations": {"queries": {"value": 40}, "named": {"value": 40},
                              "names": {"value": 12}}}  # fmt: skip
    assert outbound.read_dns(p, plain)[0] == "plain"
    assert outbound.read_dns(p, {"aggregations": {}})[0] == "none"


def test_a_row_carries_its_request_and_its_cost() -> None:
    a = ask()
    p = a.task.params if a.task else None
    assert isinstance(p, beacon.PairParams)
    verdict, facts = outbound.read(a, Result(pair_answer(p.start, p.end, 5), 812, ()))
    row = outbound.row_of(a, verdict, facts, 812)
    assert (row.template, row.template_version, row.took_ms, row.verdict) == (
        "proxy.pair",
        1,
        812,
        "regular",
    )
    assert row.task_key is not None
    assert len(row.task_key) == 64
    gone = outbound.unknown_row(a, "the SIEM did not answer (TimedOutError)")
    assert (gone.verdict, gone.took_ms, gone.task_key) == ("unknown", None, row.task_key)


# --------------------------------------------------------------------------- what it changes


def measured(*found: tuple[str, str, dict[str, Any]]) -> tuple[alt.Measured, ...]:
    out = []
    for kind, verdict, facts in found:
        device = DEVICE if kind != "contact" else None
        destination = C2 if kind != "dns" else None
        out.append(alt.Measured(kind, verdict, device, destination,  # type: ignore[arg-type]
                                {"day": "2026-10-20", "hours": "6", **facts}))  # fmt: skip
    return tuple(out)


REGULAR = ("pair", "regular", {"requests": 72, "period_s": 300, "jitter_s": 60, "bytes": 9000})
IRREGULAR = ("pair", "irregular", {"requests": 400})
RARE = ("contact", "rare", {"devices": 1})
COMMON = ("contact", "common", {"devices": 300})


def ev(*found: tuple[str, str, dict[str, Any]], **more: Any) -> alt.Evidence:
    base: dict[str, Any] = {"object_kinds": frozenset({"device"}),
                            "kinds": frozenset({"beacon", "outside"}), "strong": True,
                            "reach": {f"ip:{C2}": 11}, "measured": measured(*found)}  # fmt: skip
    return alt.Evidence(**{**base, **more})


def states(found: list[alt.Alternative]) -> dict[str, tuple[str, str]]:
    return {a.name.split(" (")[0].split(",")[0]: (a.state, a.test) for a in found}


def test_a_regular_rare_beacon_rules_out_the_benign_readings() -> None:
    found = states(alt.alternatives(ev(REGULAR, RARE)))
    assert found["A common service"] == (
        "ruled_out", f"only 1 campus device contacted {C2} on 2026-10-20 (a common service has"
        " many)")  # fmt: skip
    assert found["Ordinary use"][0] == "ruled_out"
    assert "about every 5 min (± 60 s)" in found["Ordinary use"][1]
    checks = [(c.state, c.text) for c in alt.checks(ev(REGULAR, RARE))]
    assert ("checked", f"regular requests from {DEVICE} to {C2} about every 5 min (± 60 s):"
            " 72 requests, 8.8 KB in 6 h (proxy logs)") in checks  # fmt: skip
    assert ("ruled_out", f"no other campus device contacted {C2} on 2026-10-20 (proxy logs)") \
        in checks  # fmt: skip
    word = alt.certainty(confirmed=False, lanes={"decisive"}, strong=True,
                         found=alt.alternatives(ev(REGULAR, RARE)))  # fmt: skip
    assert word == "Likely"


def test_a_popular_service_or_no_rhythm_moves_the_certainty_word() -> None:
    for found in ((REGULAR, COMMON), (IRREGULAR, RARE)):
        alts = alt.alternatives(ev(*found))
        assert any(a.state == "fits" for a in alts)
        assert alt.certainty(confirmed=False, lanes={"decisive"}, strong=True,
                             found=alts) == "Unclear"  # fmt: skip
    common = states(alt.alternatives(ev(REGULAR, COMMON)))["A common service"]
    assert common == ("fits", f"300 campus devices contacted {C2} on 2026-10-20, like a common"
                      " service")  # fmt: skip
    plain = states(alt.alternatives(ev(IRREGULAR)))["Ordinary use"]
    assert plain == ("fits", f"no regular timing to {C2} in 400 requests over 6 h")
    checks = [(c.state, c.text) for c in alt.checks(ev(IRREGULAR))]
    assert ("ruled_out", f"no regular timing from {DEVICE} to {C2}: 400 requests in 6 h (proxy"
            " logs)") in checks  # fmt: skip


def test_too_common_to_ask_about_is_a_common_service_from_argus_own_alerts() -> None:
    store = ("contact", "common", {"devices": 40, "from": "argus"})
    found = states(alt.alternatives(ev(REGULAR, store)))["A common service"]
    assert found == ("fits", f"ARGUS's own alerts name {C2} with 40 campus devices, too many to"
                     " ask about")  # fmt: skip


def test_without_measured_evidence_nothing_new_fits() -> None:
    found = alt.alternatives(ev())
    assert states(found)["Ordinary use"] == (
        "unknown",
        "the device's timing to its destination is not measured yet",
    )
    assert all(a.state != "fits" for a in found if a.name == alt.ORDINARY_USE)
    unknown = ("pair", "unknown", {"reason": "the SIEM did not answer (TimedOutError)"})
    checks = [(c.state, c.text) for c in alt.checks(ev(unknown))]
    assert ("unknown", f"timing from {DEVICE} to {C2}: the SIEM did not answer"
            " (TimedOutError)") in checks  # fmt: skip


def test_lookups_show_as_a_check() -> None:
    tunnel = ("dns", "tunnel", {"lookups": 9000, "names": 8000})
    plain = ("dns", "plain", {"lookups": 40, "names": 12})
    assert [c.state for c in alt.checks(ev(tunnel)) if "DNS" in c.text] == ["checked"]
    assert [c.text for c in alt.checks(ev(plain)) if "DNS" in c.text] == [
        f"40 DNS lookups of 12 names by {DEVICE} around its last alert, none shaped like a tunnel"
    ]


def obj(*kinds: str, score: float = 60.0) -> present.Obj:
    return present.Obj(ObjectRef("device", f"ip:{DEVICE}"), 1, ("decisive",), score=score,
                       families=1, stages=1, strong=True,
                       kinds=frozenset(kinds or ("beacon", "outside")),
                       last_at=NOW - timedelta(hours=1))  # fmt: skip


@given(st.lists(st.sampled_from([REGULAR, IRREGULAR, RARE, COMMON,
                                 ("pair", "few", {"requests": 2}),
                                 ("contact", "unknown", {"reason": "x"})]), max_size=4),
       st.floats(5, 200))  # fmt: skip
def test_measured_evidence_never_changes_the_priority(
    found: list[tuple[str, str, dict[str, Any]]], score: float
) -> None:
    ctx = present.Context(CONFIG)
    args: dict[str, Any] = {"confirmed": False, "reach": {f"ip:{C2}": 3}, "signals": (),
                            "rule_names": {}, "lanes": ("decisive",),
                            "last_seen": NOW - timedelta(hours=1)}  # fmt: skip
    plain = present.value([obj(score=score)], NOW, ctx, **args)
    checked = present.value([obj(score=score)], NOW, ctx, **args, measured=measured(*found))
    assert (checked.priority, checked.band, checked.why) == (plain.priority, plain.band, plain.why)
    # what speaks against it shows in the certainty word (a rare count or a rhythm wins a tie)
    if (COMMON in found and RARE not in found) or (IRREGULAR in found and REGULAR not in found):
        assert checked.evidence_certainty in ("Unclear", "Likely harmless")


# --------------------------------------------------------------------------- the engine's signals


def answer(kind: str, verdict: str, facts: dict[str, Any], *, day: date | None = None,
           device: str | None = DEVICE, destination: str | None = C2) -> Stored:  # fmt: skip
    subject = outbound.subject(kind, device, destination)  # type: ignore[arg-type]
    return Stored(1, 1, kind, subject, device, destination,  # type: ignore[arg-type]
                  day or (NOW - timedelta(hours=1)).date(), verdict, facts, NOW)  # fmt: skip


def test_the_answers_become_the_alert_groups_signals() -> None:
    g = group(fields={"destination.ip": [C2]})
    stored = [answer("pair", "regular", {"period_s": 300}),
              answer("contact", "rare", {"devices": 1}, device=None),
              answer("dns", "tunnel", {}, destination=None)]  # fmt: skip
    assert outbound_db.signals_of(g, stored) == {
        "pair.period_s": 300,
        "contact.hosts": 1,
        "dns.tunnel_suspected": True,
    }
    # its own dossier's values stay; another day, another address or an unknown answer give none
    assert "contact.hosts" not in outbound_db.signals_of(
        replace(g, signals={"contact.hosts": 4}), stored)  # fmt: skip
    far = [answer("pair", "regular", {"period_s": 300}, day=NOW.date() - timedelta(days=3))]
    assert outbound_db.signals_of(g, far) == {}
    other = group(actor="10.1.1.7", fields={"destination.ip": [C2]})
    assert "pair.period_s" not in outbound_db.signals_of(other, stored)
    assert outbound_db.signals_of(g, [answer("pair", "unknown", {"period_s": 300})]) == {}
    assert outbound_db.signals_of(g, [answer("pair", "irregular", {})]) == {}


def test_a_measured_rhythm_is_a_beacon_and_one_device_a_rare_destination() -> None:
    kinds_ = {k.kind: k for k in CONFIG.evidence}
    assert passes(kinds_["beacon"].signals["pair.period_s"], 300)
    assert passes(kinds_["rare_dest"].signals["contact.hosts"], 1)
    assert not passes(kinds_["rare_dest"].signals["contact.hosts"], 2)
    g = group(fields={"destination.ip": [C2]}, signals={"pair.period_s": 300, "contact.hosts": 1})
    seen = ob.observe(g, meta(), context())
    assert {o.source_key for o in seen.observations if o.source_kind == "evidence"} == {
        "ev:beacon",
        "ev:rare_dest",
    }


def test_the_settings_are_checked() -> None:
    with pytest.raises(ValidationError, match="pairs"):
        Outbound.model_validate({"pairs": 0})
    with pytest.raises(ValidationError, match="bands"):
        Outbound.model_validate({"bands": ["P5"]})
    with pytest.raises(ValidationError, match="surprise"):
        Outbound.model_validate({"surprise": 1})


# --------------------------------------------------------------------------- review findings


def contact_params(hours: float) -> beacon.ContactParams:
    start = datetime(2026, 10, 20, 1, 0, tzinfo=UTC)
    return beacon.ContactParams(destination=C2, start=start, end=start + timedelta(hours=hours))


def test_a_contact_count_says_whether_its_day_was_over() -> None:
    """A count of a day still going on is a count so far: the device's own requests may be the
    only ones yet. Only a whole day's count is complete."""
    assert outbound.read_contact(contact_params(10), contact_answer(1))[1]["complete"] is False
    whole = beacon.ContactParams(destination=C2, start=datetime(2026, 10, 20, 1, 0, tzinfo=UTC),
                                 end=datetime(2026, 10, 20, 22, 59, tzinfo=UTC))  # fmt: skip
    assert outbound.read_contact(whole, contact_answer(1))[1]["complete"] is True
    made = outbound.plan(Inputs([target(hours=30)]), NOW, OB, ALL)  # yesterday's alert
    contact = next(a for a in made if a.kind == "contact")
    assert contact.task is not None
    assert isinstance(contact.task.params, beacon.ContactParams)
    assert outbound.read_contact(contact.task.params, contact_answer(1))[1]["complete"] is True


PARTIAL_RARE = ("contact", "rare", {"devices": 1, "complete": False})


def test_a_count_so_far_never_rules_out_a_common_service_nor_marks_a_rare_destination() -> None:
    found = states(alt.alternatives(ev(REGULAR, PARTIAL_RARE)))
    assert found["A common service"][0] == "unknown"  # ARGUS's own reach (11) judges instead
    alone = states(alt.alternatives(ev(REGULAR, PARTIAL_RARE, reach={})))["A common service"]
    assert alone == ("unknown", f"1 campus device contacted {C2} so far on 2026-10-20: asked"
                     " again once the day is over")  # fmt: skip
    rare_reach = states(alt.alternatives(ev(REGULAR, PARTIAL_RARE, reach={f"ip:{C2}": 1})))
    assert rare_reach["A common service"][0] == "ruled_out"  # as before any count
    checks = [(c.state, c.text) for c in alt.checks(ev(REGULAR, PARTIAL_RARE))]
    assert not any(s == "ruled_out" and C2 in t and "contacted" in t for s, t in checks)
    g = group(fields={"destination.ip": [C2]})
    partial = answer("contact", "rare", {"devices": 1, "complete": False}, device=None)
    assert "contact.hosts" not in outbound_db.signals_of(g, [partial])
    # many devices already by midday is a common service whether or not the day is over
    many = ("contact", "common", {"devices": 300, "complete": False})
    assert states(alt.alternatives(ev(REGULAR, many)))["A common service"][0] == "fits"


def test_no_request_through_the_proxy_does_not_rule_out_a_common_service() -> None:
    """A remote-admin port or other traffic the proxy never sees: zero devices in its logs says
    nothing about how common the address is."""
    none = ("contact", "none", {"devices": 0, "complete": True})
    assert states(alt.alternatives(ev(REGULAR, none)))["A common service"][0] == "unknown"
    alone = states(alt.alternatives(ev(REGULAR, none, reach={})))["A common service"]
    assert alone == ("unknown", f"no campus device reached {C2} through the proxy on 2026-10-20")


def test_ordinary_use_is_an_alternative_only_to_a_claimed_beacon() -> None:
    """An incident about contact with a flagged server never claimed a rhythm: requests at no
    rhythm do not explain it away (its certainty word stays)."""
    contact_only = ev(IRREGULAR, kinds=frozenset({"outside"}))
    assert alt.ORDINARY_USE not in {a.name for a in alt.alternatives(contact_only)}
    assert states(alt.alternatives(ev(IRREGULAR)))["Ordinary use"][0] == "fits"


def test_no_request_in_the_proxy_logs_is_not_called_not_measured_yet() -> None:
    none = ("pair", "none", {"requests": 0})
    said = states(alt.alternatives(ev(none)))["Ordinary use"]
    assert said[0] == "unknown"
    assert "not measured yet" not in said[1]
    assert "proxy logs" in said[1]


def test_a_campus_destination_is_not_timed_through_the_proxy() -> None:
    inside = Pair(DEVICE, "10.9.9.9", NOW - timedelta(hours=1), flagged=True)
    t = target(pairs=(inside, Pair(DEVICE, C2, NOW - timedelta(hours=2))))
    kept = outbound.outside_only([t], lambda v: v.startswith("10."))
    asks = outbound.plan(Inputs(kept), NOW, OB, ALL)
    assert {a.destination for a in asks} == {C2}
