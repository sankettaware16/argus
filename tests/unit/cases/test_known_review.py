"""AR4b after the adversarial review (D-181): a change that lasts, two devices, a lone device, and
one bad investigation that never fails a case's pass. Pure rules; the database side is
tests/integration/cases/test_known_review.py."""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from argus.assets.classify import IpClassifier
from argus.cases import known, knownrun
from argus.cases.known import Prior, Settled, Verdict, resurfaced, settle
from tests.unit.cases.test_known import (
    HOST,
    NOW,
    OTHER,
    SERVER,
    a_print,
    a_subject,
)

KNOWN_VERDICT = Verdict("known")
WAITING = Prior("changed", "changed since notice: a new flagged destination (185.1.1.1)", 3)


def _changed(*reasons: str) -> Verdict:
    return Verdict("changed", tuple(reasons))


# --------------------------------------------------------------------------- a change lasts


def test_a_change_stays_a_change_when_the_next_version_is_decided_known() -> None:
    """The blocker of the review: the investigation's next alert must not erase the change before
    a person has seen it."""
    kept = settle(WAITING, KNOWN_VERDICT, 4, reviewed=False)
    assert kept.outcome == "changed"
    assert kept.why == WAITING.why  # its reason is kept
    assert kept.changed_version == 3  # and the version it was decided at


def test_a_later_change_adds_its_reason_and_a_repeated_one_does_not() -> None:
    more = settle(
        WAITING, _changed("a kind of evidence the case did not have (success)"), 4, reviewed=False
    )
    assert more.why == (
        "changed since notice: a new flagged destination (185.1.1.1);"
        " a kind of evidence the case did not have (success)"
    )
    assert more.changed_version == 3
    same = settle(WAITING, _changed("a new flagged destination (185.1.1.1)"), 4, reviewed=False)
    assert same.why == WAITING.why


def test_a_reviewed_change_lets_a_later_version_be_known() -> None:
    assert settle(WAITING, KNOWN_VERDICT, 4, reviewed=True) == Settled("known", None, None)
    fresh = settle(
        WAITING, _changed("a university service is involved (10.1.1.10)"), 4, reviewed=True
    )
    assert (fresh.outcome, fresh.changed_version) == ("changed", 4)
    assert fresh.why == "changed since notice: a university service is involved (10.1.1.10)"


def test_nothing_before_it_is_known_and_a_first_change_starts_at_its_version() -> None:
    assert settle(None, KNOWN_VERDICT, 2, reviewed=False) == Settled("known", None, None)
    prior_known = Prior("known", None, None)
    assert settle(prior_known, KNOWN_VERDICT, 3, reviewed=False).outcome == "known"
    first = settle(prior_known, _changed("x"), 3, reviewed=False)
    assert (first.outcome, first.why, first.changed_version) == (
        "changed",
        "changed since notice: x",
        3,
    )


def test_the_kept_reason_fits_the_column() -> None:
    long = Prior("changed", known.CHANGED + "a" * 470, 2)
    out = settle(long, _changed("b" * 300), 3, reviewed=False)
    assert out.why is not None
    assert len(out.why) <= known.WHY_LIMIT
    assert out.why.startswith(known.CHANGED + "a" * 470)  # the first reason is the one kept


@settings()
@given(
    st.sampled_from(["known", "changed"]),
    st.booleans(),
    st.integers(1, 9),
    st.lists(st.sampled_from(["a", "b", "c"]), max_size=3),
)
def test_a_waiting_change_is_never_lost_to_a_decision(
    prior_outcome: str, reviewed: bool, version: int, reasons: list[str]
) -> None:
    """Over every prior, every next decision and every review state: a change that no person has
    reviewed is a change afterwards (at the same version, its reason kept); a change that was
    reviewed, or no change, is decided afresh."""
    prior = (
        Prior("changed", "changed since notice: first", 2)
        if prior_outcome == "changed"
        else Prior("known", None, None)
    )
    verdict = _changed(*reasons) if reasons else KNOWN_VERDICT
    out = settle(prior, verdict, version, reviewed=reviewed)
    if prior.outcome == "changed" and not reviewed:
        assert out.outcome == "changed"
        assert out.changed_version == 2
        assert out.why is not None
        assert out.why.startswith("changed since notice: first")
    elif verdict.outcome == "changed":
        assert out.outcome == "changed"
        assert out.changed_version == version
    else:
        assert out == Settled("known", None, None)
    assert (out.outcome == "changed") == (out.why is not None) == (out.changed_version is not None)


# --------------------------------------------------------------------------- two devices


def test_an_old_address_that_alerts_again_after_a_move_is_found() -> None:
    since = NOW - timedelta(hours=3)
    moves = {"10.1.1.5": since}
    later = a_subject(devices=frozenset({("ip", "10.1.1.5")}), last_event_at=NOW)
    assert resurfaced(later, moves) == ["10.1.1.5"]
    earlier = a_subject(devices=frozenset({("ip", "10.1.1.5")}), last_event_at=since)
    assert resurfaced(earlier, moves) == []  # no later than the new address's first alert
    assert resurfaced(a_subject(devices=frozenset({HOST}), last_event_at=NOW), moves) == []
    assert resurfaced(a_subject(devices=frozenset({("ip", "10.1.1.5")})), moves) == []
    assert resurfaced(later, {}) == []


def test_a_case_with_one_address_is_a_lone_device_and_a_second_address_ends_it() -> None:
    assert a_print().lone_address() == HOST
    with_names = a_print(devices=frozenset({HOST, ("host", "LAB-PC-7"), ("user", "asha")}))
    assert with_names.lone_address() == HOST
    assert a_print(devices=frozenset({HOST, OTHER})).lone_address() is None
    assert a_print(devices=frozenset({("host", "LAB-PC-7")})).lone_address() is None
    assert a_print(devices=frozenset()).lone_address() is None


# --------------------------------------------------------------------------- threat-intel values


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("185.9.9.9", ("ip", "185.9.9.9")),
        ("  185.9.9.9 ", ("ip", "185.9.9.9")),
        ("2001:DB8::1", ("ip", "2001:db8::1")),
        ("Evil.Example.NET.", ("domain", "evil.example.net")),
        ("http://payload.example.com/a.exe", ("domain", "payload.example.com")),
        ("https://203.0.113.7:8443/x?y=1", ("ip", "203.0.113.7")),
        ("http://[2001:db8::7]/x", ("ip", "2001:db8::7")),
        ("d41d8cd98f00b204e9800998ecf8427e", None),  # an MD5 is no destination
        ("a" * 64, None),  # nor a SHA-256
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", None),
        ("http://" + "a" * 600 + ".example.com/", None),
        ("ftp://files.example.com/x", None),  # not a web URL
        ("=cmd|' /C calc'!A0.example.com", None),
        ("", None),
        (None, None),
        (42, None),
    ],
)
def test_a_listed_value_is_typed_as_the_outside_cache_types_it(
    value: object, expected: tuple[str, str] | None
) -> None:
    assert knownrun.listed_key(value) == expected


# --------------------------------------------------------------------------- one bad subject


def _case(stopped: bool = False) -> knownrun.Tracked:
    return knownrun.Tracked(
        uuid.UUID(int=1), 7, "closed" if stopped else "open", 4, "high", NOW - timedelta(days=3),
        None, NOW if stopped else None, a_print(), True, NOW - timedelta(days=3),
    )  # fmt: skip


def _context() -> knownrun.Context:
    return knownrun.Context(IpClassifier(None, ()))


def test_one_bad_investigation_never_fails_the_others_of_the_case(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A problem in one subject is said and left; the rest of the case's pass goes on."""
    good = a_subject()
    bad = a_subject()
    more = a_subject(destinations=frozenset({SERVER, ("ip", "203.0.113.9")}))
    real = known.evaluate

    def flaky(fp: known.Print, subject: known.Subject, **more_: object) -> Verdict:
        if subject.investigation_id == bad.investigation_id:
            raise ZeroDivisionError("a subject that cannot be judged")
        return real(fp, subject, **more_)  # type: ignore[arg-type]

    monkeypatch.setattr(known, "evaluate", flaky)
    found = {s.investigation_id: s for s in (good, bad, more)}
    decisions, problems = knownrun.decide(_context(), _case(), a_print(), found, [])
    assert {d.subject.investigation_id for d in decisions} == {
        good.investigation_id, more.investigation_id,
    }  # fmt: skip
    assert problems == [f"investigation {bad.investigation_id}: ZeroDivisionError"]


def test_a_level_of_zero_never_fails_the_pass() -> None:
    """The review's crash: a case whose level at the notice was 0 divided by it."""
    fp = a_print(bytes=0)
    found = {s.investigation_id: s for s in (a_subject(bytes=5_000_000_000), a_subject(bytes=0))}
    decisions, problems = knownrun.decide(_context(), _case(), fp, found, [])
    assert problems == []
    assert [d.verdict.outcome for d in decisions] == ["known", "known"]
    assert not any(d.verdict.volume_judged for d in decisions)


def test_a_stopped_case_decides_a_change_for_the_device_and_nothing_for_another() -> None:
    mine = a_subject()
    other = a_subject(devices=frozenset({OTHER}))
    found = {s.investigation_id: s for s in (mine, other)}
    decisions, problems = knownrun.decide(_context(), _case(stopped=True), a_print(), found, [])
    assert problems == []
    assert [(d.subject.investigation_id, d.verdict.outcome) for d in decisions] == [
        (mine.investigation_id, "changed")
    ]


# --------------------------------------------------------------------------- a moved address


def test_a_case_with_two_devices_never_merges_a_third() -> None:
    """The review's major finding: another person's laptop was merged as a move of the second
    notified device."""
    fp = a_print(devices=frozenset({HOST, ("ip", "10.198.36.231")}))
    newcomer = a_subject(
        devices=frozenset({("ip", "10.198.99.4")}),
        first_event_at=NOW,
        last_event_at=NOW,
    )
    gone = [known.Gone(("ip", "10.198.36.231"), NOW - timedelta(hours=8), frozenset({SERVER}))]
    decisions, _ = knownrun.decide(
        _context(), _case(), fp, {newcomer.investigation_id: newcomer}, gone
    )
    assert decisions == []


def test_a_lone_device_follows_a_new_address_by_timing_or_by_its_host_name() -> None:
    newcomer = a_subject(
        devices=frozenset({("ip", "10.198.99.4")}),
        first_event_at=NOW,
        last_event_at=NOW,
    )
    gone = [known.Gone(HOST, NOW - timedelta(hours=8), frozenset({SERVER}))]
    (decision,), _ = knownrun.decide(
        _context(), _case(), a_print(), {newcomer.investigation_id: newcomer}, gone
    )
    assert decision.new_address == ("ip", "10.198.99.4")
    assert decision.moved_from == HOST[1]
    assert decision.verdict.outcome == "known"
    # the host name the case holds is a stronger key than any timing
    fp = a_print(devices=frozenset({HOST, ("host", "LAB-PC-7")}))
    named = a_subject(
        devices=frozenset({("host", "LAB-PC-7"), ("ip", "10.198.99.4")}),
        first_event_at=NOW,
        last_event_at=NOW,
    )
    (strong,), _ = knownrun.decide(_context(), _case(), fp, {named.investigation_id: named}, [])
    assert strong.moved_from == "host LAB-PC-7"


def test_a_user_shared_with_another_machine_is_no_move() -> None:
    fp = a_print(devices=frozenset({HOST, ("user", "asha")}))
    someone = a_subject(
        devices=frozenset({("user", "asha"), ("ip", "10.198.99.4")}),
        first_event_at=NOW,
        last_event_at=NOW,
    )
    gone = [known.Gone(HOST, NOW - timedelta(hours=8), frozenset({SERVER}))]
    decisions, _ = knownrun.decide(
        _context(), _case(), fp, {someone.investigation_id: someone}, gone
    )
    assert decisions == []


def test_another_host_or_a_second_address_in_the_investigation_is_another_device() -> None:
    gone = [known.Gone(HOST, NOW - timedelta(hours=8), frozenset({SERVER}))]
    for devices in (
        {("ip", "10.198.99.4"), ("host", "SOMEONE-ELSES-PC")},
        {("ip", "10.198.99.4"), ("ip", "10.198.99.5")},
        {("ip", "10.198.99.4"), HOST},  # the old address is in it: two devices, not a move
    ):
        s = a_subject(devices=frozenset(devices), first_event_at=NOW, last_event_at=NOW)
        out, _ = knownrun.decide(_context(), _case(), a_print(), {s.investigation_id: s}, gone)
        assert out == [], devices


def test_the_old_address_alerting_again_after_the_move_is_two_devices() -> None:
    fp = a_print(devices=frozenset({HOST, ("ip", "10.198.99.4")}))
    again = a_subject(devices=frozenset({HOST}), first_event_at=NOW, last_event_at=NOW)
    since = NOW - timedelta(hours=2)
    (decision,), _ = knownrun.decide(
        _context(), _case(), fp, {again.investigation_id: again}, [], {HOST[1]: since}
    )
    assert decision.verdict.outcome == "changed"
    assert decision.verdict.why == (
        f"changed since notice: two devices: {HOST[1]} active again after the move"
    )
    quiet, _ = knownrun.decide(
        _context(), _case(), fp, {again.investigation_id: again}, [], {HOST[1]: NOW}
    )
    assert quiet[0].verdict.outcome == "known"  # the move is after its last alert


def test_two_new_addresses_that_both_fit_the_quiet_device_are_never_guessed_between() -> None:
    gone = [known.Gone(HOST, NOW - timedelta(hours=8), frozenset({SERVER}))]
    news = [
        a_subject(
            devices=frozenset({("ip", f"10.198.99.{n}")}), first_event_at=NOW, last_event_at=NOW
        )
        for n in (4, 5)
    ]
    found = {s.investigation_id: s for s in news}
    decisions, _ = knownrun.decide(_context(), _case(), a_print(), found, gone)
    assert decisions == []
    (one,), _ = knownrun.decide(
        _context(), _case(), a_print(), {news[0].investigation_id: news[0]}, gone
    )
    assert one.by_timing
    assert one.new_address == ("ip", "10.198.99.4")


def test_a_needle_matches_a_value_in_a_canonical_grouping_key_and_escapes_like() -> None:
    assert knownrun._needle("10.198.36.230") == '%,"10.198.36.230"]%'
    assert knownrun._needle("LAB_PC_7") == '%,"LAB\\_PC\\_7"]%'  # _ is a wildcard in LIKE
    assert knownrun._needle("100%") == '%,"100\\%"]%'
    assert knownrun._needle('a"b') == '%,"a\\\\"b"]%'  # the JSON escape, then LIKE's
