"""The known infection of a notified case (AR4b, D-169, D-176): what an investigation of its device
is (known, changed, or not the case's), when ARGUS reminds, when it proposes to close, and when a
new address is probably the same device. Pure rules; the database side is
tests/integration/cases/test_known_pass.py."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from argus.cases import known
from argus.cases.known import (
    Gone,
    Print,
    Rules,
    Subject,
    evaluate,
    join,
    moved,
    partition,
    print_of,
    reminders,
    stopped,
)

NOW = datetime(2026, 10, 29, 6, 0, tzinfo=UTC)
RULES = Rules()
HOST = ("ip", "10.201.7.11")
OTHER = ("ip", "10.55.1.1")
SERVER = ("ip", "77.221.155.150")
SERVER_2 = ("ip", "185.1.1.1")
DOMAIN = ("domain", "fast-dns-host.com")
BEACON = "regular traffic, like a beacon"
OUTSIDE = "flagged by outside threat intel"
SUCCESS = "successful answers after the alert"


def a_print(**kw: object) -> Print:
    base: dict[str, object] = {
        "devices": frozenset({HOST}),
        "destinations": frozenset({SERVER, DOMAIN}),
        "families": frozenset({"fast-dns-host.com"}),
        "flags": frozenset({BEACON, OUTSIDE}),
        "services": frozenset(),
        "bytes": 1_000_000,
    }
    base.update(kw)
    return Print(**base)  # type: ignore[arg-type]


_N = 0


def a_subject(**kw: object) -> Subject:
    global _N
    _N += 1
    base: dict[str, object] = {
        "investigation_id": uuid.UUID(int=_N),
        "version": 1,
        "devices": frozenset({HOST}),
        "destinations": frozenset({SERVER}),
        "flagged": frozenset({SERVER}),
        "flags": (BEACON, OUTSIDE),
        "services": frozenset(),
        "bytes": 900_000,
    }
    base.update(kw)
    return Subject(**base)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- the fingerprint


def test_the_fingerprint_is_the_cases_rows_and_the_keys_the_notice_added() -> None:
    fp = print_of(
        [HOST, ("host", "LAB-PC-7"), ("domain", "ignored")],
        [SERVER, DOMAIN, ("url", "http://x")],
        [
            (known.SEED, ""),
            (known.FLAG, BEACON),
            (known.DESTINATION, "ip:185.1.1.1"),
            (known.FAMILY, "other.net"),
            (known.SERVICE, "ip:10.9.9.9"),
            (known.BYTES, "500"),
            (known.BYTES, "2000"),
            (known.BYTES, "not a number"),
        ],
    )
    assert fp.devices == {HOST, ("host", "LAB-PC-7")}  # a domain is no device
    assert fp.destinations == {SERVER, DOMAIN, SERVER_2}
    assert fp.families == {"fast-dns-host.com", "other.net"}
    assert fp.flags == {BEACON}
    assert fp.services == {("ip", "10.9.9.9")}
    assert fp.bytes == 2000


def test_a_name_under_a_family_the_case_holds_is_known() -> None:
    fp = a_print()
    assert fp.knows(("domain", "www.google.com.x9f3.fast-dns-host.com"))
    assert not fp.knows(("domain", "fast-dns-host.org"))
    assert not fp.knows(("domain", "localhost"))  # no registered parent
    assert fp.knows(SERVER)
    assert not fp.knows(SERVER_2)


def test_keys_round_trip() -> None:
    for key in (SERVER, DOMAIN, ("ip", "2001:db8::1")):
        assert known.split(known.join(key)) == key
    assert known.split("nonsense") is None
    assert known.split("ip:") is None


# --------------------------------------------------------------------------- evaluating


def test_a_new_day_of_the_same_infection_is_known() -> None:
    verdict = evaluate(a_print(), a_subject())
    assert verdict.outcome == "known"
    assert verdict.why is None
    assert verdict.changes == ()


def test_the_amadey_acceptance_a_new_flagged_server_is_a_change() -> None:
    verdict = evaluate(
        a_print(),
        a_subject(
            destinations=frozenset({SERVER, SERVER_2}), flagged=frozenset({SERVER, SERVER_2})
        ),
    )
    assert verdict.outcome == "changed"
    assert verdict.why == "changed since notice: a new flagged destination (185.1.1.1)"
    assert verdict.adds.destinations == {SERVER_2}


def test_a_name_in_a_new_flagged_family_is_a_change_and_one_in_the_known_family_is_not() -> None:
    same = ("domain", "a.b.fast-dns-host.com")
    assert evaluate(a_print(), a_subject(destinations=frozenset({same}),
                                         flagged=frozenset({same}))).outcome == "known"  # fmt: skip
    new = ("domain", "evil.example.net")
    verdict = evaluate(a_print(), a_subject(flagged=frozenset({SERVER, new})))
    assert verdict.outcome == "changed"
    assert verdict.adds.families == {"example.net"}


def test_a_new_kind_of_evidence_is_a_change() -> None:
    verdict = evaluate(a_print(), a_subject(flags=(BEACON, SUCCESS)))
    assert verdict.outcome == "changed"
    assert "a kind of evidence the case did not have (successful answers after the alert)" in (
        verdict.why or ""
    )
    assert verdict.adds.flags == {SUCCESS}


def test_a_university_service_as_a_target_is_a_change() -> None:
    sso = ("ip", "10.1.1.10")
    verdict = evaluate(a_print(), a_subject(services=frozenset({sso})))
    assert verdict.outcome == "changed"
    assert "a university service is involved (10.1.1.10)" in (verdict.why or "")
    assert evaluate(a_print(services=frozenset({sso})), a_subject(services=frozenset({sso}))
                    ).outcome == "known"  # fmt: skip


def test_much_more_data_is_a_change_only_when_the_evidence_carries_bytes() -> None:
    big = a_subject(bytes=25_000_000)
    verdict = evaluate(a_print(), big)
    assert verdict.outcome == "changed"
    assert "much more traffic than at the notice (about 25 times)" in (verdict.why or "")
    assert verdict.adds.bytes == 25_000_000
    for fp, subject in (
        (a_print(), a_subject(bytes=None)),  # the investigation has no byte count
        (a_print(bytes=None), big),  # the case has none
    ):
        result = evaluate(fp, subject)
        assert result.outcome == "known"
        assert not result.volume_judged  # the pass says that the volume was not judged
    assert evaluate(a_print(), a_subject(bytes=9_999_999)).outcome == "known"  # below 10 times


def test_a_known_verdict_never_moves_the_level_and_a_change_is_known_the_second_time() -> None:
    """The volume is judged against the level at the notice (D-181): small steps cannot creep past
    it. Only a spoken change moves the level, so the next one has to beat that."""
    fp = a_print()
    grown = evaluate(fp, a_subject(bytes=5_000_000))
    assert grown.outcome == "known"
    assert grown.adds.bytes is None  # known growth is not remembered
    assert evaluate(fp, a_subject(bytes=9_900_000)).outcome == "known"
    change = evaluate(fp, a_subject(flags=(BEACON, SUCCESS)))
    again = evaluate(print_of(fp.devices, fp.destinations, [(k, v) for k, v in
                                                            [(known.FLAG, f) for f in fp.flags]
                                                            + change.adds.rows()]),
                     a_subject(flags=(BEACON, SUCCESS)))  # fmt: skip
    assert again.outcome == "known"
    jump = evaluate(fp, a_subject(bytes=30_000_000))
    assert jump.outcome == "changed"
    assert jump.adds.bytes == 30_000_000  # a change moves the level...
    fp_after = print_of(
        fp.devices, fp.destinations,
        [(known.BYTES, "1000000"), *[(known.FLAG, f) for f in fp.flags], *jump.adds.rows()],
    )  # fmt: skip
    assert fp_after.bytes == 30_000_000
    assert evaluate(fp_after, a_subject(bytes=40_000_000)).outcome == "known"  # ...once
    assert evaluate(fp_after, a_subject(bytes=300_000_001)).outcome == "changed"


@pytest.mark.parametrize("level", [0, None])
def test_a_level_of_zero_or_none_is_not_judged_and_never_divides(level: int | None) -> None:
    fp = a_print(bytes=level)
    result = evaluate(fp, a_subject(bytes=5_000_000_000))
    assert result.outcome == "known"
    assert not result.volume_judged
    assert print_of(fp.devices, fp.destinations, [(known.BYTES, "0")]).bytes is None


def test_another_device_is_not_this_infections() -> None:
    assert evaluate(a_print(), a_subject(devices=frozenset({OTHER}))).outcome is None


def test_an_investigation_that_lists_another_persons_device_too_is_not_absorbed() -> None:
    """One notified device does not take in other people's devices (D-181): a campus address the
    case does not hold is another laptop or a lateral move, and the normal pipeline decides."""
    both = a_subject(devices=frozenset({HOST, OTHER}))
    assert evaluate(a_print(), both).outcome is None
    assert evaluate(a_print(devices=frozenset({HOST, OTHER})), both).outcome == "known"
    many = a_subject(devices=frozenset({HOST, *[("ip", f"10.55.7.{n}") for n in range(1, 40)]}))
    assert evaluate(a_print(), many).outcome is None
    assert not known.own_device(a_print(), both)


def test_a_user_shared_with_another_machine_does_not_make_the_device() -> None:
    """The device is told by an address or a host name; a user alone may sit on another machine."""
    fp = a_print(devices=frozenset({HOST, ("user", "asha")}))
    assert evaluate(fp, a_subject(devices=frozenset({("user", "asha")}))).outcome is None
    assert evaluate(fp, a_subject(devices=frozenset({("user", "asha"), OTHER}))).outcome is None
    assert evaluate(fp, a_subject(devices=frozenset({HOST, ("user", "asha")}))).outcome == "known"


def test_a_university_service_is_judged_by_its_own_rule_not_as_another_device() -> None:
    sso = ("ip", "10.1.1.10")
    with_service = a_subject(devices=frozenset({HOST, sso}), services=frozenset({sso}))
    changed = evaluate(a_print(), with_service)
    assert changed.outcome == "changed"
    assert "a university service is involved" in (changed.why or "")
    held = evaluate(a_print(services=frozenset({sso})), with_service)
    assert held.outcome == "known"


def test_new_destinations_that_nobody_flags_are_noted_not_raised() -> None:
    """One held destination no longer absorbs new ones silently (D-181): the new ones are added to
    the case and counted, and the investigation stays known."""
    fresh = ("domain", "cdn.fresh-names.net")
    other = ("ip", "203.0.113.9")
    verdict = evaluate(a_print(), a_subject(destinations=frozenset({SERVER, fresh, other}),
                                            flagged=frozenset()))  # fmt: skip
    assert verdict.outcome == "known"
    assert verdict.adds.seen == {fresh, other}
    assert {row for row in verdict.adds.rows() if row[0] == known.NEW_DESTINATION} == {
        (known.NEW_DESTINATION, "domain:cdn.fresh-names.net"),
        (known.NEW_DESTINATION, "ip:203.0.113.9"),
    }  # fmt: skip
    # a name under a family the case holds, and one the case noted before, are not new
    held = ("domain", "x.fast-dns-host.com")
    fp = print_of(
        [HOST], [SERVER, DOMAIN],
        [(known.NEW_DESTINATION, "ip:203.0.113.9"), (known.FLAG, BEACON), (known.FLAG, OUTSIDE),
         (known.BYTES, "1000000")],
    )  # fmt: skip
    again = evaluate(fp, a_subject(destinations=frozenset({SERVER, held, other, fresh}),
                                   flagged=frozenset()))  # fmt: skip
    assert again.adds.seen == {fresh}
    # reaching only a noted-new destination is no reason to be known
    assert evaluate(fp, a_subject(destinations=frozenset({other}), flagged=frozenset())
                    ).outcome is None  # fmt: skip


def test_a_destination_noted_as_new_and_flagged_later_is_a_change() -> None:
    """The late-evidence path (D-181): the look-ups may flag a destination after it was absorbed
    as new; it is not held, so the flag is a change."""
    late = ("ip", "203.0.113.9")
    fp = print_of(
        [HOST], [SERVER, DOMAIN],
        [(known.NEW_DESTINATION, join(late)), (known.FLAG, BEACON), (known.FLAG, OUTSIDE)],
    )  # fmt: skip
    assert fp.seen == {late}
    assert not fp.knows(late)
    verdict = evaluate(fp, a_subject(destinations=frozenset({SERVER, late}),
                                     flagged=frozenset({SERVER, late})))  # fmt: skip
    assert verdict.outcome == "changed"
    assert verdict.adds.destinations == {late}
    assert "a new flagged destination (203.0.113.9)" in (verdict.why or "")


def test_the_new_destinations_one_investigation_adds_are_capped() -> None:
    many = frozenset(("ip", f"198.51.{n // 250}.{n % 250}") for n in range(400))
    verdict = evaluate(a_print(), a_subject(destinations=many | {SERVER}, flagged=frozenset()))
    assert verdict.outcome == "known"
    assert len(verdict.adds.seen) == known.NEW_PER_SUBJECT


def test_the_device_alone_is_not_the_infection_unless_something_changed() -> None:
    quiet = a_subject(destinations=frozenset({("domain", "docs.example.org")}),
                      flagged=frozenset(), flags=())  # fmt: skip
    assert evaluate(a_print(), quiet).outcome is None
    flagged = a_subject(destinations=frozenset({SERVER_2}), flagged=frozenset({SERVER_2}))
    assert evaluate(a_print(), flagged).outcome == "changed"


def test_a_host_name_names_the_device_too() -> None:
    fp = a_print(devices=frozenset({("host", "LAB-PC-7")}))
    assert evaluate(fp, a_subject(devices=frozenset({("host", "LAB-PC-7")}))).outcome == "known"
    assert evaluate(fp, a_subject(devices=frozenset({("host", "LAB-PC-7"), OTHER}))).outcome is None


def test_a_long_reason_is_cut_to_the_column() -> None:
    many = frozenset(("ip", f"185.1.{n // 250}.{n % 250}") for n in range(2000))
    verdict = evaluate(a_print(), a_subject(destinations=many, flagged=many))
    assert verdict.why is not None
    assert len(verdict.why) <= known.WHY_LIMIT
    assert "and 1997 more" in verdict.why


# --------------------------------------------------------------------------- properties

_DEVICES = st.sampled_from([HOST, OTHER, ("host", "LAB-PC-7")])
_DESTINATIONS = st.sampled_from(
    [SERVER, SERVER_2, DOMAIN, ("domain", "a.fast-dns-host.com"), ("domain", "x.example.net"),
     ("ip", "8.8.8.8")]
)  # fmt: skip
_FLAGS = st.sampled_from([BEACON, OUTSIDE, SUCCESS, "on a threat list"])
_SERVICES = st.sampled_from([("ip", "10.1.1.10"), ("ip", "10.1.1.11")])
_PRINTS = st.builds(
    Print,
    st.frozensets(_DEVICES, max_size=3),
    st.frozensets(_DESTINATIONS, max_size=4),
    st.frozensets(st.sampled_from(["fast-dns-host.com", "example.net"]), max_size=2),
    st.frozensets(_FLAGS, max_size=3),
    st.frozensets(_SERVICES, max_size=2),
    st.none() | st.integers(1, 10**9),
)
_SUBJECTS = st.builds(
    Subject,
    st.integers(1, 10**6).map(lambda n: uuid.UUID(int=n)),
    st.just(1),
    st.frozensets(_DEVICES, max_size=3),
    st.frozensets(_DESTINATIONS, max_size=4),
    st.frozensets(_DESTINATIONS, max_size=3),
    st.lists(_FLAGS, max_size=3).map(tuple),
    st.frozensets(_SERVICES, max_size=2),
    st.none() | st.integers(0, 10**10),
)


@settings()  # the profile sets the count: 100 dev, 1,000 ci, 10,000 gate
@given(_PRINTS, st.lists(_SUBJECTS, max_size=12))
def test_absorbing_and_changing_are_a_partition(fp: Print, subjects: list[Subject]) -> None:
    """Every investigation is exactly one of known, changed, or not the case's; their counts add up
    to the total, and the buckets do not depend on the order."""
    parts = partition(fp, subjects)
    assert sum(len(v) for v in parts.values()) == len(subjects)
    seen = [id(s) for v in parts.values() for s in v]
    assert len(seen) == len(set(seen))
    reversed_parts = partition(fp, list(reversed(subjects)))
    assert {k: sorted(s.investigation_id for s in v) for k, v in parts.items()} == {
        k: sorted(s.investigation_id for s in v) for k, v in reversed_parts.items()
    }


@settings()
@given(_PRINTS, _SUBJECTS)
def test_a_known_match_never_brings_anything_the_case_does_not_hold(
    fp: Print, subject: Subject
) -> None:
    """No match of a notified case is raised without a change: a known one has the device, only
    flagged destinations the case holds, only kinds of evidence it carried, no new university
    service, and no jump in data."""
    verdict = evaluate(fp, subject)
    if verdict.outcome == "known":
        assert subject.devices & fp.devices
        assert subject.devices <= fp.devices | subject.services  # no other person's device
        assert any(k[0] in known.IDENTITY_KINDS for k in subject.devices & fp.devices)
        assert verdict.adds.bytes is None  # known growth never moves the level
        assert all(fp.knows(k) for k in subject.flagged)
        assert set(subject.flags) <= fp.flags
        assert subject.services <= fp.services
        assert any(fp.knows(k) for k in subject.destinations)
        assert verdict.why is None
        assert verdict.changes == ()
        if subject.bytes is not None and fp.bytes is not None:
            assert subject.bytes < RULES.volume_factor * fp.bytes or subject.bytes <= fp.bytes
    elif verdict.outcome == "changed":
        assert subject.devices & fp.devices
        assert verdict.why is not None
        assert verdict.why.startswith(known.CHANGED)
        assert verdict.changes
    else:
        assert verdict.why is None


@settings()
@given(_PRINTS, _SUBJECTS)
def test_a_change_speaks_once(fp: Print, subject: Subject) -> None:
    """After a change is added to the fingerprint the same investigation is known (or not the
    case's), never a change again; and a fingerprint that holds more never turns a known
    investigation into a change."""
    verdict = evaluate(fp, subject)
    grown = print_of(
        fp.devices,
        fp.destinations,
        [(known.FLAG, f) for f in fp.flags]
        + [(known.FAMILY, f) for f in fp.families]
        + [(known.SERVICE, known.join(k)) for k in fp.services]
        + ([(known.BYTES, str(fp.bytes))] if fp.bytes else [])
        + verdict.adds.rows(),
    )
    after = evaluate(grown, subject)
    if verdict.outcome == "changed":
        assert after.outcome in ("known", None)
    if verdict.outcome == "known":
        assert after.outcome == "known"


# --------------------------------------------------------------------------- reminders and ending


def days(n: float) -> timedelta:
    return timedelta(days=n)


def test_a_notice_still_active_after_a_week_suggests_notifying_again() -> None:
    told = NOW - days(7)
    seen = NOW - days(1)
    assert reminders(NOW, told, 1, False, seen, RULES) == ["notify_again"]
    assert reminders(NOW, NOW - days(6.9), 1, False, seen, RULES) == []
    assert reminders(NOW, told, 2, False, seen, RULES) == []  # told twice already
    assert reminders(NOW, told, 1, False, None, RULES) == []  # never active
    assert reminders(NOW, told, 1, False, NOW - days(4), RULES) == []  # quiet for 4 days


def test_after_three_weeks_it_suggests_network_side_action_unless_a_block_is_recorded() -> None:
    told = NOW - days(21)
    seen = NOW - timedelta(hours=5)
    assert reminders(NOW, told, 1, False, seen, RULES) == ["notify_again", "network_action"]
    assert reminders(NOW, told, 2, False, seen, RULES) == ["network_action"]
    assert reminders(NOW, told, 2, True, seen, RULES) == []
    assert reminders(NOW, NOW - days(20.9), 2, False, seen, RULES) == []


def test_the_days_are_settings() -> None:
    quick = Rules(renotify_days=2, network_days=4, active_days=1)
    assert reminders(NOW, NOW - days(2), 1, False, NOW - days(0.5), quick) == ["notify_again"]
    assert reminders(NOW, NOW - days(4), 1, False, NOW - days(0.5), quick) == [
        "notify_again", "network_action",
    ]  # fmt: skip


def test_fourteen_quiet_days_after_the_notice_propose_closing() -> None:
    told = NOW - days(14)
    assert stopped(NOW, told, None, RULES)
    assert not stopped(NOW, NOW - days(13.9), None, RULES)
    assert not stopped(NOW, told, NOW - days(2), RULES)  # active two days ago
    assert stopped(NOW, NOW - days(30), NOW - days(14), RULES)
    assert not stopped(NOW, NOW - days(30), NOW - days(13), RULES)
    assert stopped(
        NOW, told, told - days(40), RULES
    )  # activity before the notice counts for nothing
    assert stopped(NOW, NOW - days(20), NOW - days(30), Rules(quiet_days=14))


@settings()
@given(st.floats(0, 60), st.floats(0, 60) | st.none(), st.integers(1, 3), st.booleans())
def test_reminders_and_closing_never_overlap(
    age: float, quiet: float | None, notices: int, blocked: bool
) -> None:
    """A case is never both suggested a reminder (it is still active) and proposed for closing
    (14 quiet days) at the same moment, with the default days."""
    told = NOW - days(age)
    last = None if quiet is None else NOW - days(quiet)
    if stopped(NOW, told, last, RULES):
        assert reminders(NOW, told, notices, blocked, last, RULES) == []


# --------------------------------------------------------------------------- a moved address


def gone(device: str, hours_ago: float, *destinations: tuple[str, str]) -> Gone:
    return Gone(("ip", device), NOW - timedelta(hours=hours_ago), frozenset(destinations))


def test_the_same_indicators_from_a_new_address_soon_after_the_old_went_quiet_is_a_move() -> None:
    old = gone("10.1.1.5", 30, SERVER, DOMAIN)
    assert moved(NOW, frozenset({SERVER, DOMAIN}), [old], RULES) is old
    # the window is 72 hours after the old address went quiet
    assert moved(NOW, frozenset({SERVER, DOMAIN}), [gone("10.1.1.5", 72, SERVER, DOMAIN)], RULES)
    assert (
        moved(NOW, frozenset({SERVER, DOMAIN}), [gone("10.1.1.5", 73, SERVER, DOMAIN)], RULES)
        is None
    )


def test_a_device_that_began_an_hour_after_another_stopped_is_a_second_device() -> None:
    """A move leaves a quiet gap; a device that begins within two hours of another's last alert
    is more likely a second device."""
    assert moved(NOW, frozenset({SERVER}), [gone("10.1.1.5", 1, SERVER)], RULES) is None
    assert moved(NOW, frozenset({SERVER}), [gone("10.1.1.5", 2, SERVER)], RULES) is not None
    assert moved(
        NOW, frozenset({SERVER}), [gone("10.1.1.5", 1, SERVER)], Rules(move_gap=timedelta(0))
    )


def test_an_old_address_that_is_still_active_is_a_second_device() -> None:
    later = Gone(("ip", "10.1.1.5"), NOW + timedelta(hours=1), frozenset({SERVER}))
    assert moved(NOW, frozenset({SERVER}), [later], RULES) is None


def test_different_indicators_are_a_different_device() -> None:
    old = gone("10.1.1.5", 10, SERVER, DOMAIN, SERVER_2)
    assert moved(NOW, frozenset({SERVER}), [old], RULES) is None  # 1 of 3 in common
    assert moved(NOW, frozenset(), [old], RULES) is None
    assert moved(NOW, frozenset({SERVER}), [gone("10.1.1.5", 10)], RULES) is None  # no indicators


def test_two_equally_good_old_devices_are_never_guessed_between() -> None:
    a = gone("10.1.1.5", 10, SERVER)
    b = gone("10.1.1.6", 12, SERVER)
    assert moved(NOW, frozenset({SERVER}), [a, b], RULES) is None
    assert moved(NOW, frozenset({SERVER}), [a, gone("10.1.1.6", 12, SERVER_2)], RULES) is a


def test_the_window_and_the_similarity_are_settings() -> None:
    rules = Rules(move_window=timedelta(hours=6), move_similarity=0.5)
    assert moved(NOW, frozenset({SERVER}), [gone("10.1.1.5", 5, SERVER, DOMAIN)], rules)
    assert moved(NOW, frozenset({SERVER}), [gone("10.1.1.5", 7, SERVER, DOMAIN)], rules) is None


# --------------------------------------------------------------------------- the words


def stamp(moment: datetime) -> str:
    return f"{moment:%d %b}"


def test_the_status_line_says_still_active_or_blocked() -> None:
    told = datetime(2026, 10, 26, 9, tzinfo=UTC)
    assert known.still_active_line(14, 3, told, None, stamp) == (
        "still active: 14 alerts in 3 days since the owner was notified (26 Oct)"
    )
    assert known.still_active_line(1, 1, told, None, stamp).startswith(
        "still active: 1 alert in 1 day since"
    )
    assert known.still_active_line(14, 3, told, told + days(2), stamp) == (
        "blocked at the network; the device is still infected; owner notified on 26 Oct"
    )


def test_the_trend_compares_the_halves_of_the_days() -> None:
    assert known.trend({"2026-10-20": 10}) == "too few days to say"
    assert known.trend({"d1": 2, "d2": 3, "d3": 10, "d4": 12}) == "rising"
    assert known.trend({"d1": 10, "d2": 12, "d3": 2, "d4": 3}) == "falling"
    assert known.trend({"d1": 5, "d2": 5, "d3": 5, "d4": 5}) == "steady"
    assert known.trend({"d1": 0, "d2": 0, "d3": 0, "d4": 4}) == "rising"
    assert known.trend({"d1": 0, "d2": 0}) == "steady"


def test_managed_means_every_device_is_in_a_managed_network() -> None:
    assert known.managed(["lab", "Computer-Room"], RULES)  # D-180: the defaults
    assert not known.managed(["lab", "hostel"], RULES)
    assert not known.managed(["lab", None], RULES)  # unknown is not managed
    assert known.managed(["server"], Rules(managed_types=frozenset({"server"})))
    assert not known.managed([], RULES)


@pytest.mark.parametrize("field", ["renotify_days", "network_days", "quiet_days", "active_days"])
def test_the_days_must_be_positive(field: str) -> None:
    with pytest.raises(ValueError, match="greater than or equal to 1"):
        Rules(**{field: 0})
