"""The action states and the verdict on a person's "done" (Q-H2): the edges, the plain words,
and the properties that matter: never "verified" while coverage is unknown."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from itertools import product
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from argus.cases import watch
from argus.cases.watch import Row, Subject
from argus.context import paths as web_paths
from argus.responder import machine
from argus.responder.machine import ActionRefused, PathReading, State, Verdict

D = date(2026, 10, 14)
DONE = datetime(2026, 10, 14, 6, 0, tzinfo=UTC)  # a Wednesday, 11:30 AM IST
HOST = "10.8.235.157"
C2 = "77.221.155.150"
WANTED = [Subject(C2, 0, (HOST,))]


def day(n: int) -> date:
    return D + timedelta(days=n)


def at(n: int, hour: int = 0, minute: int = 0) -> datetime:
    return datetime(2026, 10, 14, hour, minute, tzinfo=UTC) + timedelta(days=n)


def quiet_alerts(n: int) -> Row:
    return Row(day(n), "alerts", "", 0, "quiet")


def quiet_proxy(n: int, hosts: tuple[str, ...] = (HOST,)) -> Row:
    return Row(day(n), "proxy.contact", C2, 0, "quiet", None, {"watched": list(hosts)})


def quiet_days(*days: int) -> list[Row]:
    return [row for n in days for row in (quiet_alerts(n), quiet_proxy(n))]


# --------------------------------------------------------------------------- the states


ALL: list[State | None] = [None, *machine.STATES]
PERSON = {
    (None, "requested"), (None, "reported_done"),
    ("recommended", "requested"), ("recommended", "reported_done"),
    ("requested", "reported_done"), ("not_verified", "reported_done"),
}  # fmt: skip
ARGUS = {
    (None, "recommended"), ("reported_done", "verified"), ("reported_done", "not_verified"),
    ("verified", "not_verified"), ("not_verified", "not_verified"),
}  # fmt: skip


@pytest.mark.parametrize(
    ("current", "to", "person"), list(product(ALL, machine.STATES, (True, False)))
)
def test_every_edge_is_decided_by_who_makes_it(
    current: State | None, to: State, person: bool
) -> None:
    allowed = (current, to) in (PERSON if person else ARGUS)
    if allowed:
        assert machine.move(current, to, person=person) == to
    else:
        with pytest.raises(ActionRefused) as caught:
            machine.move(current, to, person=person)
        assert caught.value.code == "conflict"


def test_only_arguss_own_states_are_never_a_persons() -> None:
    """A person never makes an action recommended, verified or not verified."""
    for state in ("recommended", "verified", "not_verified"):
        for current in ALL:
            with pytest.raises(ActionRefused):
                machine.move(current, state, person=True)  # type: ignore[arg-type]


def test_a_persons_done_is_an_attestation_in_their_words() -> None:
    assert machine.attest("  The network team  blocked it\n at 3 PM ") == (
        "The network team blocked it at 3 PM"
    )
    for bad in ("", "   \n\t ", "x" * 501, "bell\x07", "esc\x1b[2J"):
        with pytest.raises(ActionRefused) as caught:
            machine.attest(bad)
        assert caught.value.code == "invalid"
    assert len(machine.attest("x" * 500)) == 500


@pytest.mark.parametrize(
    ("moment", "text"),
    [
        (datetime(2026, 10, 26, 8, 22, tzinfo=UTC), "1:52 PM IST on 26 Oct 2026"),
        (datetime(2026, 10, 26, 18, 30, tzinfo=UTC), "12:00 AM IST on 27 Oct 2026"),
        (datetime(2026, 10, 26, 6, 35, tzinfo=UTC), "12:05 PM IST on 26 Oct 2026"),
        (datetime(2026, 10, 26, 0, 0, tzinfo=UTC), "5:30 AM IST on 26 Oct 2026"),
        (datetime(2026, 10, 26, 13, 49, tzinfo=UTC), "7:19 PM IST on 26 Oct 2026"),
    ],
)  # fmt: skip
def test_times_are_ist_twelve_hour(moment: datetime, text: str) -> None:
    assert machine.ist12(moment) == text


def test_a_time_that_cannot_be_shown_never_raises() -> None:
    far = datetime(9999, 12, 31, 23, 0, tzinfo=UTC)
    assert machine.ist12(far) == "an unreadable time"
    assert machine.ist_day(far) == "an unreadable time"
    assert machine.ist_day(datetime(2026, 10, 26, 18, 30, tzinfo=UTC)) == "27 Oct 2026"
    assert machine.say(Verdict("not_verified", "x", far), "proxy.contact") == (
        "not verified: still beaconing, last beat an unreadable time"
    )


# --------------------------------------------------------------------------- the watch


def test_activity_after_the_action_is_not_verified_and_names_the_last_beat() -> None:
    beat = at(1, 13, 52)
    rows = [Row(day(1), "proxy.contact", C2, 0, "active", None, {"last": beat.isoformat()})]
    got = machine.verify_watch("proxy.contact", rows, {}, WANTED, DONE, at(2, 3), zeros_on=True)
    assert got == Verdict("not_verified", "still beaconing", beat)
    assert machine.say(got, "proxy.contact") == (
        "not verified: still beaconing, last beat 7:22 PM IST on 15 Oct 2026"
    )


def test_the_newest_sign_wins_and_an_undated_one_still_counts() -> None:
    older, newer = at(1, 5), at(2, 5)
    rows = [
        Row(day(1), "proxy.contact", C2, 0, "active", None, {"last": older.isoformat()}),
        Row(day(2), "proxy.contact", C2, 0, "active", None, {"last": newer.isoformat()}),
        Row(day(3), "alerts", "", 0, "active", None, {}),  # active, no time known
    ]
    got = machine.verify_watch("proxy.contact", rows, {}, WANTED, DONE, at(4, 3), zeros_on=True)
    assert (got.kind, got.last) == ("not_verified", newer)
    undated = machine.verify_watch(
        "proxy.contact", rows[2:], {}, WANTED, DONE, at(4, 3), zeros_on=True
    )
    assert (undated.kind, undated.last) == ("not_verified", None)
    assert machine.say(undated, "proxy.contact") == "not verified: still beaconing"


def test_the_actions_own_day_counts_only_for_a_sign_later_than_the_action() -> None:
    before = Row(day(0), "proxy.contact", C2, 0, "active", None, {"last": at(0, 5, 59).isoformat()})
    after = Row(day(0), "proxy.contact", C2, 0, "active", None, {"last": at(0, 6, 1).isoformat()})
    still = machine.verify_watch("proxy.contact", [before], {}, WANTED, DONE, at(1), zeros_on=True)
    assert still.kind == "waiting"  # the beats before the block were before it
    got = machine.verify_watch("proxy.contact", [after], {}, WANTED, DONE, at(1), zeros_on=True)
    assert got == Verdict("not_verified", "still beaconing", at(0, 6, 1))
    undated = Row(day(0), "proxy.contact", C2, 0, "active", None, {})
    unknown = machine.verify_watch(
        "proxy.contact", [undated], {}, WANTED, DONE, at(1), zeros_on=True
    )
    assert (unknown.kind, unknown.last) == ("not_verified", None)  # unknown is not quiet


def test_alerts_since_the_action_count_from_the_database_as_it_is_now() -> None:
    activity = {day(2): (3, at(2, 9, 10))}
    got = machine.verify_watch("alerts", [], activity, None, DONE, at(3), zeros_on=False)
    assert got == Verdict("not_verified", "still raising alerts", at(2, 9, 10))
    assert machine.say(got, "alerts") == (
        "not verified: still raising alerts, last alert 2:40 PM IST on 16 Oct 2026"
    )
    before = {day(0): (3, at(0, 5, 0))}  # earlier the same day
    assert (
        machine.verify_watch("alerts", [], before, None, DONE, at(3), zeros_on=False).kind
        == "waiting"
    )


def test_nothing_verifies_before_three_whole_days_have_passed_after_the_action() -> None:
    rows = quiet_days(1, 2, 3)
    for hours in (0, 30, 60, 80):
        got = machine.verify_watch(
            "proxy.contact", rows, {}, WANTED, DONE, DONE + timedelta(hours=hours), zeros_on=True
        )
        assert got.kind == "waiting"
        assert "whole UTC days must pass" in got.reason
    on_the_day = machine.verify_watch("proxy.contact", rows, {}, WANTED, DONE, at(4), zeros_on=True)
    assert on_the_day.kind == "verified"
    assert "no activity of the case's addresses for 3 whole UTC days" in on_the_day.reason


def test_coverage_that_is_unknown_is_never_verified() -> None:
    rows = quiet_days(1, 2, 3)
    now = at(4, 2)

    def run(rows: list[Row], **kw: Any) -> Verdict:
        args: dict[str, Any] = {"wanted": WANTED, "zeros_on": True, **kw}
        wanted = args.pop("wanted")
        return machine.verify_watch("proxy.contact", rows, {}, wanted, DONE, now, **args)

    assert run(rows).kind == "verified"
    assert run(rows, zeros_on=False).kind == "waiting"  # Q-F1's verified zeros are not on
    assert run(rows, wanted=None).kind == "waiting"  # the case's addresses cannot be listed
    assert run([r for r in rows if r.day != day(2)]).kind == "waiting"  # a missing day
    assert run([r for r in rows if r.source != "alerts"]).kind == "waiting"  # no alerts answer
    assert run([r for r in rows if r.source == "alerts"]).kind == "waiting"  # no proxy answer
    for outcome in ("unverified", "not_checked"):
        swapped = [
            Row(r.day, r.source, r.subject, r.part, outcome, "why", r.detail)
            if r.source == "proxy.contact" and r.day == day(3)
            else r
            for r in rows
        ]
        assert run(swapped).kind == "waiting"  # a zero nobody could vouch for
    other_host = [quiet_proxy(n, ("10.0.0.9",)) if n == 2 else quiet_proxy(n) for n in (1, 2, 3)]
    assert run([*other_host, *(quiet_alerts(n) for n in (1, 2, 3))]).kind == "waiting"
    assert run(rows, blocked=watch.TOO_COMMON).kind == "waiting"


def test_a_case_with_no_address_to_check_is_verified_on_its_alerts_alone_and_says_so() -> None:
    rows = [quiet_alerts(n) for n in (1, 2, 3)]
    got = machine.verify_watch("proxy.contact", rows, {}, [], DONE, at(4), zeros_on=True)
    assert got.kind == "verified"
    assert "alerts only" in got.reason


def test_the_alerts_verifier_needs_no_log_zeros() -> None:
    rows = [quiet_alerts(n) for n in (1, 2, 3)]
    got = machine.verify_watch("alerts", rows, {}, None, DONE, at(4), zeros_on=False)
    assert got.kind == "verified"
    assert machine.verify_watch("alerts", rows[:2], {}, None, DONE, at(4), zeros_on=False).kind == (
        "waiting"
    )


# --------------------------------------------------------------------------- the properties

DAYS = list(range(-1, 9))


@st.composite
def watch_worlds(draw: st.DrawFn) -> dict[str, Any]:
    calm = draw(st.booleans())  # most worlds are noisy; a calm one can really be verified
    done_at = DONE + timedelta(minutes=draw(st.integers(0, 3 * 24 * 60)))
    late = 4 * 24 * 60 if calm else 0
    now = done_at + timedelta(minutes=draw(st.integers(late, 10 * 24 * 60)))
    kind = draw(st.sampled_from(["proxy.contact", "alerts"]))
    hosts = ("10.0.0.1", "10.0.0.2")
    wanted = draw(
        st.one_of(
            st.none(),
            st.lists(
                st.builds(
                    Subject,
                    st.sampled_from([C2, "5.5.5.5"]),
                    st.integers(0, 1),
                    st.just(hosts[:1]),
                ),
                max_size=2,
                unique_by=lambda s: (s.destination, s.part),
            ),
        )
    )
    rows = []
    keys = [(watch.ALERTS, "", 0), *[(watch.CONTACT, s.destination, s.part) for s in wanted or []]]
    for n in DAYS:
        for source, subject, part in keys:
            weight = 150 if calm else 12
            outcome = draw(
                st.sampled_from(["quiet"] * weight + ["active", "unverified", "not_checked", "-"])
            )
            if outcome == "-":
                continue
            last = draw(st.one_of(st.none(), st.integers(-30, 200).map(
                lambda m, n=n: (at(n, 12) + timedelta(minutes=m)).isoformat())))  # fmt: skip
            detail: dict[str, Any] = {"watched": list(draw(st.sampled_from([hosts[:1], hosts])))}
            if outcome == "active" and last is not None:
                detail["last"] = last
            rows.append(Row(day(n), source, subject, part, outcome, "r", detail))
    activity = {}
    for n in DAYS:
        if draw(st.integers(0, 400 if calm else 12)) == 0:
            activity[day(n)] = (1, at(n, 3) + timedelta(minutes=draw(st.integers(0, 1000))))
    return {
        "kind": kind, "rows": rows, "activity": activity, "wanted": wanted, "done_at": done_at,
        "now": now, "zeros_on": draw(st.booleans()),
        "blocked": draw(st.sampled_from([None, None, None, watch.TOO_COMMON])),
    }  # fmt: skip


def explain_verified(w: dict[str, Any]) -> list[str]:
    """Why a "verified" verdict on ``w`` would be wrong: the conditions, written out again."""
    wrong = []
    today = watch.utc_day(w["now"])
    done_day = watch.utc_day(w["done_at"])
    window = [today - timedelta(days=n) for n in (3, 2, 1)]
    kind, rows = w["kind"], {r.key: r for r in w["rows"]}
    if window[0] <= done_day:
        wrong.append("a day of the window is not after the action")
    if kind != "alerts" and not w["zeros_on"]:
        wrong.append("Q-F1's verified zeros are off")
    if kind != "alerts" and w["wanted"] is None:
        wrong.append("the case's addresses were not listed")
    if w["blocked"] is not None:
        wrong.append("the key is too common to search")
    sources = {watch.ALERTS} if kind == "alerts" else {watch.ALERTS, watch.CONTACT}
    for r in w["rows"]:
        if r.outcome == "active" and r.source in sources and r.day > done_day:
            wrong.append("an active answer after the action's day")
        if r.outcome == "active" and r.source in sources and r.day == done_day:
            when = r.detail.get("last")
            if when is not None and datetime.fromisoformat(when) > w["done_at"]:
                wrong.append("an active answer later on the action's day")
    for d, (_, last) in w["activity"].items():
        if d > done_day or (d == done_day and last > w["done_at"]):
            wrong.append("an alert after the action")
    for d in window:
        alerts = rows.get((d, watch.ALERTS, "", 0))
        if alerts is None or alerts.outcome != "quiet":
            wrong.append(f"no quiet alerts answer for {d}")
        for s in (w["wanted"] or []) if kind != "alerts" else []:
            row = rows.get((d, *s.key))
            if row is None or row.outcome != "quiet":
                wrong.append(f"no quiet proxy answer for {s.destination} on {d}")
            elif not set(s.hosts) <= set(row.detail.get("watched") or ()):
                wrong.append("a host the case has now was not watched")
    return wrong


@settings(max_examples=400, deadline=None)
@given(watch_worlds())
def test_never_verified_while_coverage_is_unknown(w: dict[str, Any]) -> None:
    got = machine.verify_watch(
        w["kind"], w["rows"], w["activity"], w["wanted"], w["done_at"], w["now"],
        zeros_on=w["zeros_on"], blocked=w["blocked"],
    )  # fmt: skip
    assert got.kind in ("verified", "not_verified", "waiting")
    if got.kind == "verified":
        assert explain_verified(w) == []
        assert got.last is None
    if got.kind == "not_verified":
        assert machine.say(got, w["kind"]).startswith("not verified: still ")
        if got.last is not None:
            assert got.last >= w["done_at"]
    assert len(got.reason) <= 300


@settings(max_examples=300, deadline=None)
@given(watch_worlds(), st.integers(1, 8), st.integers(0, 1000))
def test_a_new_sign_of_activity_never_makes_a_case_verified(
    w: dict[str, Any], n: int, minutes: int
) -> None:
    first = machine.verify_watch(
        w["kind"], w["rows"], w["activity"], w["wanted"], w["done_at"], w["now"],
        zeros_on=w["zeros_on"], blocked=w["blocked"],
    )  # fmt: skip
    old = w["activity"].get(day(n))
    new = at(n, 1) + timedelta(minutes=minutes)  # a new sign never takes an old one away
    more = {**w["activity"], day(n): (1, max(new, old[1]) if old else new)}
    second = machine.verify_watch(
        w["kind"], w["rows"], more, w["wanted"], w["done_at"], w["now"],
        zeros_on=w["zeros_on"], blocked=w["blocked"],
    )  # fmt: skip
    if first.kind != "verified":
        assert second.kind != "verified"
    if first.kind == "not_verified":
        assert second.kind == "not_verified"


@settings(max_examples=200, deadline=None)
@given(watch_worlds())
def test_the_verdict_does_not_depend_on_the_order_of_the_rows(w: dict[str, Any]) -> None:
    a = machine.verify_watch(
        w["kind"], w["rows"], w["activity"], w["wanted"], w["done_at"], w["now"],
        zeros_on=w["zeros_on"], blocked=w["blocked"],
    )  # fmt: skip
    b = machine.verify_watch(
        w["kind"], list(reversed(w["rows"])), w["activity"], w["wanted"], w["done_at"], w["now"],
        zeros_on=w["zeros_on"], blocked=w["blocked"],
    )  # fmt: skip
    assert (a.kind, a.last) == (b.kind, b.last)


# --------------------------------------------------------------------------- web paths

ENV = "/.env"
GIT = "/.git/config"


def reading(n: int, hours: int, outcomes: dict[str, str], start_hours: int | None = None) -> Any:
    asked = at(n, hours)
    return PathReading(asked, asked - timedelta(hours=start_hours or 1), outcomes)


def test_a_path_is_verified_only_by_a_logged_refusal_after_the_action() -> None:
    required = frozenset({ENV})
    refused_after = reading(1, 9, {ENV: web_paths.REFUSED})
    assert machine.verify_paths(required, [refused_after], DONE).kind == "verified"
    for outcome in (web_paths.UNKNOWN, web_paths.POSSIBLE, web_paths.CATCH_ALL):
        got = machine.verify_paths(required, [reading(1, 9, {ENV: outcome})], DONE)
        assert got.kind == "waiting", outcome  # a zero or an incomparable 2xx is not proof
    assert machine.verify_paths(required, [], DONE).kind == "waiting"
    assert machine.verify_paths(frozenset(), [refused_after], DONE).kind == "waiting"
    before = reading(0, 5, {ENV: web_paths.REFUSED}, start_hours=1)  # its window began before
    assert machine.verify_paths(required, [before], DONE).kind == "waiting"


def test_a_path_still_served_is_not_verified_and_names_the_check_that_saw_it() -> None:
    served = reading(1, 9, {ENV: web_paths.SUCCESS})
    got = machine.verify_paths(frozenset({ENV}), [served], DONE)
    assert got == Verdict("not_verified", "still being served", served.asked_at)
    assert machine.say(got, "web.path_outcomes") == (
        "not verified: still being served, last seen by the check of 2:30 PM IST on 15 Oct 2026"
    )


def test_only_the_newest_reading_of_a_path_counts_and_every_path_must_be_refused() -> None:
    required = frozenset({ENV, GIT})
    early = reading(1, 9, {ENV: web_paths.SUCCESS, GIT: web_paths.REFUSED})
    later = reading(2, 9, {ENV: web_paths.REFUSED})
    got = machine.verify_paths(required, [early, later], DONE)
    assert got.kind == "verified"
    back = reading(3, 9, {ENV: web_paths.SUCCESS})
    assert machine.verify_paths(required, [early, later, back], DONE).kind == "not_verified"
    only_one = machine.verify_paths(required, [later], DONE)
    assert only_one.kind == "waiting"
    assert "1 of 2 paths" in only_one.reason


@settings(max_examples=300, deadline=None)
@given(
    st.lists(
        st.tuples(st.integers(0, 6), st.integers(0, 23), st.integers(0, 3),
                  st.sampled_from([ENV, GIT, "/x"]), st.sampled_from([
                      web_paths.SUCCESS, web_paths.REFUSED, web_paths.UNKNOWN,
                      web_paths.POSSIBLE, web_paths.CATCH_ALL])),
        max_size=8,
    ),
    st.sets(st.sampled_from([ENV, GIT]), max_size=2),
)  # fmt: skip
def test_paths_are_verified_only_when_each_was_refused_last_after_the_action(
    items: list[tuple[int, int, int, str, str]], required: set[str]
) -> None:
    readings = [
        PathReading(at(n, h), at(n, h) - timedelta(hours=s), {path: outcome})
        for n, h, s, path, outcome in items
    ]
    got = machine.verify_paths(frozenset(required), readings, DONE)
    after = [r for r in readings if r.start >= DONE]
    if got.kind == "verified":
        assert required
        for path in required:
            seen = [r for r in after if path in r.outcomes]
            newest = max(seen, key=lambda r: r.asked_at)
            assert newest.outcomes[path] == web_paths.REFUSED
    if not after or not required:
        assert got.kind == "waiting"
    if got.kind == "not_verified":
        assert got.last is not None
        assert any(web_paths.SUCCESS in r.outcomes.values() for r in after)


# --------------------------------------------------------------------------- settle


@pytest.mark.parametrize(
    ("stored", "kind", "shown"),
    [
        ("reported_done", "verified", "verified"),
        ("reported_done", "not_verified", "not_verified"),
        ("reported_done", "waiting", "reported_done"),
        ("reported_done", "not_verifiable", "reported_done"),
        ("verified", "not_verified", "not_verified"),  # activity came back
        ("verified", "verified", "verified"),
        ("verified", "waiting", "verified"),
        ("not_verified", "verified", "not_verified"),  # only a new report restarts it
        ("not_verified", "not_verified", "not_verified"),
        ("not_verified", "waiting", "not_verified"),
        ("recommended", "verified", "recommended"),
        ("requested", "not_verified", "requested"),
    ],
)  # fmt: skip
def test_settle_changes_a_state_only_on_a_definite_verdict(
    stored: State, kind: Any, shown: State
) -> None:
    assert machine.settle(stored, Verdict(kind, "x")) == shown


def test_not_verifiable_says_why() -> None:
    got = machine.not_verifiable("Mail templates come in Phase 4.")
    assert got.kind == "not_verifiable"
    assert machine.say(got, "none") == "not verifiable in Phase 3: Mail templates come in Phase 4."
