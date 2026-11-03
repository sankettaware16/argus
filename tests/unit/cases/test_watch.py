"""The still-active watch's rules (Q-C2): which days and questions, the cap, how answers read,
what makes a day quiet, and the 72-hour quiet window "contained" needs."""

from __future__ import annotations

import random
from datetime import UTC, date, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.cases import watch
from argus.cases.watch import Row, Subject
from argus.freshness.model import Check

NOW = datetime(2026, 10, 24, 3, 0, tzinfo=UTC)
TODAY = date(2026, 10, 24)
D = [TODAY - timedelta(days=n) for n in (3, 2, 1)]  # the three whole days before today


def campus(value: str) -> bool:
    return value.startswith("10.")


# --------------------------------------------------------------------------- days and windows


def test_complete_days_end_yesterday_and_never_pass_the_backlog() -> None:
    assert watch.complete_days(TODAY, NOW) == []  # opened today: nothing is finished yet
    assert watch.complete_days(TODAY - timedelta(days=1), NOW) == [TODAY - timedelta(days=1)]
    long_ago = watch.complete_days(date(2026, 1, 1), NOW)
    assert len(long_ago) == watch.BACKLOG_DAYS
    assert long_ago[-1] == TODAY - timedelta(days=1)
    assert long_ago == sorted(long_ago)
    assert watch.complete_days(date(2026, 12, 1), NOW) == []  # in the future: nothing


def test_the_log_window_is_one_index_and_starts_after_the_freshness_pause() -> None:
    start, end = watch.log_window(date(2026, 10, 23))
    assert (start.hour, start.minute, end.hour, end.minute) == (1, 40, 22, 59)
    assert start.date() == end.date()
    from argus.context import beacon

    params = beacon.ContactParams(destination="203.0.113.9", start=start, end=end)
    assert params.end - params.start < beacon.CONTACT_LONGEST  # a window the template accepts


# --------------------------------------------------------------------------- what to ask


def test_a_case_with_a_c2_and_three_hosts_has_one_check_for_the_c2() -> None:
    held = [
        ("ip", "10.0.0.1", "actor"), ("ip", "10.0.0.2", "actor"), ("ip", "10.0.0.3", "actor"),
        ("ip", "77.221.155.150", "c2"), ("domain", "evil.example", "c2"),
        ("user", "alice", "actor"), ("ip", "8.8.8.8", "actor"),
    ]  # fmt: skip
    (subject,) = watch.subjects(held, campus)
    assert subject.destination == "77.221.155.150"
    assert subject.hosts == ("10.0.0.1", "10.0.0.2", "10.0.0.3")  # a public actor is no host
    assert subject.key == (watch.CONTACT, "77.221.155.150", 0)


def test_more_than_ten_hosts_make_more_parts_and_a_campus_address_is_no_destination() -> None:
    held = [("ip", f"10.0.0.{n}", "actor") for n in range(1, 24)]
    held += [("ip", "77.221.155.150", "c2"), ("ip", "10.9.9.9", "c2")]
    found = watch.subjects(held, campus)
    assert [(s.destination, s.part, len(s.hosts)) for s in found] == [
        ("77.221.155.150", 0, 10), ("77.221.155.150", 1, 10), ("77.221.155.150", 2, 3),
    ]  # fmt: skip


def test_a_shared_destination_is_checked_only_for_watched_hosts() -> None:
    def shared(kind: str, value: str) -> str | None:
        return "a CDN" if value == "104.21.5.5" else None

    alone = [("ip", "104.21.5.5", "c2")]
    assert watch.subjects(alone, campus, shared) == []  # "who reached it" asks a CDN nothing
    with_host = [*alone, ("ip", "10.0.0.1", "actor")]
    assert [s.destination for s in watch.subjects(with_host, campus, shared)] == ["104.21.5.5"]


def test_hosts_without_a_destination_have_no_proxy_check() -> None:
    assert watch.subjects([("ip", "10.0.0.1", "actor"), ("host", "pc1", "actor")], campus) == []


def subject(destination: str, part: int = 0) -> Subject:
    return Subject(destination, part, ("10.0.0.1",))


def test_questions_are_asked_oldest_unanswered_day_first_within_the_cap() -> None:
    """Q-C2 review R18: a case with more addresses than the cap completes its older days over
    several runs (the newest day waits), instead of leaving every day half answered."""
    days = [TODAY - timedelta(days=n) for n in (4, 3, 2, 1)]
    asks, cut = watch.plan_asks([subject("1.1.1.1"), subject("2.2.2.2")], days, set(), set(), 0)
    assert [(a.day, a.subject.destination) for a in asks] == [
        (days[0], "1.1.1.1"), (days[0], "2.2.2.2"), (days[1], "1.1.1.1"),
        (days[1], "2.2.2.2"), (days[2], "1.1.1.1"), (days[2], "2.2.2.2"),
    ]  # fmt: skip
    assert [(a.day, a.subject.destination) for a in cut] == [
        (days[3], "1.1.1.1"), (days[3], "2.2.2.2"),
    ]  # fmt: skip


@pytest.mark.parametrize(
    ("subjects", "cap"),
    [
        (0, 6), (1, 6), (4, 6), (5, 7), (6, 8), (8, 10), (18, 20), (19, 20), (20, 20), (21, 20),
        (100, 20),
    ],
)  # fmt: skip
def test_the_cap_is_the_subjects_and_two_spare_from_six_to_twenty(subjects: int, cap: int) -> None:
    """Q-C2 review R18 (the lead's decision): a case may ask one question a day for each
    checkable subject and two more, at least 6 and at most 20."""
    assert watch.cap_for(subjects) == cap
    assert (watch.MIN_REQUESTS_A_DAY, watch.MAX_REQUESTS_A_DAY, watch.SPARE_REQUESTS) == (6, 20, 2)


@given(st.integers(0, 200), st.integers(0, 200))
def test_property_the_cap_never_shrinks_with_more_subjects_and_stays_in_range(
    a: int, b: int
) -> None:
    low, high = sorted((a, b))
    assert watch.cap_for(low) <= watch.cap_for(high)
    assert watch.MIN_REQUESTS_A_DAY <= watch.cap_for(a) <= watch.MAX_REQUESTS_A_DAY
    assert watch.cap_for(a) >= min(a, watch.MAX_REQUESTS_A_DAY)  # a subject a day, up to 20
    assert watch.cap_for(a) >= min(a + watch.SPARE_REQUESTS, watch.MAX_REQUESTS_A_DAY)


def run_daily(
    subjects: int, runs: int, *, fail_once: bool
) -> tuple[list[int], list[bool], list[int]]:
    """``runs`` daily runs of a case with ``subjects`` addresses, watched from its first day: the
    questions each run asks, whether the last three finished days are whole after it, and how
    many questions are still open. With ``fail_once`` the first question of the first day fails
    (it stays open and is asked again)."""
    wanted = [subject(f"203.0.113.{n}") for n in range(1, subjects + 1)]
    start = date(2026, 10, 14)
    decided: set[tuple[date, str, str, int]] = set()
    failing = fail_once
    asked, whole, open_ = [], [], []
    for run in range(2, 2 + runs):
        today = start + timedelta(days=run)
        days = [start + timedelta(days=d) for d in range(1, run)]
        asks, _ = watch.plan_asks(wanted, days, decided, set(), 0)
        asked.append(len(asks))
        for ask in asks:
            if failing and ask.day == days[0] and ask.subject == wanted[0]:
                failing = False  # sent, no usable answer: it stays open
                continue
            decided.add((ask.day, *ask.subject.key))
        window = [today - timedelta(days=k) for k in (3, 2, 1)]
        whole.append(all((d, *s.key) in decided for d in window for s in wanted))
        open_.append(sum(1 for d in days for s in wanted if (d, *s.key) not in decided))
    return asked, whole, open_


@pytest.mark.parametrize("subjects", [1, 5, 6, 8, 12, 18, 19])
def test_one_question_asked_again_is_cleared_in_a_day_and_the_window_completes(
    subjects: int,
) -> None:
    """The lead's decision on the spare questions: 8 addresses, one question failing once on the
    first day, 14 runs: the leftover is asked with the next day's and the window is whole from
    the fourth run on. (Without spare room the leftover stayed one question short for ever.)"""
    asked, whole, open_ = run_daily(subjects, 14, fail_once=True)
    assert open_[1:] == [0] * 13  # cleared by the second run after the failure
    assert whole[2:] == [True] * 12  # D1 to D3 whole at the run on D4
    assert max(asked) <= watch.cap_for(subjects)
    assert asked[0] == subjects  # the first day's questions, one of which failed
    assert asked[1] == subjects + 1  # the next day's and the leftover


def test_with_twenty_subjects_there_is_no_spare_room_and_a_leftover_stays() -> None:
    """The one case the spare questions do not cover: 20 subjects ask all 20 a day (the most),
    so a question asked again takes a place of the next day's and the newest day stays one
    short."""
    _, whole, open_ = run_daily(20, 14, fail_once=True)
    assert open_ == [1] * 14
    assert whole == [False] * 14
    clean_asked, clean_whole, _ = run_daily(20, 14, fail_once=False)
    assert clean_whole[2:] == [True] * 12
    assert max(clean_asked) == 20


def test_a_case_with_eight_addresses_has_a_cap_of_ten_and_clears_two_days_in_two_runs() -> None:
    days = [TODAY - timedelta(days=2), TODAY - timedelta(days=1)]
    wanted = [subject(f"203.0.113.{n}") for n in range(1, 9)]  # eight addresses, a cap of ten
    decided: set[tuple[date, str, str, int]] = set()
    asked, finished = [], []
    for _ in range(3):
        asks, _ = watch.plan_asks(wanted, days, decided, set(), 0)
        decided |= {(a.day, *a.subject.key) for a in asks}
        asked.append(len(asks))
        finished.append([d for d in days if all((d, *s.key) in decided for s in wanted)])
    assert asked == [10, 6, 0]  # sixteen questions, ten a run, the oldest day whole first
    assert finished == [[days[0]], days, days]


def test_a_case_with_more_addresses_than_twenty_completes_a_day_over_several_runs() -> None:
    days = [TODAY - timedelta(days=2), TODAY - timedelta(days=1)]
    wanted = [subject(f"203.0.113.{n}") for n in range(1, 26)]  # 25 addresses, a cap of 20
    decided: set[tuple[date, str, str, int]] = set()
    asked, finished = [], []
    for _ in range(4):
        asks, _ = watch.plan_asks(wanted, days, decided, set(), 0)
        decided |= {(a.day, *a.subject.key) for a in asks}
        asked.append(len(asks))
        finished.append([d for d in days if all((d, *s.key) in decided for s in wanted)])
    assert asked == [20, 20, 10, 0]  # fifty questions, twenty a run
    assert finished == [[], [days[0]], days, days]  # the older day is whole after two runs


def test_what_is_decided_or_already_known_is_not_asked_and_spending_shrinks_the_room() -> None:
    days = [TODAY - timedelta(days=2), TODAY - timedelta(days=1)]
    wanted = [subject("1.1.1.1")]
    done = {(days[1], *wanted[0].key)}
    asks, cut = watch.plan_asks(wanted, days, done, set(), 0)
    assert [a.day for a in asks] == [days[0]]
    assert cut == []
    asks, cut = watch.plan_asks(wanted, days, set(), {days[1]}, 0)  # the alerts show it active
    assert [a.day for a in asks] == [days[0]]
    asks, cut = watch.plan_asks(wanted, days, set(), set(), 5)
    assert len(asks) == 1
    assert len(cut) == 1
    asks, cut = watch.plan_asks(wanted, days, set(), set(), 6)  # the day's six are spent
    assert asks == []
    assert len(cut) == 2
    asks, cut = watch.plan_asks(wanted, days, set(), set(), 9)  # never a negative room
    assert asks == []


@given(
    st.integers(0, 4), st.integers(0, 7), st.integers(0, 9),
    st.lists(st.integers(0, 6), max_size=8, unique=True),
)  # fmt: skip
def test_property_the_cap_holds_and_nothing_is_lost_or_asked_twice(
    destinations: int, backlog: int, spent: int, decided_days: list[int]
) -> None:
    wanted = [subject(f"203.0.113.{n}") for n in range(destinations)]
    days = [TODAY - timedelta(days=n + 1) for n in range(backlog)]
    decided = {(TODAY - timedelta(days=n + 1), *wanted[0].key) for n in decided_days if wanted}
    asks, cut = watch.plan_asks(wanted, days, decided, set(), spent)
    assert len(asks) <= max(watch.cap_for(len(wanted)) - spent, 0)
    everything = [(a.day, a.subject) for a in asks] + [(a.day, a.subject) for a in cut]
    assert len(everything) == len(set(everything))  # none twice
    expected = {(d, s) for d in days for s in wanted if (d, *s.key) not in decided}
    assert set(everything) == expected  # none lost
    assert not any((a.day, *a.subject.key) in decided for a in asks)
    again, rest = watch.plan_asks(
        wanted, days, decided | {(a.day, *a.subject.key) for a in asks}, set(), spent
    )
    assert {(a.day, a.subject) for a in again + rest} == {(a.day, a.subject) for a in cut}


@given(st.integers(1, 4), st.integers(0, 7), st.integers(0, 6))
def test_property_the_questions_run_oldest_first_and_the_cut_ones_are_the_newest(
    destinations: int, backlog: int, spent: int
) -> None:
    wanted = [subject(f"203.0.113.{n}") for n in range(destinations)]
    days = [TODAY - timedelta(days=n + 1) for n in range(backlog)]
    asks, cut = watch.plan_asks(wanted, days, set(), set(), spent)
    order = [(a.day, a.subject.destination) for a in [*asks, *cut]]
    assert order == sorted(order)  # asked: the oldest unanswered (day, address) first
    assert not asks or not cut or asks[-1].day <= cut[0].day


# --------------------------------------------------------------------------- reading answers


def body(requests: int | None, hosts: dict[str, int] | None = None, last_ms: int | None = None,
         **extra: object) -> dict[str, object]:  # fmt: skip
    aggs: dict[str, object] = {}
    if requests is not None:
        aggs["requests"] = {"value": requests}
    if last_ms is not None:
        aggs["last"] = {"value": last_ms}
    aggs["hosts"] = {
        "buckets": [
            {"key": h, "doc_count": n, "first": {"value": 1}, "last": {"value": 2}}
            for h, n in (hosts or {}).items()
        ]
    }
    return {"timed_out": False, "_shards": {"failed": 0}, "aggregations": aggs, **extra}


def test_reading_a_contact_answer() -> None:
    last = int(datetime(2026, 10, 23, 12, 30, tzinfo=UTC).timestamp() * 1000)
    got = watch.read_contact(body(7, {"10.0.0.2": 4, "10.0.0.1": 3, "10.0.0.9": 0}, last))
    assert got == watch.Reading(
        True, 7, datetime(2026, 10, 23, 12, 30, tzinfo=UTC), ("10.0.0.1", "10.0.0.2")
    )
    assert watch.read_contact(body(0)) == watch.Reading(True, 0, None, ())


@pytest.mark.parametrize(
    "answer",
    [
        None, "x", {}, {"aggregations": None}, body(None),
        body(0, timed_out=True), body(0, _shards={"failed": 1}), body(True),  # type: ignore[arg-type]
    ],
    ids=["none", "text", "empty", "no aggregations", "no count", "timed out", "shard failed",
         "a boolean count"],
)  # fmt: skip
def test_an_answer_that_is_not_whole_is_never_read_as_nothing(answer: object) -> None:
    assert not watch.read_contact(answer).complete


MALFORMED_BODIES = {
    "buckets is a number": body(0, hosts=None) | {"aggregations": {"requests": {"value": 1},
                                                                  "hosts": {"buckets": 5}}},
    "buckets is a string": {"aggregations": {"requests": {"value": 1}, "hosts": {"buckets": "x"}}},
    "buckets is an object": {"aggregations": {"requests": {"value": 1}, "hosts": {"buckets": {}}}},
    "hosts is a list": {"aggregations": {"requests": {"value": 1}, "hosts": []}},
    "requests is a list": {"aggregations": {"requests": []}},
    "requests is negative": {"aggregations": {"requests": {"value": -3}}},
    "requests is NaN": {"aggregations": {"requests": {"value": float("nan")}}},
    "requests is infinite": {"aggregations": {"requests": {"value": float("inf")}}},
    "requests is huge": {"aggregations": {"requests": {"value": 10**30}}},
    "requests is text": {"aggregations": {"requests": {"value": "7"}}},
    "last is negative": {"aggregations": {"requests": {"value": 1}, "last": {"value": -5}}},
    "last is NaN": {"aggregations": {"requests": {"value": 1}, "last": {"value": float("nan")}}},
    "last is infinite": {"aggregations": {"requests": {"value": 1},
                                          "last": {"value": float("-inf")}}},
    "last is huge": {"aggregations": {"requests": {"value": 1}, "last": {"value": 10**25}}},
    "last is a list": {"aggregations": {"requests": {"value": 1}, "last": []}},
    "a host's time is huge": {
        "aggregations": {"requests": {"value": 1}, "hosts": {"buckets": [
            {"key": "10.0.0.1", "doc_count": 1, "first": {"value": 10**25}}]}}
    },
    "a host's time is infinite": {
        "aggregations": {"requests": {"value": 1}, "hosts": {"buckets": [
            {"key": "10.0.0.1", "doc_count": 1, "last": {"value": float("inf")}}]}}
    },
}  # fmt: skip


@pytest.mark.parametrize("name", MALFORMED_BODIES)
def test_a_malformed_answer_is_never_read_as_nothing_and_never_raises(name: str) -> None:
    """Q-C2 review R12: a field that is not what the template returns is "not checked:
    malformed answer", never a crash and never "quiet" (``requests: -3`` was "complete, zero")."""
    got = watch.read_contact(MALFORMED_BODIES[name])
    assert (got.complete, got.problem) == (False, watch.MALFORMED)
    judged = watch.judge_contact(got, known(), zeros_on=True)
    assert (judged.outcome, judged.reason) == ("not_checked", watch.MALFORMED)


def test_a_good_answer_has_no_problem_and_an_absent_field_is_only_incomplete() -> None:
    assert watch.read_contact(body(0)).problem is None
    absent = watch.read_contact({"aggregations": {"hosts": {"buckets": []}}})
    assert (absent.complete, absent.problem) == (False, None)  # "the search did not finish"


def known(at: datetime = NOW) -> Check:
    return Check(True, "complete", at)


def test_contact_is_news_whatever_q_f1_says() -> None:
    reading = watch.Reading(True, 3, datetime(2026, 10, 23, 12, 0, tzinfo=UTC), ("10.0.0.1",))
    for check, on in ((None, False), (known(), True), (Check(False, "gap"), True)):
        judged = watch.judge_contact(reading, check, zeros_on=on)
        assert judged.outcome == "active"
        assert judged.detail["requests"] == 3
        assert judged.detail["hosts"] == ["10.0.0.1"]
        assert judged.detail["last"] == "2026-10-23T12:00:00+00:00"


def test_a_zero_is_quiet_only_when_q_f1_verifies_it() -> None:
    zero = watch.Reading(True, 0, None, ())
    assert watch.judge_contact(zero, known(), zeros_on=True).outcome == "quiet"
    off = watch.judge_contact(zero, known(), zeros_on=False)
    assert (off.outcome, off.reason) == ("unverified", watch.NOT_ON)
    assert watch.judge_contact(zero, None, zeros_on=True).outcome == "unverified"
    for reason in ("no_margin", "late", "silent", "gap", "no_anchor", "quiet_hours"):
        judged = watch.judge_contact(zero, Check(False, reason), zeros_on=True)
        assert judged.outcome == "unverified"
        assert judged.reason is not None
        assert watch.ZERO_WORDS[reason] in judged.reason
    early = watch.judge_contact(zero, Check(False, "not_past_end"), zeros_on=True)
    assert early.outcome == "not_checked"  # the proof may exist later: ask again


def test_an_unfinished_search_is_not_checked_and_asked_again() -> None:
    judged = watch.judge_contact(watch.Reading(False, None, None, ()), None, zeros_on=True)
    assert (judged.outcome, judged.reason) == ("not_checked", "the search did not finish")


def test_every_refusal_has_plain_words_and_the_final_ones_are_known() -> None:
    codes = ["stopped", "deferred", "breaker_open", "skipped_budget", "deadline_passed", "off",
             "quiet_hours", "too_common", "daily_cap", "not_normal", "no_subject", "failed",
             "source_expired", "rejected"]  # fmt: skip
    for code in codes:
        assert watch.refusal_words(code) != watch.refusal_words("nothing like it")
    assert set(codes) >= watch.FINAL_REFUSALS
    assert watch.refusal_words("nothing like it") == "the check could not be asked"


# --------------------------------------------------------------------------- alerts coverage

DAY_START = datetime(2026, 10, 22, 0, 0, tzinfo=UTC)
DAY_END = DAY_START + timedelta(days=1)


def test_a_day_is_covered_when_the_collector_read_past_it_and_no_gap_touches_it() -> None:
    live = DAY_END + timedelta(hours=1)
    assert watch.coverage_reason(DAY_START, DAY_END, live, []) is None
    behind = watch.coverage_reason(DAY_START, DAY_END, DAY_END + timedelta(minutes=59), [])
    assert behind is not None
    assert behind[0] is False  # transient: asked again
    assert watch.coverage_reason(DAY_START, DAY_END, None, []) == (
        False, "the collector has not read any alerts yet",
    )  # fmt: skip


@pytest.mark.parametrize(
    ("begin", "until", "touches"),
    [
        (DAY_START - timedelta(hours=5), DAY_START, False),  # ended as the day began
        (DAY_START - timedelta(hours=5), DAY_START + timedelta(seconds=1), True),
        (DAY_END, DAY_END + timedelta(hours=1), False),  # began as the day ended
        (DAY_END - timedelta(seconds=1), DAY_END + timedelta(hours=1), True),
        (DAY_START + timedelta(hours=3), None, True),  # still open
        (DAY_START - timedelta(days=2), None, True),  # open since long before
    ],
)
def test_a_coverage_gap_touching_the_day_is_final(
    begin: datetime, until: datetime | None, touches: bool
) -> None:
    live = DAY_END + timedelta(hours=2)
    found = watch.coverage_reason(DAY_START, DAY_END, live, [("source_stalled", begin, until)])
    assert (found is not None) is touches
    if found is not None:
        assert found[0] is True
        assert "source stalled" in found[1]


# --------------------------------------------------------------------------- the quiet window

WANTED = [Subject("77.221.155.150", 0, ("10.0.0.1",))]


def quiet_rows(days: list[date] = D, wanted: list[Subject] = WANTED) -> list[Row]:
    rows = [Row(day, watch.ALERTS, "", 0, "quiet") for day in days]
    rows += [
        Row(day, *s.key, "quiet", None, {"watched": list(s.hosts)}) for day in days for s in wanted
    ]
    return rows


def window(rows: list[Row], **kw: object) -> tuple[bool, str]:
    args: dict[str, object] = {"zeros_on": True, "alert_days": ()}
    args.update(kw)
    found = watch.quiet_window(rows, WANTED, TODAY, **args)  # type: ignore[arg-type]
    return found.verified, found.reason


def test_three_quiet_days_with_every_check_quiet_is_a_verified_window() -> None:
    verified, reason = window(quiet_rows())
    assert verified
    assert "3 whole UTC days" in reason
    assert f"{D[0]} to {D[-1]}" in reason
    assert "72 hours" in reason  # and says what it means


def test_the_verdict_names_what_was_read() -> None:
    """Q-C2 review R8: a case with no log check is verified on alerts alone and says so; one
    with a log check says which hours of which days, and that the seam and today are alerts."""
    rows = [Row(day, watch.ALERTS, "", 0, "quiet") for day in D]
    alone = watch.quiet_window(rows, [], TODAY, zeros_on=True)
    assert alone.verified
    assert "alerts only: no address of this case can be checked in the proxy logs" in alone.reason
    assert "01:40" not in alone.reason
    both = window(quiet_rows())[1]
    assert "alerts, and the proxy logs 01:40-22:59 UTC on each of the 3 days" in both
    assert "the nightly seam and today are covered by alerts only" in both
    assert "alerts only" not in both.replace("covered by alerts only", "")
    assert '"72 hours" means these three days' in both


def test_a_key_too_common_to_search_is_never_quiet() -> None:
    """Q-C2 review R4: ``blocked`` beats quiet rows (and Q-F1 being off still says so first)."""
    found = watch.quiet_window(quiet_rows(), WANTED, TODAY, zeros_on=True, blocked=watch.TOO_COMMON)
    assert (found.verified, found.reason) == (False, watch.TOO_COMMON)
    assert "too common" in watch.TOO_COMMON
    off = watch.quiet_window(quiet_rows(), WANTED, TODAY, zeros_on=False, blocked=watch.TOO_COMMON)
    assert off.reason == watch.NOT_ON


def test_a_window_still_filling_says_how_many_checks_are_answered() -> None:
    """Q-C2 review R18: six checks are needed (three days of alerts and one address)."""
    rows = quiet_rows()
    del rows[0]
    del rows[-1]
    verified, reason = window(rows)
    assert not verified
    assert "(4 of 6 checks answered)" in reason
    held = [r if r.day != D[2] or r.source != watch.CONTACT
            else Row(r.day, r.source, r.subject, r.part, "not_checked", "cut off", {})
            for r in quiet_rows()]  # fmt: skip
    assert "(5 of 6 checks answered)" in window(held)[1]
    unverified = [r if r.day != D[2] or r.source != watch.CONTACT
                  else Row(r.day, r.source, r.subject, r.part, "unverified", "a gap", {})
                  for r in quiet_rows()]  # fmt: skip
    assert "checks answered" not in window(unverified)[1]  # decided, not waiting


def test_a_case_with_more_addresses_than_the_watch_asks_in_a_day_says_so() -> None:
    """The lead's decision on R18: above 20 subjects the day stays incomplete, and the verdict
    says the case has more addresses than the watch asks in a day (not before)."""

    def subjects(count: int) -> list[Subject]:
        return [Subject(f"203.0.113.{n}", 0, ("10.0.0.1",)) for n in range(1, count + 1)]

    def verdict(count: int) -> str:
        rows = [Row(day, watch.ALERTS, "", 0, "quiet") for day in D]
        found = watch.quiet_window(rows, subjects(count), TODAY, zeros_on=True)
        assert not found.verified
        return found.reason

    over = verdict(21)
    assert (
        "(3 of 66 checks answered; this case has more addresses than the watch asks in a day)"
        in over
    )
    assert "more addresses than the watch asks" not in verdict(20)
    assert "(3 of 63 checks answered)" in verdict(20)


def test_the_last_run_is_told_in_plain_words() -> None:
    assert "never run" in watch.last_run_words(None, NOW)
    assert watch.last_run_words(NOW - timedelta(minutes=20), NOW) == (
        "last run of the watch: 2026-10-24 02:40 UTC (less than an hour ago)"
    )
    assert "(5 hours ago)" in watch.last_run_words(NOW - timedelta(hours=5), NOW)
    assert "late" not in watch.last_run_words(NOW - timedelta(hours=36), NOW)
    assert "the daily run is late" in watch.last_run_words(NOW - timedelta(hours=37), NOW)


def test_without_q_f1_nothing_is_verified() -> None:
    verified, reason = window(quiet_rows(), zeros_on=False)
    assert (verified, reason) == (False, watch.NOT_ON)


def test_a_case_with_no_proxy_check_needs_only_the_alerts() -> None:
    rows = [Row(day, watch.ALERTS, "", 0, "quiet") for day in D]
    assert watch.quiet_window(rows, [], TODAY, zeros_on=True).verified


@pytest.mark.parametrize("missing", range(6))
def test_a_missing_answer_for_any_day_or_source_blocks(missing: int) -> None:
    rows = quiet_rows()
    del rows[missing]
    verified, reason = window(rows)
    assert not verified
    assert "has not been done yet" in reason


def test_one_day_short_is_not_72_hours() -> None:
    verified, reason = window(quiet_rows(D[1:]))
    assert not verified
    assert str(D[0]) in reason


@pytest.mark.parametrize("outcome", ["active", "unverified", "not_checked"])
@pytest.mark.parametrize("source", ["alerts", "proxy"])
def test_any_other_answer_blocks_and_says_why(outcome: str, source: str) -> None:
    rows = quiet_rows()
    target = (D[1], watch.ALERTS if source == "alerts" else watch.CONTACT)
    rows = [
        Row(r.day, r.source, r.subject, r.part, outcome, "because", {})
        if (r.day, r.source) == target
        else r
        for r in rows
    ]
    verified, reason = window(rows)
    assert not verified
    assert str(D[1]) in reason
    if outcome != "active":
        assert "because" in reason


def test_activity_in_the_window_that_arrived_late_or_today_blocks() -> None:
    assert not window(quiet_rows(), alert_days={D[0]})[0]
    assert "ARGUS's own alerts show activity" in window(quiet_rows(), alert_days={D[2]})[1]
    assert not window(quiet_rows(), alert_days={TODAY})[0]
    today_active = [*quiet_rows(), Row(TODAY, watch.ALERTS, "", 0, "active")]
    verified, reason = window(today_active)
    assert not verified
    assert str(TODAY) in reason


def test_a_window_that_ended_before_yesterday_is_not_current() -> None:
    old = [d - timedelta(days=1) for d in D]
    assert not window(quiet_rows(old))[0]


def test_a_day_asked_before_a_host_joined_does_not_cover_it() -> None:
    """The case gained a host after those days were checked: their quiet answers say nothing
    about it, so the window is not verified until three days that did cover it."""
    wanted = [Subject("77.221.155.150", 0, ("10.0.0.1", "10.0.0.2"))]
    found = watch.quiet_window(quiet_rows(), wanted, TODAY, zeros_on=True)
    assert not found.verified
    assert "did not cover every host" in found.reason
    covered = quiet_rows(D, wanted)
    assert watch.quiet_window(covered, wanted, TODAY, zeros_on=True).verified


def test_a_new_address_the_case_gained_must_be_quiet_too() -> None:
    wanted = [*WANTED, Subject("198.51.100.4", 0, ("10.0.0.1",))]
    found = watch.quiet_window(quiet_rows(), wanted, TODAY, zeros_on=True)
    assert not found.verified


rows_strategy = st.lists(
    st.builds(
        lambda day, source, outcome: Row(
            day,
            source,
            "" if source == watch.ALERTS else WANTED[0].destination,
            0,
            outcome,
            "why",
            {"watched": list(WANTED[0].hosts)} if source == watch.CONTACT else {},
        ),
        st.sampled_from([TODAY - timedelta(days=n) for n in range(0, 6)]),
        st.sampled_from([watch.ALERTS, watch.CONTACT]),
        st.sampled_from(["active", "quiet", "unverified", "not_checked"]),
    ),
    max_size=24,
)


def independent(rows: list[Row], alert_days: set[date]) -> bool:
    """The rule again, written differently: every needed key quiet, nothing active from the
    window's start on, no live alert."""
    by = {r.key: r.outcome for r in rows}
    if alert_days & {*D, TODAY}:
        return False
    if any(r.outcome == "active" and r.day >= TODAY for r in rows):
        return False
    return all(
        by.get((day, source, subject, 0)) == "quiet"
        for day in D
        for source, subject in ((watch.ALERTS, ""), (watch.CONTACT, WANTED[0].destination))
    )


@given(rows_strategy, st.sets(st.sampled_from([TODAY - timedelta(days=n) for n in range(0, 6)])))
def test_property_verified_exactly_when_every_needed_answer_is_quiet(
    rows: list[Row], alert_days: set[date]
) -> None:
    got = watch.quiet_window(rows, WANTED, TODAY, zeros_on=True, alert_days=alert_days).verified
    assert got is independent(list({r.key: r for r in rows}.values()), alert_days)


@given(rows_strategy, st.randoms(use_true_random=False))
def test_property_the_order_of_the_answers_changes_nothing(
    rows: list[Row], rng: random.Random
) -> None:
    unique = list({r.key: r for r in rows}.values())  # one answer per key, as stored
    shuffled = list(unique)
    rng.shuffle(shuffled)
    assert watch.quiet_window(unique, WANTED, TODAY, zeros_on=True) == watch.quiet_window(
        shuffled, WANTED, TODAY, zeros_on=True
    )


@given(rows_strategy, st.sampled_from([TODAY - timedelta(days=n) for n in range(0, 6)]))
def test_property_activity_can_only_take_a_window_away(rows: list[Row], day: date) -> None:
    unique = list({r.key: r for r in rows}.values())
    before = watch.quiet_window(unique, WANTED, TODAY, zeros_on=True).verified
    more = [r for r in unique if r.key != (day, watch.ALERTS, "", 0)]
    more.append(Row(day, watch.ALERTS, "", 0, "active", None))
    after = watch.quiet_window(more, WANTED, TODAY, zeros_on=True).verified
    assert not (after and not before)


# --------------------------------------------------------------------------- what a person reads


def test_status_says_what_was_not_checked_and_why() -> None:
    rows = [
        Row(D[2], watch.ALERTS, "", 0, "quiet"),
        Row(D[2], watch.CONTACT, "77.221.155.150", 0, "not_checked", "the SIEM is not normal"),
        Row(D[1], watch.ALERTS, "", 0, "active"),
        Row(D[1], watch.CONTACT, "77.221.155.150", 0, "unverified", "no margin"),
        Row(D[1], watch.PAIR, "10.0.0.1>77.221.155.150", 0, "active"),
    ]
    lines = watch.status_lines(rows, WANTED)
    assert lines == [
        f"{D[2]}: alerts: quiet; proxy-log: not checked: the SIEM is not normal",
        f"{D[1]}: alerts: active; proxy-log: could not verify: no margin",
    ]
    assert watch.status_lines([], WANTED) == ["1 proxy check(s) are due; none has been done yet"]
    assert watch.status_lines([], []) == []


# ------------------------------------------------------- a missing stream is not an expired day


def test_a_missing_stream_is_not_final_and_has_its_own_words() -> None:
    assert "source_expired" in watch.FINAL_REFUSALS  # ILM deleted the day: asking again is vain
    assert "source_missing" not in watch.FINAL_REFUSALS  # a stream not there can come back (F8)
    words = watch.refusal_words("source_missing")
    assert "not there" in words
    assert words != watch.refusal_words("source_expired")
    assert words != watch.refusal_words("nonsense")


@pytest.mark.parametrize(
    ("reason", "refused"),
    [
        ("source_expired", "source_expired"),
        ("source_missing", "source_missing"),
        ("source_not_ready", "deferred"),
    ],
)
async def test_the_asker_tells_a_missing_stream_from_an_expired_day(
    reason: str, refused: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from argus.cases import watchrun
    from argus.context import beacon
    from argus.context.packs import TaskSpec
    from argus.gateway.errors import SourceMissingError

    class Gateway:
        state = None

        def clock(self) -> datetime:
            return NOW

        async def run(self, *args: object, **kwargs: object) -> object:
            raise SourceMissingError(reason, ())

    class Connection:
        async def __aenter__(self) -> object:
            return object()

        async def __aexit__(self, *exc: object) -> None:
            return None

    class Engine:
        def connect(self) -> Connection:
            return Connection()

    async def admitted(*args: object, **kwargs: object) -> None:
        return None

    monkeypatch.setattr(watchrun.batch1, "admit", admitted)
    asker = watchrun.GatewayAsker(
        Gateway(),  # type: ignore[arg-type]
        Engine(),  # type: ignore[arg-type]
        enabled=["proxy.contact"],
        history=timedelta(days=5),
        is_campus=campus,
    )
    start = NOW.replace(hour=2, minute=0)
    task = TaskSpec(
        beacon.ProxyContact(),
        beacon.ContactParams(destination="8.8.8.8", start=start, end=start + timedelta(hours=1)),
    )
    answer = await asker.ask(task)
    assert answer.refused == refused
    assert (answer.refused in watch.FINAL_REFUSALS) is (reason == "source_expired")
