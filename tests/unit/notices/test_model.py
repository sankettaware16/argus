"""The rules of a notice (Q-H4): one per (kind, subject) until resolved or raised, a reminder at
most once a day, an outage once and once more when it ends, and the hour's room (10 e-mails, the
rest folded). Pure: no database, no mail. Examples first, then properties over any history."""

from __future__ import annotations

import dataclasses
import uuid
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from argus.cases.model import SEVERITIES, Severity
from argus.notices import model
from argus.notices.model import (
    END_NOTICE_WITHIN,
    KINDS,
    MAX_PER_HOUR,
    OUTAGE_AFTER,
    REMIND_EVERY,
    REMINDED,
    Condition,
    Intent,
    Kind,
    Row,
    Target,
    allocate,
    decide,
    ending,
    hours_between,
    rank,
    ready,
    reconcile,
    urgency,
)

pytestmark = pytest.mark.unit

T0 = datetime(2026, 10, 26, 6, 0, tzinfo=UTC)
CASE = uuid.UUID("11111111-1111-4111-8111-111111111111")


def at(minutes: float = 0, hours: float = 0, days: float = 0) -> datetime:
    return T0 + timedelta(minutes=minutes, hours=hours, days=days)


def cond(
    kind: Kind = "case_active", subject: str = "s1", severity: Severity = "medium",
    count: int = 2, since: datetime | None = None,
) -> Condition:  # fmt: skip
    target = Target("health") if kind == "outage" else Target("case", CASE)
    return Condition(kind, subject, severity, count, target, since)


def row(
    kind: Kind = "case_active", subject: str = "s1", severity: Severity = "medium",
    first: datetime = T0, sent: datetime | None = None,
    sent_severity: Severity | None = None, resolved: datetime | None = None,
    ended: datetime | None = None, notified: int | None = None, id: int = 1,
) -> Row:  # fmt: skip
    if sent is not None and sent_severity is None:
        sent_severity = severity
    if notified is None:
        notified = 0 if sent is None else 1
    return Row(id, kind, subject, severity, 1, first, first, resolved, sent, sent_severity,
               notified, ended)  # fmt: skip


# --------------------------------------------------------------------------- one subject


@pytest.mark.parametrize("kind", [k for k in KINDS if k != "outage"])
def test_a_new_condition_is_stored_and_noticed_at_once(kind: Kind) -> None:
    got = decide(None, cond(kind), T0)
    assert got.store == "insert"
    assert got.first_seen == T0
    assert got.intent is not None
    assert (got.intent.reason, got.intent.kind, got.intent.severity) == ("new", kind, "medium")
    assert got.intent.count == 2


def test_the_same_condition_again_is_stored_not_noticed() -> None:
    sent = row(sent=T0)
    got = decide(sent, cond(), at(minutes=10))
    assert (got.store, got.intent) == ("update", None)


def test_a_row_that_was_stored_but_never_sent_is_noticed_when_the_pass_can_send() -> None:
    """Notices off at first: the rows are stored, nothing marked sent; once on, they are due."""
    got = decide(row(), cond(), at(hours=5))
    assert got.store == "update"
    assert got.intent is not None
    assert got.intent.reason == "new"


def test_a_higher_severity_is_a_new_notice_and_a_lower_one_is_not() -> None:
    sent = row(severity="medium", sent=T0)
    raised = decide(sent, cond(severity="high"), at(minutes=10))
    assert raised.intent is not None
    assert (raised.intent.reason, raised.intent.severity) == ("raised", "high")
    assert decide(sent, cond(severity="low"), at(minutes=10)).intent is None
    # compared with what last went out, not with the row's severity now
    back = row(severity="medium", sent=T0, sent_severity="high")
    assert decide(back, cond(severity="high"), at(minutes=10)).intent is None
    assert decide(back, cond(severity="critical"), at(minutes=10)).intent is not None


@pytest.mark.parametrize("kind", sorted(REMINDED))
def test_a_reminder_comes_after_a_day_and_not_before(kind: Kind) -> None:
    sent = row(kind, sent=T0)
    assert decide(sent, cond(kind), T0 + REMIND_EVERY - timedelta(seconds=1)).intent is None
    got = decide(sent, cond(kind), T0 + REMIND_EVERY)
    assert got.intent is not None
    assert got.intent.reason == "reminder"


def test_an_event_has_no_reminder() -> None:
    assert decide(row("ioc_hit", sent=T0), cond("ioc_hit"), at(days=3)).intent is None


def test_an_outage_is_noticed_once_it_has_lasted_an_hour() -> None:
    first = decide(None, cond("outage"), T0)
    assert (first.store, first.intent) == ("insert", None)  # held: it has only just begun
    held = row("outage", first=T0)
    assert decide(held, cond("outage"), T0 + OUTAGE_AFTER - timedelta(seconds=1)).intent is None
    got = decide(held, cond("outage"), T0 + OUTAGE_AFTER)
    assert got.intent is not None
    assert (got.intent.reason, got.intent.count) == ("new", 1)


def test_an_outage_that_must_last_longer_is_not_noticed_before_then() -> None:
    """The watch that has never run: late after 36 hours, counted from the first sighting (R10)."""
    wait = timedelta(hours=36)
    slow = replace(cond("outage"), after=wait)
    assert decide(None, slow, T0).intent is None
    held = row("outage", first=T0)
    assert decide(held, slow, T0 + OUTAGE_AFTER).intent is None  # an hour is not enough
    assert decide(held, slow, T0 + wait - timedelta(seconds=1)).intent is None
    got = decide(held, slow, T0 + wait)
    assert got.intent is not None
    assert (got.intent.reason, got.intent.count) == ("new", 36)
    assert ready("outage", T0, T0 + wait, wait)
    assert not ready("outage", T0, T0 + OUTAGE_AFTER, wait)
    assert ready("case_active", T0, T0, wait)  # only outages wait


def test_an_outage_whose_start_is_known_is_noticed_at_once_when_it_is_old() -> None:
    got = decide(None, cond("outage", since=at(hours=-3)), T0)
    assert got.first_seen == at(hours=-3)
    assert got.intent is not None
    assert got.intent.count == 3  # the hours it has lasted
    future = decide(None, cond("outage", since=at(hours=2)), T0)  # a clock that runs ahead
    assert future.first_seen == T0
    assert future.intent is None


def test_an_outage_is_never_noticed_twice_nor_reminded_nor_raised() -> None:
    sent = row("outage", severity="medium", first=T0, sent=at(hours=1))
    for later in (at(hours=2), at(days=2)):
        assert decide(sent, cond("outage", severity="critical"), later).intent is None


def test_an_outage_count_is_the_hours_it_has_lasted() -> None:
    got = decide(row("outage", first=T0), cond("outage", count=0), at(hours=5, minutes=30))
    assert got.count == 5
    assert hours_between(T0, T0 + timedelta(minutes=5)) == 1  # never "0 hours"


def test_a_condition_that_is_gone_resolves_the_row() -> None:
    assert decide(row(), None, at(hours=1)).store == "resolve"
    assert decide(None, None, at(hours=1)).store == "none"
    assert decide(row(resolved=at(hours=1)), None, at(hours=2)).store == "none"


def test_a_resolved_subject_that_comes_back_is_a_new_occurrence() -> None:
    over = row(sent=T0, resolved=at(hours=1))
    got = decide(over, cond(), at(hours=2))
    assert got.store == "insert"
    assert got.intent is not None
    assert got.intent.reason == "new"


def test_ready_is_only_about_outages() -> None:
    for kind in KINDS:
        assert ready(kind, T0, T0) is (kind != "outage")
    assert ready("outage", T0, T0 + OUTAGE_AFTER)


# --------------------------------------------------------------------------- the end of an outage


def test_an_announced_outage_that_ends_is_told_once() -> None:
    over = row("outage", first=T0, sent=at(hours=1), resolved=at(hours=4))
    got = ending(over, Target("health"), at(hours=4))
    assert got is not None
    assert (got.reason, got.count) == ("ended", 4)
    assert ending(replace(over, ended_at=at(hours=4)), Target("health"), at(hours=5)) is None


@pytest.mark.parametrize(
    "changes",
    [
        {"kind": "case_active"},  # only an outage has an end notice
        {"sent_at": None, "sent_severity": None, "notified": 0},  # never announced
        {"resolved_at": None},  # still going on
    ],
)
def test_no_end_notice_for_what_was_not_announced_or_is_not_an_outage(changes: dict) -> None:
    base = row("outage", first=T0, sent=at(hours=1), resolved=at(hours=4))
    assert ending(replace(base, **changes), Target("health"), at(hours=4)) is None


def test_an_outage_that_ended_long_ago_is_not_announced_now() -> None:
    over = row("outage", first=T0, sent=at(hours=1), resolved=at(hours=4))
    assert ending(over, Target("health"), at(hours=4) + END_NOTICE_WITHIN) is not None
    assert (
        ending(over, Target("health"), at(hours=4) + END_NOTICE_WITHIN + timedelta(seconds=1))
        is None
    )


# --------------------------------------------------------------------------- a whole pass


def test_reconcile_stores_and_notices_in_one_pass() -> None:
    live = [row("case_active", "a", sent=T0), row("ioc_hit", "b")]
    got = reconcile(
        live, [], [cond("case_active", "a"), cond("closure_waiting", "c")], at(minutes=10)
    )
    by_key = {s.key: s.decision.store for s in got.steps}
    assert by_key == {
        ("case_active", "a"): "update",
        ("closure_waiting", "c"): "insert",
        ("ioc_hit", "b"): "resolve",
    }
    assert [(i.kind, i.reason) for i in got.intents] == [("closure_waiting", "new")]


def test_a_kind_that_could_not_be_read_is_never_resolved() -> None:
    live = [row("case_active", "a", sent=T0), row("ioc_hit", "b")]
    got = reconcile(live, [], [], at(minutes=10), failed={"ioc_hit"})
    assert {s.key: s.decision.store for s in got.steps} == {("case_active", "a"): "resolve"}


def test_two_conditions_for_one_subject_are_one_with_the_higher_severity() -> None:
    got = reconcile(
        [], [], [cond(severity="low"), cond(severity="high"), cond(severity="medium")], T0
    )
    (step,) = got.steps
    assert step.decision.severity == "high"
    assert len(got.intents) == 1


def test_resolving_an_announced_outage_tells_that_it_ended() -> None:
    live = [row("outage", "siem", first=at(hours=-2), sent=at(hours=-1))]
    got = reconcile(live, [], [], T0)
    assert [(i.reason, i.kind) for i in got.intents] == [("ended", "outage")]
    quiet = reconcile([row("outage", "siem", first=at(hours=-2))], [], [], T0)  # never announced
    assert quiet.intents == ()


def test_an_ended_outage_still_waiting_to_be_told_is_due_again() -> None:
    waiting = row("outage", "siem", first=at(hours=-5), sent=at(hours=-4), resolved=at(hours=-1))
    got = reconcile([], [waiting], [], T0)
    assert [i.reason for i in got.intents] == ["ended"]
    assert got.intents[0].row_id == waiting.id


# --------------------------------------------------------------------------- the hour's room


def intent(
    n: int, severity: Severity = "medium", reason: str = "new", kind: Kind = "case_active"
) -> Intent:  # fmt: skip
    return Intent(
        kind, reason, severity, 1, Target("case", CASE), (kind, f"s{n:03d}"),
        T0 + timedelta(minutes=n),
    )  # type: ignore[arg-type]  # fmt: skip


def test_everything_that_fits_goes_out_one_by_one() -> None:
    got = allocate([intent(n) for n in range(10)], 10)
    assert (len(got.send), got.folded, got.emails) == (10, (), 10)


def test_more_than_the_room_leaves_the_last_email_for_a_n_more_notice() -> None:
    got = allocate([intent(n) for n in range(25)], 10)
    assert len(got.send) == 9
    assert len(got.folded) == 16
    assert got.emails == 10


def test_the_most_urgent_go_out_first_and_the_rest_are_folded() -> None:
    low = [intent(n, "low") for n in range(12)]
    high = intent(99, "high")
    critical = intent(98, "critical", kind="ioc_hit")
    got = allocate([*low, high, critical], 3)
    assert [i.severity for i in got.send] == ["critical", "high"]
    assert all(i.severity == "low" for i in got.folded)
    assert len(got.folded) == 12


def test_new_comes_before_a_reminder_and_an_end_comes_last_at_the_same_severity() -> None:
    got = allocate([intent(1, reason="ended"), intent(2, reason="reminder"), intent(3)], 10)
    assert [i.reason for i in got.send] == ["new", "reminder", "ended"]


def test_no_room_sends_nothing_and_loses_nothing() -> None:
    got = allocate([intent(n) for n in range(5)], 0)
    assert (got.send, got.folded, got.emails) == ((), (), 0)
    assert allocate([intent(1)], -3).emails == 0


def test_a_single_email_of_room_folds_everything() -> None:
    got = allocate([intent(n) for n in range(4)], 1)
    assert (got.send, len(got.folded)) == ((), 4)


# --------------------------------------------------------------------------- properties

severities = st.sampled_from(SEVERITIES)
reasons = st.sampled_from(["new", "raised", "reminder", "ended"])
kinds = st.sampled_from(KINDS)


@st.composite
def intents(draw: st.DrawFn) -> Intent:
    n = draw(st.integers(0, 10_000))
    return Intent(
        draw(kinds), draw(reasons), draw(severities), draw(st.integers(0, 99)),
        Target("health"), (draw(kinds), f"s{n}"), T0 + timedelta(minutes=draw(st.integers(0, 600))),
    )  # fmt: skip


@given(st.lists(intents(), max_size=60, unique_by=lambda i: i.key), st.integers(-2, 15))
def test_property_the_room_is_never_exceeded_and_nothing_is_lost(
    due: list[Intent], room: int
) -> None:
    got = allocate(due, room)
    assert got.emails <= max(room, 0)
    told = [*got.send, *got.folded]
    if room >= 1:
        assert sorted(i.key for i in told) == sorted(i.key for i in due)  # all of them, once each
        if len(due) > room:
            assert got.emails == room
            assert len(got.folded) >= 2
    else:
        assert told == []
    for sent in got.send:  # nobody folded is more urgent than somebody sent
        for left in got.folded:
            assert urgency(sent) <= urgency(left)


@given(st.lists(intents(), max_size=40, unique_by=lambda i: i.key), st.integers(1, 12))
def test_property_the_order_of_the_due_notices_changes_nothing(
    due: list[Intent], room: int
) -> None:
    assert allocate(due, room) == allocate(list(reversed(due)), room)


@dataclass
class Subject:
    """A little model of the table and the mail for one (kind, subject): what ``run`` does with
    the pure rules, one 10-minute pass at a time (``emails`` is the hour's count, 10 free)."""

    kind: Kind
    live: Row | None = None
    over: list[Row] = field(default_factory=list)
    log: list[tuple[datetime, str, Severity, int]] = field(
        default_factory=list
    )  # (when, reason, sev, occurrence)
    occurrence: int = 0
    ids: int = 0

    def step(self, now: datetime, condition: Condition | None) -> None:
        pending = [r for r in self.over if r.sent_at is not None and r.ended_at is None]
        rec = reconcile(
            [self.live] if self.live else [], pending, [condition] if condition else [], now
        )
        for s in rec.steps:
            d = s.decision
            if d.store == "insert":
                self.ids += 1
                self.occurrence += 1
                assert d.severity is not None
                assert d.first_seen is not None
                self.live = Row(
                    self.ids, self.kind, s.key[1], d.severity, d.count, d.first_seen, now
                )
            elif d.store == "update" and self.live is not None:
                assert d.severity is not None
                self.live = replace(self.live, severity=d.severity, count=d.count, last_seen=now)
            elif d.store == "resolve" and self.live is not None:
                self.over.append(replace(self.live, resolved_at=now))
                self.live = None
        for i in sorted(rec.intents, key=urgency):
            if i.reason == "ended":
                for index, r in enumerate(self.over):
                    if r.id == i.row_id:
                        self.over[index] = replace(r, ended_at=now)
                self.log.append((now, "ended", i.severity, self.occurrence))
            elif self.live is not None:
                self.live = replace(
                    self.live,
                    sent_at=now,
                    sent_severity=i.severity,
                    notified=self.live.notified + 1,
                )
                self.log.append((now, i.reason, i.severity, self.occurrence))


histories = st.lists(
    st.one_of(st.none(), severities), min_size=1, max_size=300
)  # one entry per 10 minutes: no condition, or one at this severity


@given(kinds, histories)
@settings(max_examples=300, deadline=None)
def test_property_notices_follow_the_rules_over_any_history(
    kind: Kind, history: list[Severity | None]
) -> None:
    sim = Subject(kind)
    for index, severity in enumerate(history):
        now = T0 + timedelta(minutes=10 * index)
        sim.step(now, None if severity is None else cond(kind, "s1", severity))
    by_occurrence: dict[int, list[tuple[datetime, str, Severity]]] = {}
    for when, reason, severity, occurrence in sim.log:
        by_occurrence.setdefault(occurrence, []).append((when, reason, severity))
    for sent in by_occurrence.values():
        firsts = [s for s in sent if s[1] == "new"]
        assert len(firsts) <= 1  # one notice per occurrence, then only a rise or a reminder
        assert not firsts or sent[0] == firsts[0]
        top = None
        last = None
        for when, reason, severity in sent:
            if reason == "raised":
                assert top is not None
                assert rank(severity) > rank(top)  # only a rise
                assert kind != "outage"
            if reason == "reminder":
                assert kind in REMINDED
                assert last is not None
                assert when - last >= REMIND_EVERY  # at most once a day
            if reason in ("new", "raised"):
                top = severity if top is None else max(top, severity, key=rank)
            if reason != "ended":
                last = when
        if kind == "outage":
            assert sum(1 for s in sent if s[1] == "ended") <= 1
            assert sum(1 for s in sent if s[1] in ("new", "raised", "reminder")) <= 1
    # nothing is lost: every occurrence of something that is not an outage was noticed at once
    if kind != "outage":
        begun = [
            i for i, s in enumerate(history) if s is not None and (i == 0 or history[i - 1] is None)
        ]
        assert len(by_occurrence) == len(begun)
        for sent in by_occurrence.values():
            assert sent[0][1] == "new"


@given(st.lists(st.integers(0, 14), min_size=1, max_size=40), st.integers(1, 6))
def test_property_an_hour_of_passes_never_sends_more_than_ten(
    due_each_pass: list[int], seed: int
) -> None:
    """Passes every 10 minutes with any number of due notices: in any hour, at most 10 e-mails."""
    sent_at: list[datetime] = []
    for index, due in enumerate(due_each_pass):
        now = T0 + timedelta(minutes=10 * index)
        room = MAX_PER_HOUR - sum(1 for t in sent_at if t > now - timedelta(hours=1))
        got = allocate([intent(n + seed * 100) for n in range(due)], room)
        sent_at += [now] * got.emails
        window = [t for t in sent_at if t > now - timedelta(hours=1)]
        assert len(window) <= MAX_PER_HOUR


# --------------------------------------------------------------------------- the written-out rules


def test_the_numbers_of_the_plan_are_written_out() -> None:
    assert MAX_PER_HOUR == 10
    assert timedelta(hours=24) == REMIND_EVERY
    assert timedelta(hours=1) == OUTAGE_AFTER
    assert timedelta(hours=24) == END_NOTICE_WITHIN
    assert {"case_active", "after_closure", "closure_waiting"} == REMINDED
    assert model.SUBJECT_CHARS == 64


def test_at_one_severity_the_kinds_go_in_this_order_and_a_new_notice_ties_with_a_rise() -> None:
    order = ["case_active", "ioc_hit", "after_closure", "outage", "closure_waiting"]
    shuffled = [intent(n, kind=k) for n, k in enumerate(reversed(order))]
    assert [i.kind for i in allocate(shuffled, 10).send] == order
    assert len(set(model.KIND_ORDER.values())) == len(order)
    # a new notice and a rise are both "news": the older subject first, then a reminder, then an end
    later = intent(5, reason="raised")
    earlier = intent(1, reason="new")
    reminder = intent(0, reason="reminder")
    ended = intent(0, reason="ended")
    sent = allocate([ended, reminder, later, earlier], 10).send
    assert [(i.reason, i.first_seen) for i in sent] == [
        ("new", earlier.first_seen),
        ("raised", later.first_seen),
        ("reminder", reminder.first_seen),
        ("ended", ended.first_seen),
    ]


def test_a_subject_is_one_to_sixty_four_characters_and_a_count_is_not_negative() -> None:
    target = Target("health")
    for subject in ("x", "x" * 64):
        assert Condition("outage", subject, "low", 0, target).subject == subject
    for subject in ("", "x" * 65):
        with pytest.raises(ValueError, match="1 to 64 characters"):
            Condition("outage", subject, "low", 0, target)
    with pytest.raises(ValueError, match="not negative"):
        Condition("outage", "x", "low", -1, target)
    assert Condition("outage", "x", "low", 0, target).count == 0


def test_the_records_cannot_be_changed_after_they_are_made() -> None:
    made = [
        Target("health"),
        cond(),
        row(),
        intent(1),
        decide(None, cond(), T0),
        allocate([intent(1)], 1),
        reconcile([], [], [cond()], T0).steps[0],
        reconcile([], [], [cond()], T0),
    ]
    for record in made:
        with pytest.raises(dataclasses.FrozenInstanceError):
            record.x = 1  # type: ignore[attr-defined]


def test_a_decision_with_nothing_to_store_says_so_with_zero_and_no_severity() -> None:
    got = decide(None, None, T0)
    assert (got.store, got.intent, got.first_seen, got.severity, got.count) == (
        "none",
        None,
        None,
        None,
        0,
    )


def test_a_row_that_says_it_was_sent_without_saying_how_is_still_noticed_as_new() -> None:
    """The table cannot hold it (a constraint), but the rule does not depend on that."""
    odd = replace(row(sent=T0), sent_severity=None)
    got = decide(odd, cond(), at(hours=30))
    assert got.intent is not None
    assert got.intent.reason == "new"


def test_two_conditions_of_one_subject_with_one_severity_keep_the_first() -> None:
    first = cond(count=1)
    second = replace(first, count=9)
    got = reconcile([], [], [first, second], T0)
    assert got.steps[0].condition == first


def test_an_outage_that_resolves_with_nothing_announced_adds_no_end_notice_to_the_pass() -> None:
    got = reconcile([row("outage", "w", first=at(hours=-3))], [], [], T0)
    assert [s.decision.store for s in got.steps] == ["resolve"]
    assert got.intents == ()


def test_the_refusal_words_and_defaults() -> None:
    with pytest.raises(
        ValueError, match=r"^a case or an investigation has an id; the other pages have none$"
    ):
        Target("case")
    with pytest.raises(ValueError, match=r"^a subject is 1 to 64 characters$"):
        Condition("outage", "", "low", 0, Target("health"))
    with pytest.raises(ValueError, match=r"^a count is not negative$"):
        Condition("outage", "x", "low", -1, Target("health"))
    bare = Row(1, "case_active", "s", "low", 0, T0, T0)
    assert (bare.resolved_at, bare.sent_at, bare.sent_severity, bare.notified, bare.ended_at) == (
        None, None, None, 0, None,
    )  # fmt: skip
    assert model.REASON_ORDER == {"new": 0, "raised": 0, "reminder": 1, "ended": 2}
    assert model.KIND_ORDER["closure_waiting"] > model.KIND_ORDER["outage"]
    assert model.KINDS == ("case_active", "after_closure", "closure_waiting", "ioc_hit", "outage")
