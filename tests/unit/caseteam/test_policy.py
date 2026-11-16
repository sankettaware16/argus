"""When a case is posted (D-195 points 1 to 3): one pure function, so the rule is the same in the
pass, the preview, the API and these tests. Posting off, the confidence rule, the daily cap, the
canary, a person's rejection, the notified rule, and a started sequence that is finished."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.caseteam import policy
from argus.incident import model as m
from tests.unit.caseteam import kit

pytestmark = pytest.mark.unit
NOW = datetime(2026, 10, 29, 10, 0, tzinfo=UTC)


def facts(**more: object) -> policy.Facts:
    values: dict[str, object] = {
        "post": True,
        "case_state": "open",
        "report": kit.amadey(),
        "version": 1,
        "person": None,
        "open_done": False,
        "last_version": None,
        "last_round_at": None,
        "in_progress": False,
        "opened_today": 0,
        "opened_total": 5,
        "approved": False,
        "has_news": False,
        "now": NOW,
        "auto_min_confidence": 0.8,
        "per_day": 5,
        "canary": 1,
        "min_update_gap": timedelta(hours=6),
    }
    values.update(more)
    if values["person"] == "confirmed":  # a confirm of this version's true positive, unless told
        values.setdefault("person_outcome", "true_positive")
        values.setdefault("person_version", values["version"])
    return policy.Facts(**values)  # type: ignore[arg-type]


def with_verdict(report: m.IncidentReport, **more: object) -> m.IncidentReport:
    return report.model_copy(update={"verdict": report.verdict.model_copy(update=more)})


# --------------------------------------------------------------------------- 1. off by default


def test_posting_off_never_acts_but_says_what_it_would_do() -> None:
    d = policy.decide(facts(post=False))
    assert d.action == "none"
    assert d.dry_run
    assert d.would == "open"
    assert d.route == "ARGUS's verdict is a true positive (0.80)"
    assert "dry run" in d.why


def test_posting_off_with_a_canary_still_says_it_would_open_after_the_approval() -> None:
    d = policy.decide(facts(post=False, opened_total=0, canary=1))
    assert d.action == "none"
    assert d.dry_run
    assert d.would == "open"
    assert d.needs_approval
    assert "dry run" in d.why
    assert "approval" in d.why
    nothing = policy.decide(facts(post=False, person="rejected"))
    assert nothing.action == "none"
    assert not nothing.dry_run
    assert nothing.would == "none"


@given(
    post=st.just(False),
    state=st.sampled_from(["suspected", "open", "assigned", "contained", "closed"]),
    person=st.sampled_from([None, "confirmed", "rejected"]),
    done=st.booleans(),
    progress=st.booleans(),
    total=st.integers(0, 9),
)
def test_with_posting_off_nothing_ever_acts(
    post: bool, state: str, person: str | None, done: bool, progress: bool, total: int
) -> None:
    d = policy.decide(
        facts(
            post=post,
            case_state=state,
            person=person,
            open_done=done,
            in_progress=progress,
            opened_total=total,
            has_news=True,
            version=3,
            last_version=1,
        )
    )
    assert not d.acts


# --------------------------------------------------------------------------- 2. when it opens


def test_a_person_confirming_opens_a_case_at_any_confidence() -> None:
    report = with_verdict(kit.amadey(), confidence=0.2)
    d = policy.decide(facts(report=report, person="confirmed"))
    assert d.action == "open"
    assert d.route == "a person confirmed the report"


@pytest.mark.parametrize(
    ("confidence", "opens"), [(0.79, False), (0.8, True), (0.81, True), (1.0, True), (None, False)]
)
def test_arguss_own_true_positive_opens_a_case_from_the_minimum_confidence(
    confidence: float | None, opens: bool
) -> None:
    report = with_verdict(kit.amadey(), confidence=confidence)
    d = policy.decide(facts(report=report))
    assert d.acts is opens
    if not opens:
        assert "waiting for a person to confirm" in d.why


def test_the_minimum_is_a_setting() -> None:
    report = with_verdict(kit.amadey(), confidence=0.6)
    assert not policy.decide(facts(report=report)).acts
    assert policy.decide(facts(report=report, auto_min_confidence=0.6)).acts


def test_with_auto_off_only_a_persons_confirm_opens() -> None:
    report = with_verdict(kit.amadey(), confidence=0.99)
    d = policy.decide(facts(report=report, auto=False))
    assert not d.acts
    assert "only a person's confirm opens a case" in d.why
    assert policy.decide(facts(report=report, auto=False, person="confirmed")).acts


@pytest.mark.parametrize(
    "outcome", ["benign_expected", "rule_false_positive", "inconclusive", None]
)
def test_only_a_true_positive_opens_by_itself(outcome: str | None) -> None:
    report = with_verdict(kit.amadey(), outcome=outcome)
    assert not policy.decide(facts(report=report)).acts


@pytest.mark.parametrize("kind", ["reading", "none"])
def test_a_reading_is_not_arguss_verdict(kind: str) -> None:
    report = with_verdict(kit.amadey(), kind=kind)
    assert not policy.decide(facts(report=report)).acts
    # a person's confirm of a true positive still opens it (their confirm is not a reading)
    sure = with_verdict(report, outcome="true_positive")
    assert policy.decide(facts(report=sure, person="confirmed")).acts


@pytest.mark.parametrize("outcome", ["benign_expected", "benign_policy", "inconclusive", None])
def test_a_confirm_of_anything_but_a_true_positive_never_opens_a_case(
    outcome: str | None,
) -> None:
    """D-201 point 9: a person confirming that a case is benign (or inconclusive) is not a
    reason to write it to the team's SIEM."""
    report = with_verdict(kit.amadey(), outcome=outcome, kind="person", confidence=None)
    d = policy.decide(facts(report=report, person="confirmed", person_outcome=outcome))
    assert d.action == "none"
    assert d.route is None
    assert "not a true positive" in d.why


def test_a_confirm_holds_while_the_newest_report_says_true_positive() -> None:
    """D-229: the confirm itself and an ongoing case make new versions; they reach Kibana as
    updates, never as a reason to confirm again."""
    report = with_verdict(kit.amadey(), confidence=0.2)  # nothing of ARGUS's own to open it
    later = facts(report=report, version=4, auto=False, person="confirmed", person_version=3)
    assert policy.decide(later).route == "a person confirmed the report"
    turned = with_verdict(kit.amadey(), outcome="inconclusive", confidence=0.2)
    d = policy.decide(facts(report=turned, version=5, person="confirmed", person_version=3))
    assert d.action == "none"
    assert "no longer says true positive" in d.why


def test_the_accounts_hash_does_not_decide_a_confirm() -> None:
    report = with_verdict(kit.amadey(), confidence=0.2)
    for core, person_core in (("c" * 64, "c" * 64), ("c" * 64, "d" * 64), (None, None)):
        d = policy.decide(
            facts(
                report=report, version=4, auto=False, person="confirmed", person_version=3,
                core=core, person_core=person_core,
            )
        )  # fmt: skip
        assert d.action == "open"


def test_a_confirm_of_a_benign_outcome_never_opens_whatever_the_hashes_say() -> None:
    report = with_verdict(kit.amadey(), confidence=0.2)
    d = policy.decide(
        facts(
            report=report,
            version=4,
            person="confirmed",
            person_version=3,
            person_outcome="benign_expected",
            core="c" * 64,
            person_core="c" * 64,
        )
    )
    assert d.action == "none"


def test_a_confirm_of_an_older_version_opens_as_the_persons() -> None:
    d = policy.decide(facts(version=3, person="confirmed", person_version=2))
    assert d.action == "open"
    assert d.route == "a person confirmed the report"


@given(
    outcome=st.sampled_from(
        ["true_positive", "benign_expected", "benign_policy", "rule_false_positive", "inconclusive"]
    ),
    version=st.integers(1, 4),
    seen=st.integers(1, 4),
)
def test_a_persons_confirm_opens_only_a_true_positive(
    outcome: str, version: int, seen: int
) -> None:
    report = with_verdict(kit.amadey(), confidence=0.1)  # ARGUS's own route is closed
    d = policy.decide(
        facts(
            report=report,
            version=version,
            person="confirmed",
            person_outcome=outcome,
            person_version=seen,
        )
    )
    assert d.acts is (outcome == "true_positive")  # on any version while it says so (D-229)


@pytest.mark.parametrize(
    ("state", "opens"),
    [
        ("suspected", True),
        ("open", True),
        ("assigned", True),
        ("contained", False),
        ("closed", False),
    ],
)
def test_only_a_suggested_or_open_case_is_opened(state: str, opens: bool) -> None:
    assert policy.decide(facts(case_state=state)).acts is opens
    assert policy.decide(facts(case_state=state, person="confirmed")).acts is opens


def test_a_rejection_stops_both_routes() -> None:
    d = policy.decide(facts(person="rejected"))
    assert not d.acts
    assert d.why == "a person rejected the report"
    assert not policy.decide(
        facts(person="rejected", open_done=True, version=4, last_version=1, has_news=True)
    ).acts


def test_no_report_no_post() -> None:
    d = policy.decide(facts(report=None, version=None))
    assert not d.acts
    assert "has not written" in d.why


# --------------------------------------------------------------------------- the cap


@pytest.mark.parametrize(("today", "opens"), [(0, True), (4, True), (5, False), (6, False)])
def test_at_most_per_day_cases_are_opened_a_day(today: int, opens: bool) -> None:
    d = policy.decide(facts(opened_today=today))
    assert d.acts is opens
    if not opens:
        assert "limit of 5" in d.why


def test_the_cap_binds_a_person_confirmed_case_too_and_is_a_setting() -> None:
    assert not policy.decide(facts(opened_today=2, per_day=2, person="confirmed")).acts
    assert policy.decide(facts(opened_today=2, per_day=3, person="confirmed")).acts


def test_a_started_sequence_is_finished_whatever_the_cap_says() -> None:
    d = policy.decide(facts(opened_today=99, in_progress=True, person="rejected"))
    assert d.action == "resume"


# --------------------------------------------------------------------------- 3. the canary


def test_the_first_cases_need_a_persons_approval_of_that_case() -> None:
    d = policy.decide(facts(opened_total=0, canary=1))
    assert d.action == "none"
    assert d.needs_approval
    assert "approval" in d.why
    ok = policy.decide(facts(opened_total=0, canary=1, approved=True))
    assert ok.action == "open"
    assert ok.needs_approval


def test_after_the_canary_count_no_approval_is_asked() -> None:
    d = policy.decide(facts(opened_total=1, canary=1))
    assert d.action == "open"
    assert not d.needs_approval


@given(canary=st.integers(0, 6), total=st.integers(0, 9), approved=st.booleans())
def test_the_canary_rule_is_exactly_the_count(canary: int, total: int, approved: bool) -> None:
    d = policy.decide(facts(canary=canary, opened_total=total, approved=approved))
    needs = total < canary
    assert d.needs_approval is needs
    assert (d.action == "open") is (approved or not needs)


# --------------------------------------------------------------------------- notified, updates


def notified(changes: int) -> m.IncidentReport:
    report = kit.amadey()
    notice = m.ReportNotice(
        notified_at=NOW - timedelta(days=2),
        alerts_since=4,
        still_active=True,
        changes=changes,
        line="The owner was told two days ago.",
    )
    return report.model_copy(
        update={"summary": report.summary.model_copy(update={"notice": notice})}
    )


def update_facts(**more: object) -> policy.Facts:
    values: dict[str, object] = {
        "open_done": True,
        "version": 3,
        "last_version": 2,
        "has_news": True,
        "last_round_at": NOW - timedelta(days=1),
    }
    values.update(more)
    return facts(**values)


def test_a_newer_report_is_an_update_never_a_second_case() -> None:
    d = policy.decide(update_facts())
    assert d.action == "update"
    assert policy.decide(update_facts(opened_total=0, canary=3)).action == "update"  # no new canary


def test_nothing_new_nothing_posted() -> None:
    assert not policy.decide(update_facts(version=2)).acts
    assert not policy.decide(update_facts(has_news=False)).acts


def test_a_notified_case_that_has_not_changed_is_never_posted_again() -> None:
    d = policy.decide(update_facts(report=notified(0)))
    assert not d.acts
    assert "unchanged since the notice" in d.why


def test_a_change_since_the_notice_is_a_new_comment_on_the_existing_case() -> None:
    d = policy.decide(update_facts(report=notified(2)))
    assert d.action == "update"
    assert d.why == "changed since the notice"


def test_updates_are_spaced() -> None:
    d = policy.decide(update_facts(last_round_at=NOW - timedelta(hours=1)))
    assert not d.acts
    assert "short while ago" in d.why
    assert policy.decide(update_facts(last_round_at=NOW - timedelta(hours=7))).acts


def test_a_closed_case_gets_no_more_comments() -> None:
    assert not policy.decide(update_facts(case_state="closed")).acts
    assert policy.decide(update_facts(case_state="contained")).acts


def test_a_case_the_read_back_paused_gets_nothing_more_until_resumed() -> None:
    paused = "a person changed the case's settings in Kibana"
    for d in (
        policy.decide(update_facts(kibana_paused=paused)),
        policy.decide(update_facts(kibana_paused=paused, edits_only=True)),  # a correction too
        policy.decide(update_facts(kibana_paused=paused, in_progress=True)),
    ):
        assert not d.acts
        assert d.why.startswith(f"paused in Kibana: {paused}")
        assert "resume-case" in d.why
    assert policy.decide(update_facts(kibana_paused=None)).acts
    assert policy.decide(facts(kibana_paused=paused)).action == "open"  # nothing to pause yet


def test_a_notified_case_not_yet_in_kibana_is_opened_by_the_same_rules() -> None:
    d = policy.decide(facts(report=notified(0)))
    assert d.action == "open"  # unchanged-since-notice only stops a re-post
