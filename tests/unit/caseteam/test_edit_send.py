"""Sending an edit (D-236, D-241): read what Kibana holds, then set it or leave it. The decision is
a pure function of the step and what was read; the poster's flow around it (a version conflict
reads again once, a person's change is skipped and said, a late landing is only recorded) is
tested with the database and the Kibana lane stood in for, so no request can leave."""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from argus.caseteam import plan, policy, sender, store
from argus.caseteam.model import PERSON_EDIT, Author, Step, text_hash
from argus.caseteam.sender import EditConflict, PostConfig, Poster, PostReport, RunStopped
from argus.caseteam.store import PostRow, StepRow
from tests.unit.caseteam import kit as team

pytestmark = pytest.mark.unit
KID = "kibana-case-1"
WAS = "ACME-IR-2026-1026-01 · the title ARGUS wrote"
NEW = "ACME-IR-2026-1026-01 · the new title"
OLD_TEXT = "## Evidence\n\nwhat ARGUS wrote"
NEW_TEXT = "## Evidence\n\nwhat ARGUS writes now"


def retitle() -> Step:
    return Step("edit:title", "retitle", Author.LEAD, "title", payload={"title": NEW, "was": WAS})


def redescribe() -> Step:
    return Step(
        "edit:description",
        "redescribe",
        Author.LEAD,
        "description",
        text="the new description",
        payload={"was_hash": text_hash("the old description")},
    )


def edit_comment() -> Step:
    return Step(
        "edit:comment:evidence:1",
        "edit_comment",
        Author.EVIDENCE,
        "evidence",
        text=NEW_TEXT,
        payload={"of": "comment:evidence:1", "comment_id": "c-7", "was_hash": text_hash(OLD_TEXT)},
    )


def case_live(title: str = WAS, description: str = "the old description") -> dict[str, str]:
    return {"title": title, "description": description, "version": "WzUsMV0="}


def comment_live(text: str = OLD_TEXT, author: str = "argus-evidence") -> dict[str, str]:
    return {"text": text, "version": "WzYsMV0=", "author": author}


# --------------------------------------------------------------------------- the decision


@pytest.mark.parametrize(
    ("step", "live", "verdict"),
    [
        (retitle(), case_live(), "send"),  # what ARGUS wrote: set it
        (retitle(), case_live(NEW), "done"),  # already so: a late landing is only recorded
        (retitle(), case_live("somebody's own title"), "person"),
        (redescribe(), case_live(), "send"),
        (redescribe(), case_live(description="the new description"), "done"),
        (redescribe(), case_live(description="somebody's words"), "person"),
        (edit_comment(), comment_live(), "send"),
        (edit_comment(), comment_live(NEW_TEXT), "done"),
        (edit_comment(), comment_live("my notes replace this"), "person"),
        (edit_comment(), comment_live(author="somebody"), "gone"),  # not its author's
        (edit_comment(), None, "gone"),  # not on the case
    ],
)
def test_the_decision_never_overwrites_a_persons_change(
    step: Step, live: dict[str, str] | None, verdict: str
) -> None:
    got, why = Poster._judge(step, live)
    assert got == verdict
    assert (why == PERSON_EDIT) == (verdict == "person")


# --------------------------------------------------------------------------- the flow


class Conn:
    pass


class FakeEngine:
    @asynccontextmanager
    async def begin(self) -> Any:
        yield Conn()


def row_of(step: Step, state: str = "planned") -> StepRow:
    return StepRow(
        7, uuid.uuid4(), 2, 1, step.key, step.kind, step.author.value, step.part, 2,
        step.payload, step.text, step.units, "0" * 64, state, None, 0,
    )  # fmt: skip


def post_row() -> PostRow:
    return PostRow(uuid.uuid4(), "ACME-IR-2026-1026-01", KID, "active", None, None, 1, None)


class Rig:
    def __init__(self, monkeypatch: pytest.MonkeyPatch, lives: list[dict[str, str] | None]):
        self.poster = Poster(
            FakeEngine(),  # type: ignore[arg-type]
            None,
            PostConfig(post=True, keys=frozenset(a.value for a in Author)),
            clock=lambda: datetime(2026, 10, 30, 10, 0, tzinfo=UTC),
        )
        self.settled: list[tuple[str, str | None, dict[str, Any] | None]] = []
        self.reads = 0
        self.sent: list[Any] = []
        self.answers: list[Any] = []
        self.lives = lives

        async def settle(conn: Any, step_id: int, to: str, **kw: Any) -> bool:
            self.settled.append((to, kw.get("reason"), kw.get("ids")))
            return True

        async def read_live(step: Step, kid: str) -> dict[str, str] | None:
            self.reads += 1
            return self.lives[min(self.reads, len(self.lives)) - 1]

        async def write_step(
            row: StepRow, step: Step, template: Any, params: Any, report: Any
        ) -> Any:
            self.sent.append((template.name, params))
            answer = self.answers.pop(0)
            if isinstance(answer, BaseException):
                raise answer
            return answer

        monkeypatch.setattr(store, "settle", settle)
        monkeypatch.setattr(self.poster, "_read_live", read_live)
        monkeypatch.setattr(self.poster, "_write_step", write_step)

    async def send(self, step: Step) -> PostReport:
        report = PostReport(uuid.uuid4(), 1, policy.Decision("update", "x"))
        await self.poster._send_edit(row_of(step), post_row(), step, team.amadey(), report)
        return report


class Answer:
    def __init__(self, body: Any) -> None:
        self.body = body


async def test_what_kibana_already_shows_is_recorded_and_nothing_is_sent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rig = Rig(monkeypatch, [case_live(NEW)])
    report = await rig.send(retitle())
    assert rig.sent == []
    assert [s[0] for s in rig.settled] == ["verified"]
    assert report.verified == 1


async def test_a_persons_title_is_skipped_with_its_reason_and_said(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rig = Rig(monkeypatch, [case_live("our own title")])
    report = await rig.send(retitle())
    assert rig.sent == []
    assert [(s[0], s[1]) for s in rig.settled] == [("skipped", PERSON_EDIT)]
    assert report.note is not None
    assert "edit:title" in report.note
    assert PERSON_EDIT in report.note


async def test_a_comment_that_is_not_there_is_skipped_not_held(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rig = Rig(monkeypatch, [None])
    report = await rig.send(edit_comment())
    assert [s[0] for s in rig.settled] == ["skipped"]
    assert report.held == []  # nothing waits for a person on it


async def test_an_edit_is_sent_once_against_the_version_just_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rig = Rig(monkeypatch, [case_live()])
    rig.answers = [Answer({"id": KID, "version": "WzYsMV0="})]
    report = await rig.send(retitle())
    [(name, params)] = rig.sent
    assert name == "team.edit_case"
    assert params.cases[0].version == "WzUsMV0="
    assert params.cases[0].title == NEW
    assert [(s[0], s[2]) for s in rig.settled] == [
        ("verified", {"case": KID, "version": "WzYsMV0="})
    ]
    assert report.verified == 1


async def test_a_comment_edit_is_sent_by_its_author_against_the_comments_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rig = Rig(monkeypatch, [comment_live()])
    rig.answers = [Answer({"comments": [{"id": "c-7", "version": "WzgsMV0="}]})]
    await rig.send(edit_comment())
    [(name, params)] = rig.sent
    assert name == "team.edit_comment"
    assert (params.author, params.comment_id, params.version, params.comment) == (
        "argus-evidence", "c-7", "WzYsMV0=", NEW_TEXT,
    )  # fmt: skip
    assert rig.settled[0][2] == {"comment": "c-7", "version": "WzgsMV0="}


async def test_a_version_conflict_reads_again_and_a_late_landing_is_then_only_recorded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The first PATCH is refused (409): somebody changed the case in between. The second read
    finds the title already as wanted (the other writer set it): nothing more is sent."""
    rig = Rig(monkeypatch, [case_live(), case_live(NEW)])
    rig.answers = [EditConflict("edit:title")]
    report = await rig.send(retitle())
    assert rig.reads == 2
    assert len(rig.sent) == 1
    assert [s[0] for s in rig.settled] == ["verified"]
    assert report.verified == 1


async def test_a_version_conflict_that_a_second_read_cures_sends_again_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rig = Rig(monkeypatch, [case_live(), case_live()])
    rig.answers = [EditConflict("edit:title"), Answer({"id": KID, "version": "WzksMV0="})]
    await rig.send(retitle())
    assert rig.reads == 2
    assert len(rig.sent) == 2
    assert [s[0] for s in rig.settled] == ["verified"]


async def test_two_conflicts_leave_the_step_for_the_next_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rig = Rig(monkeypatch, [case_live(), case_live()])
    rig.answers = [EditConflict("edit:title"), EditConflict("edit:title")]
    with pytest.raises(RunStopped, match="changed again"):
        await rig.send(retitle())
    assert rig.settled == []  # the step is `planned` again (the write put it back), not settled


def test_the_poster_uses_the_edit_kinds_the_plan_makes() -> None:
    assert frozenset({"retitle", "redescribe", "edit_comment"}) == sender.EDIT_KINDS
    assert plan.STAND_IN_VERSION


# --------------------------------------------------------------------------- a refresh is no round


def refresh_comment() -> Step:
    """What ``plan.refresh_plan`` makes for a part that now needs one more comment."""
    return Step(
        "comment:evidence:2",
        "comment",
        Author.EVIDENCE,
        "evidence",
        text="## Evidence (2 of 2)\n\nthe rest",
        payload={plan.REFRESH: True},
    )


def an_update_comment() -> Step:
    return Step("comment:intel:1", "comment", Author.INTEL, "intel", text="## Update: Threat intel")


class Finish:
    """``Poster._finish`` with the round's bookkeeping watched and no Kibana to read back."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.rounds: list[int] = []
        poster = Poster(
            FakeEngine(),  # type: ignore[arg-type]
            None,
            PostConfig(post=True, keys=frozenset(a.value for a in Author)),
            clock=lambda: datetime(2026, 10, 30, 10, 0, tzinfo=UTC),
        )
        self.poster = poster

        async def finish_generation(conn: Any, case_id: Any, version: int, now: Any) -> None:
            self.rounds.append(version)

        monkeypatch.setattr(store, "finish_generation", finish_generation)

    async def run(self, *steps: Step) -> None:
        post = PostRow(uuid.uuid4(), "ACME-IR-2026-1026-01", None, "active", None, None, 1, None)
        stored = SimpleNamespace(version=5)
        report = PostReport(post.case_id, 1, policy.Decision("update", "x"))
        rows = [row_of(s, "verified") for s in steps]
        await self.poster._finish(post, rows, stored, report)  # type: ignore[arg-type]


async def test_a_refresh_that_adds_a_comment_does_not_consume_the_update_round(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The review of AR9 (F7): a part that now needed one more comment made the refresh "not only
    edits", so ``last_version`` and ``last_round_at`` moved and the files, the verdict and the new
    alerts waited for the next report version and the 6 h gap."""
    done = Finish(monkeypatch)
    await done.run(retitle(), redescribe(), edit_comment(), refresh_comment())
    assert done.rounds == []


async def test_edits_alone_never_did_and_a_real_round_still_does(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    done = Finish(monkeypatch)
    await done.run(retitle(), redescribe(), edit_comment())
    assert done.rounds == []
    await done.run(edit_comment(), an_update_comment())  # an update round with a comment of its own
    assert done.rounds == [5]
    await done.run(refresh_comment(), an_update_comment())  # a refresh step and a real one
    assert done.rounds == [5, 5]


def test_the_refresh_plan_flags_exactly_the_comments_it_adds() -> None:
    """A refresh's new comment carries the flag; the edits and an update plan's comments do not."""
    report = team.amadey()
    posted = plan.Posted(
        "kibana-case-1", 1, 1, title=report.header.title, description="an old description"
    )
    steps = plan.refresh_plan(report, 2, team.CTX, posted).steps
    added = [s for s in steps if s.kind == "comment"]
    assert added, "every comment is new to a case with no posted comments"
    assert all(s.payload.get(plan.REFRESH) is True for s in added)
    assert not any(plan.REFRESH in s.payload for s in steps if s.kind != "comment")
    first = plan.first_plan(report, 1, [], team.CTX)
    assert not any(plan.REFRESH in s.payload for s in first.steps)
