"""One scenario, two Kibanas (Q-D4's gate): every class with hostile values, against the fake
(``test_scenarios.py``, always) and the local Kibana 8.19.12 tier (``tests/kibana/test_writer.py``,
when the tier runs). A ``View`` is how the scenario looks at Kibana's side."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases.machine import Open, Take
from argus.cases.model import Indicator, Member
from argus.cases.service import CaseService
from tests.integration.cases.conftest import Person, _alert, investigation
from tests.integration.cases.test_service import _apply, _kibana_actor
from tests.integration.writer.kit import Rig, approve_compensation, approved_closure, mirror

HOSTILE_TITLE = "[click](http://evil.example/steal) **bold** <b>x</b>"
HOSTILE_NAME = "Mallory [x](http://evil.example) <img src=x onerror=alert(1)> `` ` ``"
HOSTILE_VALUES = (
    ("domain", "evil.example/[x](http://evil.example)", "indicator"),
    ("host", "<script>alert(1)</script>", "actor"),
    ("ip", "10.9.9.9", "actor"),
    ("url", "https://user:pw@evil.example/a?b=`c`", "indicator"),
)


class View(Protocol):
    """Kibana as the scenario reads it."""

    def case(self, kibana_id: str) -> dict[str, Any]: ...
    def comments(self, kibana_id: str) -> list[str]: ...
    def alert_case_ids(self, alert_id: str) -> list[str]: ...
    def add_tag(self, kibana_id: str, tag: str) -> None: ...
    def attach_actions(self, kibana_id: str) -> int: ...


@dataclass
class Result:
    case_id: uuid.UUID
    kibana_id: str
    description: str
    comments: list[str]


async def seed(
    owner: AsyncEngine, alerts: list[tuple[str, str]]
) -> uuid.UUID:  # fmt: skip
    """An investigation holding exactly these alerts (id, concrete index)."""
    inv = await investigation(owner, alerts=0, actor=(("source.ip", "10.9.9.9"),))
    async with owner.begin() as conn:
        for n, (alert_id, index) in enumerate(alerts):
            await _alert(
                conn, alert_id, inv, datetime(2026, 10, 20, 3, 0, tzinfo=UTC) + timedelta(minutes=n)
            )
            await conn.execute(
                text("UPDATE alert_records SET index = :i WHERE alert_id = :a"),
                {"i": index, "a": alert_id},
            )
    return inv


async def every_class(
    r: Rig, api: AsyncEngine, people: dict[str, Person], view: View, alerts: list[tuple[str, str]],
    *, later: Any,
) -> Result:  # fmt: skip
    """W1 (create, comment, attach), W2 (take, then the approved undo), W3 (close), each with a
    hostile title, indicator, host and person's name, a person's tag kept, a second run writing
    nothing, every comment and description read back from Kibana as it was rendered."""
    inv = await seed(r.owner, alerts)
    async with r.owner.begin() as conn:
        await conn.execute(
            text("UPDATE users SET display_name = :n WHERE username = 'ravi'"), {"n": HOSTILE_NAME}
        )
    async with api.begin() as conn:
        service = await CaseService.start(conn)
        opened = await service.open(
            _kibana_actor(people["asha"]),
            Open(
                HOSTILE_TITLE, "high", "person", (Member(inv, "person"),),
                tuple(Indicator(k, v, role) for k, v, role in HOSTILE_VALUES),  # type: ignore[arg-type]
            ),
        )  # fmt: skip
    case_id = opened.case.id

    first = await r.run("W1", limit=1, kind="canary")
    assert first.stopped is None, first.lines()
    assert first.mismatches == 0, first.lines()
    kid = str(
        (await r.sql("SELECT kibana_case_id FROM kibana_outbox WHERE op = 'create'"))[
            0
        ].kibana_case_id
    )
    case = view.case(kid)
    assert case["created_by"]["username"] == "argus"
    assert case["settings"] == {"syncAlerts": False}
    description = str(case["description"])
    for alert_id, _ in (alerts[0], alerts[-1]):  # the first and the latest of the investigation
        assert view.alert_case_ids(alert_id) == [kid]
    assert (
        view.attach_actions(kid) == 1
    )  # one attach call is one user action (the read-back's count)
    assert (await r.run("W1", limit=1)).sent == 0  # a second run writes nothing
    later(3600)

    view.add_tag(kid, "team-blue")  # a person's tag
    await mirror(r.owner, case_id, kid, version=str(view.case(kid)["version"]))
    await _apply(api, people["ravi"].actor(), case_id, Take(), 1)
    took = await r.run("W2", limit=1, kind="canary")
    assert took.verified == 2, took.lines()
    assert took.mismatches == 0, took.lines()
    assert view.case(kid)["status"] == "in-progress"
    assert "team-blue" in view.case(kid)["tags"]
    later(3600)

    row = int((await r.sql("SELECT id FROM kibana_outbox WHERE op = 'update'"))[0].id)
    await approve_compensation(r, api, people, row)
    undone = await r.run("W2", limit=5)
    assert undone.verified == 2, undone.lines()
    assert view.case(kid)["status"] == "open"
    assert "team-blue" in view.case(kid)["tags"]
    later(3600)

    await approved_closure(r, api, people, case_id, kid, version=str(view.case(kid)["version"]))
    closed = await r.run("W3", limit=1, kind="canary")
    assert closed.verified == 2, closed.lines()
    assert closed.mismatches == 0, closed.lines()
    final = view.case(kid)
    assert final["status"] == "closed"
    assert "argus:reason:benign_expected" in final["tags"]
    assert (await r.run("W3", limit=1)).sent == 0
    return Result(case_id, kid, description, view.comments(kid))


def assert_inert(description: str, comments: list[str], own_link: str) -> None:
    """Whatever the values said, Kibana holds text that a CommonMark reader reads as plain
    paragraphs, code spans and ARGUS's own link."""
    import markdown_it
    import pytest  # noqa: F401 - the caller skips without markdown-it

    for text_ in (description, *comments):
        tokens = markdown_it.MarkdownIt("commonmark", {"html": False}).parse(text_)
        types = {t.type for t in tokens}
        assert not types & {
            "heading_open",
            "bullet_list_open",
            "ordered_list_open",
            "blockquote_open",
            "fence",
            "code_block",
            "html_block",
        }, text_
        kids = [c for t in tokens if t.type == "inline" for c in (t.children or [])]
        assert not {c.type for c in kids} & {"html_inline", "image"}, text_
        hrefs = [c.attrs.get("href") for c in kids if c.type == "link_open"]
        assert all(h == own_link for h in hrefs), (hrefs, text_)
        outside = text_  # a hostile value appears only inside a code span (D-237)
        for span in (c.content for c in kids if c.type == "code_inline"):
            outside = outside.replace(span, "", 1)
        assert "evil.example" not in outside, text_
