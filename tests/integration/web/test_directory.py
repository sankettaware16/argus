"""The site's account directory through ``/api/v1`` (D-337): 404 where the site has none, only
for people who may see account names, each question audited without its answer, and nothing of
the answer stored."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.config.settings import DirectorySettings
from argus.directory import Answer, Directory, Person
from tests.integration.web.b3_support import V1, World, make_world, sign_in

pytestmark = pytest.mark.integration
NAME = "Zebedee Quillfeather"


class Book:
    label = "The book"

    def __init__(self) -> None:
        self.asked: list[str] = []
        self.answer = Answer("found", Person("a1", name=NAME, kind="Student", department="Maths",
                                             details=(("Joined", "2025"),)))  # fmt: skip

    def describe(self, account: str) -> Person | None:
        return Person(account, kind="Student")

    async def lookup(self, account: str, secret: str, timeout_s: float) -> Answer:
        self.asked.append(account)
        return self.answer

    async def check(self, secret: str, timeout_s: float) -> Answer:
        return Answer("found")


@pytest.fixture
async def world(
    seeded: AsyncEngine, web_engine: AsyncEngine, migrated_engine: AsyncEngine, tmp_path: Path
) -> World:
    return await make_world(seeded, web_engine, migrated_engine, tmp_path)


def the_directory(book: Book) -> Directory:
    return Directory(book, DirectorySettings(session=SecretStr("s3ss10n")))


async def test_a_site_without_a_directory_has_no_look_up(world: World) -> None:
    async with world.app() as http:
        await sign_in(http, "mina")
        assert (await http.get(f"{V1}/session")).json()["directory"] is None
        assert (await http.get(f"{V1}/directory/a1")).status_code == 404


async def test_only_who_may_see_account_names_may_ask(world: World) -> None:
    book = Book()
    async with world.app(directory=the_directory(book)) as http:
        await sign_in(http, "sven")  # no see_logs
        assert (await http.get(f"{V1}/session")).json()["directory"] is None
        assert (await http.get(f"{V1}/directory/a1")).status_code == 403
    assert book.asked == []
    async with world.app(directory=the_directory(book)) as http:
        assert (await http.get(f"{V1}/directory/a1")).status_code == 401


async def test_the_answer_is_shown_audited_and_not_stored(world: World) -> None:
    book = Book()
    async with world.app(directory=the_directory(book)) as http:
        await sign_in(http, "mina")
        assert (await http.get(f"{V1}/session")).json()["directory"] == "The book"
        got = await http.get(f"{V1}/directory/a1")
        assert got.status_code == 200, got.text
        said = got.json()
        assert (said["outcome"], said["directory"], said["account"]) == ("found", "The book", "a1")
        assert said["person"] == {"name": NAME, "kind": "Student", "department": "Maths",
                                  "details": [{"label": "Joined", "value": "2025"}]}  # fmt: skip
        assert said["described"]["name"] is None
        for bad in ("a%20b", "a%00b", "x" * 65, "-a"):
            assert (await http.get(f"{V1}/directory/{bad}")).status_code in (404, 422), bad
        book.answer = Answer("expired", why="signed out")
        gone = (await http.get(f"{V1}/directory/b2")).json()
        assert (gone["outcome"], gone["why"], gone["person"]) == ("expired", "signed out", None)
    assert book.asked == ["a1", "b2"]
    audit = await world.rows(
        "SELECT actor, target_id, details FROM audit_events WHERE action = 'directory_lookup'"
        " ORDER BY id")  # fmt: skip
    assert [(r.actor, r.target_id, r.details) for r in audit] == [
        ("user:mina", "a1", {"result": "found"}),
        ("user:mina", "b2", {"result": "expired"}),
    ]
    # the name is in no table: the answer lives in the web's memory alone
    tables = await world.rows(
        "SELECT table_name FROM information_schema.columns WHERE table_schema = 'public'"
        " GROUP BY table_name")  # fmt: skip
    async with world.owner.connect() as conn:
        for t in tables:
            found = (await conn.execute(
                text(f'SELECT count(*) FROM "{t.table_name}" x WHERE CAST(x AS text) LIKE :n'),  # noqa: S608
                {"n": f"%{NAME}%"})).scalar_one()  # fmt: skip
            assert found == 0, t.table_name
