"""The site's account directory hook (D-337): off unless a provider is named, a provider that
cannot be loaded leaves it off, answers are remembered for the window and failures never, and
without a saved session nothing is asked."""

from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import SecretStr, ValidationError

from argus import directory
from argus.admin import catalogue
from argus.config.settings import CUSTODY_SECRETS, DirectorySettings, Settings
from argus.directory import Answer, Directory, Person

pytestmark = pytest.mark.unit


class Book:
    label = "The book"

    def __init__(self) -> None:
        self.asked: list[str] = []
        self.next: Answer | Exception = Answer("found", Person("a1", name="A Person"))

    def describe(self, account: str) -> Person | None:
        return Person(account, kind="Student") if account.startswith("a") else None

    async def lookup(self, account: str, secret: str, timeout_s: float) -> Answer:
        self.asked.append(f"{account}:{secret}:{timeout_s:g}")
        if isinstance(self.next, Exception):
            raise self.next
        return self.next

    async def check(self, secret: str, timeout_s: float) -> Answer:
        return Answer("found")


BOOK = Book()  # what ``directory.provider`` names in these tests
NOT_ONE = object()


def settings(**more: object) -> DirectorySettings:
    return DirectorySettings(session=SecretStr("s3ss10n"), **more)  # type: ignore[arg-type]


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_it_is_off_unless_a_provider_is_named() -> None:
    assert Settings.model_fields["directory"].default.provider == ""
    assert directory.load(DirectorySettings()) is None


def test_a_named_provider_is_loaded_and_a_wrong_name_leaves_it_off() -> None:
    here = "tests.unit.directory.test_directory"
    found = directory.load(DirectorySettings(provider=f"{here}:BOOK"))
    assert found is not None
    assert found.label == "The book"
    for wrong in (f"{here}:MISSING", "no.such.module:X", f"{here}:NOT_ONE"):
        assert directory.load(DirectorySettings(provider=wrong)) is None
        with pytest.raises(ValueError, match=r"directory\.provider"):
            directory.resolve(wrong)
    for bad in ("module", "a b:c", "x:y z", ":x"):
        with pytest.raises(ValidationError):
            DirectorySettings(provider=bad)


async def test_an_answer_is_remembered_for_the_window_and_a_failure_never() -> None:
    book, clock = Book(), Clock()
    found = Directory(book, settings(cache_window=timedelta(minutes=10)), clock)
    first = await found.lookup("A1")
    assert first.outcome == "found"
    assert book.asked == ["A1:s3ss10n:10"]
    assert await found.lookup("a1") is first  # whatever the letters' case
    assert len(book.asked) == 1
    clock.now += 601
    await found.lookup("a1")
    assert len(book.asked) == 2
    book.next = Answer("expired", why="signed out")
    assert (await found.lookup("b2")).outcome == "expired"
    assert (await found.lookup("b2")).outcome == "expired"
    assert len(book.asked) == 4  # asked again: a new session is used at once
    book.next = RuntimeError("the secret s3ss10n")
    failed = await found.lookup("c3")
    assert (failed.outcome, failed.why) == ("error", "the directory's provider failed")


async def test_without_a_session_nothing_is_asked() -> None:
    book = Book()
    for none in (None, SecretStr(""), SecretStr("   ")):
        found = Directory(book, DirectorySettings(session=none))
        assert (await found.lookup("a1")).outcome == "expired"
        assert (await found.check()).outcome == "expired"
    assert book.asked == []


async def test_a_value_that_is_no_account_name_is_not_asked() -> None:
    book = Book()
    found = Directory(book, settings())
    for bad in ("", "a b", "a/b", "../x", "a\n", "x" * 65, "-a", "a;b"):
        assert (await found.lookup(bad)).outcome == "not_found"
        assert found.describe(bad) is None
    assert book.asked == []
    assert found.describe("a1") == Person("a1", kind="Student")


async def test_the_memory_is_bounded() -> None:
    book = Book()
    found = Directory(book, settings())
    for n in range(directory.MAX_CACHED + 5):
        await found.lookup(f"u{n}")
    assert len(found._cached) == directory.MAX_CACHED


def test_the_session_is_a_secret_only_the_web_holds_and_settings_shows_it() -> None:
    assert "directory.session" in CUSTODY_SECRETS["web"]
    assert not any("directory.session" in held for role, held in CUSTODY_SECRETS.items()
                   if role != "web")  # fmt: skip
    entries = catalogue.by_key()
    assert entries["directory.session"].secret
    assert entries["directory.session"].risk is catalogue.Risk.SENSITIVE
    assert entries["directory.session"].restarts == ("argus-web",)
    assert "s3ss10n" not in repr(settings())
