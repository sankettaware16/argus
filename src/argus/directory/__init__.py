"""A site's own account directory (D-337): who an account name belongs to, asked of the
organisation's own system by a provider the site names in ``directory.provider``
(``package.module:attribute``). ARGUS ships no provider: with the setting empty the feature is
off, its page and its card are not shown, and nothing is asked.

What a provider answers names a person, so it is shown only to people who may see account names
(``see_logs``), kept only in the web's memory for ``directory.cache_window``, and never written
to the database, a report, a notice, Kibana or a model's request."""

from __future__ import annotations

import importlib
import logging
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal, Protocol, runtime_checkable

from argus.config.settings import DirectorySettings

log = logging.getLogger(__name__)

Outcome = Literal["found", "not_found", "expired", "error"]
ACCOUNT = r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$"
_ACCOUNT = re.compile(ACCOUNT)
MAX_CACHED = 2_000
MAX_DETAILS = 20


@dataclass(frozen=True)
class Person:
    """What is known of an account: ``kind`` (a student, staff ...), ``department``, and the
    rest as labelled lines in the provider's order. ``name`` is None in what the account's name
    alone says (``Provider.describe``)."""

    account: str
    name: str | None = None
    kind: str | None = None
    department: str | None = None
    details: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class Answer:
    """``expired``: the directory no longer accepts the saved session (or none is saved): a
    person has to save a new one. ``why`` is for the person, never a secret."""

    outcome: Outcome
    person: Person | None = None
    why: str | None = None


@runtime_checkable
class Provider(Protocol):
    label: str  # the directory's name, as people know it

    def describe(self, account: str) -> Person | None:
        """What the account's name alone says (no request), or None."""

    async def lookup(self, account: str, secret: str, timeout_s: float) -> Answer: ...

    async def check(self, secret: str, timeout_s: float) -> Answer:
        """Whether the directory accepts ``secret``, without asking about anyone: ``found``
        (it does), ``expired`` or ``error``."""


def resolve(named: str) -> Provider:
    """The provider ``package.module:attribute`` names; ValueError when there is none."""
    module, _, attribute = named.partition(":")
    if not module or not attribute:
        raise ValueError("directory.provider is package.module:attribute")
    try:
        found: Any = getattr(importlib.import_module(module), attribute)
    except (ImportError, AttributeError) as exc:
        raise ValueError(f"directory.provider {named!r} cannot be loaded ({exc})") from None
    if not isinstance(found, Provider):
        raise ValueError(f"directory.provider {named!r} is not a directory provider")
    return found


def valid(account: str) -> bool:
    return _ACCOUNT.fullmatch(account) is not None


class Directory:
    """The provider with the site's settings: answers are remembered for ``cache_window`` (a
    person found, or not in the directory), failures never."""

    def __init__(self, provider: Provider, settings: DirectorySettings,
                 clock: Callable[[], float] = time.monotonic) -> None:  # fmt: skip
        self.provider = provider
        self.label = provider.label
        self._secret = settings.secret()
        self._timeout = settings.timeout.total_seconds()
        self._window = settings.cache_window.total_seconds()
        self._clock = clock
        self._cached: dict[str, tuple[float, Answer]] = {}

    def describe(self, account: str) -> Person | None:
        return self.provider.describe(account) if valid(account) else None

    async def lookup(self, account: str) -> Answer:
        if not valid(account):
            return Answer("not_found")
        key = account.lower()
        now = self._clock()
        held = self._cached.get(key)
        if held is not None and now - held[0] < self._window:
            return held[1]
        if self._secret is None:
            return Answer("expired", why="no session is saved yet")
        try:
            answer = await self.provider.lookup(account, self._secret, self._timeout)
        except Exception as exc:  # a provider is the site's code: its failure is an answer
            log.warning("directory provider failed: %s", type(exc).__name__)
            return Answer("error", why="the directory's provider failed")
        if answer.outcome in ("found", "not_found"):
            if len(self._cached) >= MAX_CACHED:
                self._cached.pop(next(iter(self._cached)))
            self._cached.pop(key, None)
            self._cached[key] = (now, answer)
        return answer

    async def check(self) -> Answer:
        if self._secret is None:
            return Answer("expired", why="no session is saved yet")
        try:
            return await self.provider.check(self._secret, self._timeout)
        except Exception as exc:
            log.warning("directory provider failed: %s", type(exc).__name__)
            return Answer("error", why="the directory's provider failed")


def load(settings: DirectorySettings) -> Directory | None:
    """The site's directory, or None when none is named. A provider that cannot be loaded
    leaves the feature off (and says so in the log): a typing mistake in a setting must not
    stop the web."""
    if not settings.provider:
        return None
    try:
        return Directory(resolve(settings.provider), settings)
    except ValueError as exc:
        log.warning("%s: the account directory stays off", exc)
        return None
