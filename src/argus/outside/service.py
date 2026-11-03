"""The one place ARGUS asks an outside source (AR3, D-165).

:class:`Outside` is shared by the investigator's tools and the prefetch; the pages never use it.
A lookup is, in this order:

1. **refused** unless the indicator is external (``eligible``: never a campus or private address
   or name) and the source takes that kind;
2. **off** when the source has no key (``outside.<source>_api_key``), except Shodan, which with
   no key asks its free InternetDB (``outside.shodan_internetdb``, AR2c, D-168);
3. **cached** when the same indicator was answered lately (a detection and a server's
   description inside ``outside.cache_window``, 7 days; "no record" and every other answer inside
   ``outside.clean_cache_window``, a day, so a fresh server is looked at again): no request, no
   ledger row;
4. **retry later** when the indicator got no usable answer lately (``outside.error_backoff``,
   6 hours; an error is never an answer, and it is remembered in this process only);
5. **blocked** when a 429 stopped the source and the stop has not ended, or a limit (a second,
   a minute, a day, a month) or the prefetch's own daily budget has no room: the answer says
   when it has;
6. otherwise one request, reserved in the ledger first, sent through the transport, the reply
   reduced to a small answer, cached and the ledger row finished. A 429 stops the source (for the
   reply's Retry-After, which may be 0; else an hour for VirusTotal unless today's ledger shows its
   daily limit used, 10 minutes for Shodan, the rest of the month for Censys); a refused key stops
   it for an hour.

One lookup of a source at a time in this process (the free Censys tier allows one). Nothing here
logs or stores a key, and no log line holds an indicator: the ledger has the source, the kind,
the outcome, the status and the size of the answer.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.ext.asyncio import AsyncEngine

from argus.config.settings import OutsideSettings
from argus.llm.detect import Campus
from argus.outside import facts, providers, read, store
from argus.outside.eligible import Eligibility
from argus.outside.read import View

log = logging.getLogger("argus.outside")

REFUSED_STOP = timedelta(hours=1)  # a key the source did not accept: do not ask again for a while
SHODAN_STOP = timedelta(minutes=10)  # Shodan's limit is a rate; its 429 clears quickly
VIRUSTOTAL_STOP = timedelta(hours=1)  # a 429 with no Retry-After and the day's limit not spent
MAX_FAILED = 5_000  # indicators remembered as failing at once (the oldest go first)
PACE = 2.0  # seconds a lookup will wait for a per-second limit rather than say "not now"

# lookup statuses
CACHED = "cached"
FETCHED = "fetched"
OFF = "off"  # no key
REFUSED = "refused"  # not an external indicator, or a kind the source does not take
BLOCKED = "blocked"  # stopped, or a limit or budget has no room
RETRY_LATER = "retry_later"  # no usable answer for this indicator lately: not asked again yet
FAILED = "failed"  # the request got no usable answer


@dataclass(frozen=True)
class Outcome:
    status: str
    source: str
    kind: str
    value: str
    answer_status: str | None = None  # found | not_found, when there is an answer
    answer: Mapping[str, Any] = field(default_factory=dict)
    reason: str = ""  # plain words, for the run's checks
    until: datetime | None = None  # when a blocked source has room again

    @property
    def has_answer(self) -> bool:
        return self.answer_status is not None

    def fact(self, threshold: int) -> dict[str, Any] | None:
        if self.answer_status is None:
            return None
        return facts.fact(self.source, self.kind, self.value, self.answer_status, self.answer,
                          threshold)  # fmt: skip


Sleep = Callable[[float], Awaitable[None]]


class Outside:
    def __init__(
        self,
        engine: AsyncEngine,
        settings: OutsideSettings,
        transport: providers.Transport,
        eligibility: Eligibility,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        sleep: Sleep = asyncio.sleep,
        sources: Mapping[str, providers.Provider] | None = None,
        internetdb: providers.Provider | None = None,
        parent_ok: Callable[[str], bool] | None = None,
    ) -> None:
        self.engine = engine
        self.settings = settings
        self.transport = transport
        self.eligibility = eligibility
        self.clock = clock
        self.sleep = sleep
        self.providers = sources if sources is not None else providers.PROVIDERS
        self.internetdb = internetdb if internetdb is not None else providers.INTERNETDB
        self._parent_ok = parent_ok
        self._locks = {s: asyncio.Lock() for s in facts.SOURCES}
        self._failed: dict[tuple[str, str, str], datetime] = {}  # (source, kind, value) -> until

    # -- what is on ------------------------------------------------------------------------

    def on(self, source: str) -> bool:
        """The source can be asked: it has a key (Shodan also with its keyless InternetDB)."""
        return self.settings.enabled(source)

    @property
    def window(self) -> timedelta:
        return self.settings.cache_window

    @property
    def threshold(self) -> int:
        return self.settings.flag_threshold

    @property
    def clean_window(self) -> timedelta:
        return min(self.settings.clean_cache_window, self.window)

    def parent_ok(self, parent: str) -> bool:
        """Whether the answer for a registered parent may be read as true of the names under it
        (D-174): eligible, and given ``parent_ok`` at construction (the shared-infrastructure list)
        not a name many customers share."""
        return self.eligibility.check("domain", parent) is None and (
            self._parent_ok is None or self._parent_ok(parent)
        )

    @property
    def view(self) -> View:
        return view_of(self.settings, self.parent_ok)

    # -- indicators that failed lately -----------------------------------------------------

    def failed_lately(self, source: str, kind: str, indicator: str) -> bool:
        """The source gave no usable answer for this indicator inside ``outside.error_backoff``
        (remembered in this process): it is not asked again yet, and the prefetch moves on."""
        until = self._failed.get((source, kind, indicator))
        return until is not None and until > self.clock()

    def _failure(self, source: str, kind: str, indicator: str, now: datetime) -> None:
        self._failed = {k: u for k, u in self._failed.items() if u > now}
        while len(self._failed) >= MAX_FAILED:
            del self._failed[min(self._failed, key=lambda k: self._failed[k])]
        self._failed[(source, kind, indicator)] = now + self.settings.error_backoff

    # -- the cache, read only --------------------------------------------------------------

    async def attach(
        self, conn: Any, investigation_id: Any, body: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        """``body`` with the cached outside facts of the investigation's external indicators as
        its ``outside`` list (no request is made). The body itself when there are none."""
        found = await read.facts_for(conn, [investigation_id], self.clock(), self.window,
                                     self.threshold, clean_window=self.clean_window,
                                     parent_ok=self.parent_ok)  # fmt: skip
        mine = found.get(investigation_id, [])
        if not mine:
            return body
        return {**body, "outside": facts.merge(facts.facts_of(body.get("outside")), mine)}

    # -- a lookup --------------------------------------------------------------------------

    async def lookup(
        self, source: str, kind: str, value: str, *, purpose: str = "agent",
        day_cap: int | None = None, campus: Campus | None = None,
        fresh: Callable[[str, Mapping[str, Any]], bool] | None = None,
    ) -> Outcome:  # fmt: skip
        """Ask ``source`` about one indicator (see the module's docstring for the order).
        ``campus`` is the caller's view of the campus for this one item (the base campus plus
        the host and user names it mentions): the indicator is checked against it. ``fresh``: a
        cached answer it calls out of date (an older shape) is asked again."""
        provider = self.providers.get(source)
        indicator = facts.canonical(kind, value)
        shown = value if indicator is None else indicator

        def say(status: str, reason: str, **more: Any) -> Outcome:
            return Outcome(status, source, kind, shown, reason=reason, **more)

        if provider is None or kind not in provider.kinds:
            return say(REFUSED, f"{facts.NAMES.get(source, source)} does not take a {kind}")
        if indicator is None:
            return say(REFUSED, f"not a valid {facts.THIS.get(kind, kind)}")
        eligibility = self.eligibility if campus is None else self.eligibility.with_campus(campus)
        why = eligibility.check(kind, indicator)
        if why is not None:
            return say(REFUSED, f"never looked up outside: {why}")
        key = self.settings.key_of(source)
        if key is None and source == facts.SHODAN and self.settings.shodan_internetdb:
            provider, key = self.internetdb, ""  # no key: Shodan's free InternetDB answers
        if key is None:
            return say(OFF, f"{facts.NAMES[source]} is off (no key)")
        async with self._locks[source]:
            return await self._ask(provider, key, kind, indicator, purpose, day_cap, fresh)

    async def _ask(
        self, provider: providers.Provider, key: str, kind: str, indicator: str, purpose: str,
        day_cap: int | None, fresh: Callable[[str, Mapping[str, Any]], bool] | None = None,
    ) -> Outcome:  # fmt: skip
        source = provider.source
        name = facts.NAMES[source]
        limits = store.limits_of(source, self.settings)
        now = self.clock()
        async with self.engine.connect() as conn:
            hit = await store.cached(conn, source, kind, indicator, now, self.view)
        if hit is not None and (fresh is None or fresh(hit.status, hit.answer)):
            return Outcome(CACHED, source, kind, indicator, hit.status, hit.answer)
        again = self._failed.get((source, kind, indicator))
        if again is not None and again > now:
            when = again.astimezone(UTC).strftime("%H:%M UTC")
            return Outcome(RETRY_LATER, source, kind, indicator, until=again,
                           reason=f"{name} gave no usable answer lately; not asked again before"
                                  f" {when}")  # fmt: skip
        reservation = await self._reserve(source, kind, purpose, limits, day_cap)
        if isinstance(reservation, store.Blocked):
            return Outcome(BLOCKED, source, kind, indicator, until=reservation.until,
                           reason=_blocked(name, reservation))  # fmt: skip
        try:
            reply = await self.transport.get(provider.prepare(kind, indicator, key),
                                             self.settings.timeout.total_seconds())  # fmt: skip
        except Exception as exc:  # whatever went wrong, the request is finished and counted
            await self._finish(reservation, providers.ERROR, None, None)
            self._failure(source, kind, indicator, self.clock())
            what = str(exc) if isinstance(exc, providers.TransportError) else type(exc).__name__
            log.warning("outside: %s did not answer (%s)", source, what)  # never the URL or key
            return Outcome(FAILED, source, kind, indicator, reason=f"{name} did not answer")
        try:
            parsed = provider.parse(kind, reply, self.clock())
        except Exception:  # a parser never raises on what it was tested with; belt and braces
            parsed = providers.Parsed(providers.ERROR)
        size = len(reply.body)
        end = self.clock()
        if parsed.outcome in (providers.FOUND, providers.NOT_FOUND):
            await self._finish(reservation, "ok" if parsed.outcome == providers.FOUND
                               else "not_found", reply.status, size)  # fmt: skip
            async with self.engine.begin() as conn:
                await store.put(conn, source, kind, indicator, parsed.outcome, parsed.answer,
                                size, end)  # fmt: skip
            self._failed.pop((source, kind, indicator), None)
            return Outcome(FETCHED, source, kind, indicator, parsed.outcome, parsed.answer)
        if parsed.outcome == providers.LIMITED:
            until = await self._stop_until(source, end, parsed.retry_after)
            await self._finish(reservation, "limited", reply.status, size, until)
            log.warning("outside: %s answered 429; stopped until %s", source, until.isoformat())
            stopped = f"{name} is stopped: it answered that the limit is reached"
            return Outcome(BLOCKED, source, kind, indicator, until=until, reason=stopped)
        if parsed.outcome == providers.REFUSED:
            until = end + REFUSED_STOP
            await self._finish(reservation, "error", reply.status, size, until)
            log.warning("outside: %s refused the key (HTTP %s); stopped for an hour", source,
                        reply.status)  # fmt: skip
            return Outcome(BLOCKED, source, kind, indicator, until=until,
                           reason=f"{name} did not accept its key")  # fmt: skip
        await self._finish(reservation, "error", reply.status, size)
        self._failure(source, kind, indicator, end)
        log.warning("outside: %s answered HTTP %s that could not be read", source, reply.status)
        return Outcome(FAILED, source, kind, indicator, reason=f"{name} gave no usable answer")

    async def _reserve(
        self, source: str, kind: str, purpose: str, limits: tuple[store.Limit, ...],
        day_cap: int | None,
    ) -> int | store.Blocked:  # fmt: skip
        now = self.clock()
        async with self.engine.begin() as conn:
            got = await store.reserve(conn, source, kind, purpose, limits, now,
                                      purpose_day_cap=day_cap)  # fmt: skip
        if isinstance(got, store.Blocked) and got.reason == "limit":
            wait = (got.until - now).total_seconds()
            if wait <= PACE:  # a per-second limit: wait for it once rather than say "not now"
                await self.sleep(max(wait, 0.0))
                now = self.clock()
                async with self.engine.begin() as conn:
                    got = await store.reserve(conn, source, kind, purpose, limits, now,
                                              purpose_day_cap=day_cap)  # fmt: skip
        return got

    async def _finish(
        self, request_id: int, outcome: str, status: int | None, size: int | None,
        stopped_until: datetime | None = None,
    ) -> None:  # fmt: skip
        async with self.engine.begin() as conn:
            await store.finish(conn, request_id, outcome, status, size, stopped_until)

    async def _stop_until(self, source: str, now: datetime, retry_after: int | None) -> datetime:
        """When a source that answered 429 may be asked again: when it said (0 is now), else a
        window that fits its limit. VirusTotal's 429 is as likely the minute's limit as the day's:
        an hour, unless today's ledger shows the day's limit used."""
        if retry_after is not None:
            return now + timedelta(seconds=retry_after)
        if source == facts.SHODAN:
            return now + SHODAN_STOP
        if source == facts.VIRUSTOTAL:
            day = store.Limit("day", self.settings.virustotal_per_day)
            async with self.engine.connect() as conn:
                used = await store.used_since(conn, source, day.since(now))
            return day.resets(None, now) if used >= day.maximum else now + VIRUSTOTAL_STOP
        return store.Limit("month", 0).resets(None, now)  # Censys: the rest of the month

    async def prune(self) -> int:
        """Delete answers long past their window (four windows)."""
        async with self.engine.begin() as conn:
            return await store.prune(conn, self.clock() - 4 * self.window)


def view_of(settings: OutsideSettings, parent_ok: Callable[[str], bool] | None = None) -> View:
    """How the cache is read under these settings (the pages, the flags and the investigator
    all read it alike). ``parent_ok``: whether the answer for a registered parent may be read as
    true of the names under it (D-174)."""
    return View(settings.cache_window, settings.flag_threshold,
                min(settings.clean_cache_window, settings.cache_window), parent_ok)  # fmt: skip


def _blocked(name: str, got: store.Blocked) -> str:
    when = got.until.astimezone(UTC).strftime("%H:%M UTC")
    why = {
        "stopped": f"{name} is stopped until {when}",
        "limit": f"{name} is at its limit; it has room again at {when}",
        "budget": f"{name}'s budget for this use is spent for today",
    }[got.reason]
    return why


def sentence(outcome: Outcome, threshold: int = 3) -> str:
    """The plain sentence for a lookup's result, for the run's checks: the answer in words, or
    why there is none."""
    entry = outcome.fact(threshold)
    return facts.describe(entry) if entry is not None else outcome.reason


__all__ = ["Outcome", "Outside", "sentence", "view_of"]
