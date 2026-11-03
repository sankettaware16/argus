"""Reading the SIEM's answer to :class:`~argus.signins.template.SigninsDay` (AR6, D-216), strictly.

The gateway has already refused an answer that timed out, lost shards or ended early
(``PartialResultError``). What is left is the shape: every address in the answer is one that was
asked about, every count is a whole non-negative number, every time is inside the day, the hours add
up to the events. An answer that is not exactly that raises :class:`BadAnswer` and is stored as
incomplete, never as "none seen": unknown is not negative.

Text that came from the logs is made storable first (:func:`text_of`): an account name or a browser
string with a NUL, a lone surrogate or a control character would make the database refuse the whole
answer, and an attacker can type any account name into a failed sign-in (D-222). Sign-in events
whose account name is missing or unusable are counted, and a lookup that has them is incomplete
(``unnamed_events``, D-223): the named accounts are right, the day is not whole.

Nothing here logs or raises with an account name in its message.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from argus.context.evidence import clean
from argus.signins import model as m
from argus.signins.template import DayParams

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
OUTCOMES = ("success", "failure")
INT_MAX = 2**31 - 1  # the database's integer: a larger count is not a count of ours


class BadAnswer(ValueError):  # noqa: N818 - an answer that is not the contract's, not an error of ours
    """The answer is not what the template asks for. The message names the part, never a value."""


@dataclass(frozen=True)
class Parsed:
    """What one answer says: a lookup for every address asked about (complete) and the sightings."""

    lookups: tuple[m.Lookup, ...]
    sightings: tuple[m.Sighting, ...]


def text_of(value: str, cap: int) -> str:
    """``value`` as the database can keep it: NUL and lone surrogates (``clean``) and control
    characters become U+FFFD, and it is cut to ``cap`` characters."""
    return _CONTROL.sub("\ufffd", clean(value))[:cap]


def _whole(value: Any, what: str, *, low: int = 0) -> int:
    if isinstance(value, bool):
        raise BadAnswer(f"{what} is not a number")
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if not isinstance(value, int) or not low <= value <= INT_MAX:
        raise BadAnswer(f"{what} is not a whole number of at least {low}")
    return value


def _buckets(node: Any, what: str) -> list[Mapping[str, Any]]:
    found = node.get("buckets") if isinstance(node, Mapping) else None
    if not isinstance(found, list) or not all(isinstance(b, Mapping) for b in found):
        raise BadAnswer(f"{what} has no list of buckets")
    return found


def _time(node: Any, what: str, params: DayParams) -> datetime:
    value = node.get("value") if isinstance(node, Mapping) else None
    if isinstance(value, bool) or not isinstance(value, int | float) or value != value:
        raise BadAnswer(f"{what} is not a time")
    try:
        moment = datetime.fromtimestamp(float(value) / 1000, UTC)
    except (OverflowError, OSError, ValueError):
        raise BadAnswer(f"{what} is not a time") from None
    if not m.day_start(params.day) <= moment < params.end:
        raise BadAnswer(f"{what} is outside the day that was read")
    return moment


def _user(bucket: Mapping[str, Any], params: DayParams, address: str) -> m.Sighting | int:
    """The account's sighting, or (an account name that is empty once made storable) the number of
    its events, which no account can be named for."""
    raw = bucket.get("key")
    if not isinstance(raw, str):
        raise BadAnswer("an account name is not text")
    events = _whole(bucket.get("doc_count"), "an account's events", low=1)
    name = text_of(raw, m.MAX_USER_CHARS)
    if not name.strip():
        return events
    first = _time(bucket.get("first"), "an account's first event", params)
    last = _time(bucket.get("last"), "an account's last event", params)
    if last < first:
        raise BadAnswer("an account's last event is before its first")
    won = lost = 0
    for entry in _buckets(bucket.get("outcomes"), "the outcomes"):
        n = _whole(entry.get("doc_count"), "an outcome's events", low=1)
        if entry.get("key") == "success":
            won += n
        elif entry.get("key") == "failure":
            lost += n
        elif not isinstance(entry.get("key"), str):
            raise BadAnswer("an outcome is not text")
    if won + lost > events:
        raise BadAnswer("an account has more outcomes than events")
    agent_buckets = _buckets(bucket.get("agents"), "the browser strings")
    seen_agents: Counter[str] = Counter()
    for entry in agent_buckets:
        text = entry.get("key")
        if not isinstance(text, str):
            raise BadAnswer("a browser string is not text")
        n = _whole(entry.get("doc_count"), "a browser string's events", low=1)
        seen_agents[text_of(text, m.MAX_AGENT_CHARS)] += n
    agents = [m.Agent(text, n) for text, n in seen_agents.items()]
    if len(agent_buckets) > m.MAX_AGENTS or sum(a.events for a in agents) > events:
        raise BadAnswer("an account has more browser strings than the template asks for")
    hours: set[int] = set()
    in_hours = 0
    start = m.day_start(params.day)
    for entry in _buckets(bucket.get("hours"), "the hours"):
        key = entry.get("key")
        if isinstance(key, bool) or not isinstance(key, int | float):
            raise BadAnswer("an hour is not a time")
        offset = float(key) / 1000 - start.timestamp()
        if offset < 0 or offset >= 86_400 or offset % 3600 != 0:
            raise BadAnswer("an hour is not an hour of the day that was read")
        hours.add(int(offset // 3600))
        in_hours += _whole(entry.get("doc_count"), "an hour's events", low=1)
    if in_hours != events or not hours:
        raise BadAnswer("an account's hours do not add up to its events")
    if first.hour not in hours or last.hour not in hours:
        raise BadAnswer("an account's first or last event is in an hour with no events")
    return m.Sighting(
        address, params.day, name, first, last, events, won, lost, tuple(sorted(hours)),
        tuple(agents),
    )  # fmt: skip


def _combine(a: m.Sighting, b: m.Sighting) -> m.Sighting:
    """Two sightings of one name (two names that are one once made storable): their sum."""
    agents: Counter[str] = Counter()
    for agent in (*a.agents, *b.agents):
        agents[agent.text] += agent.events
    top = sorted(agents.items(), key=lambda kv: (-kv[1], kv[0]))[: m.MAX_AGENTS]
    return m.Sighting(
        a.address, a.day, a.user, min(a.first_at, b.first_at), max(a.last_at, b.last_at),
        a.events + b.events, a.successes + b.successes, a.failures + b.failures,
        tuple(sorted({*a.hours, *b.hours})), tuple(m.Agent(t, n) for t, n in top),
    )  # fmt: skip


def parse(params: DayParams, body: Any, looked_at: datetime) -> Parsed:
    """The lookups and sightings of ``body``. Raises :class:`BadAnswer`. A lookup with sign-ins by
    no account name is incomplete (``unnamed_events``) and still carries its named sightings."""
    aggs = body.get("aggregations") if isinstance(body, Mapping) else None
    ips = aggs.get("ips") if isinstance(aggs, Mapping) else None
    if not isinstance(ips, Mapping):
        raise BadAnswer("the answer has no address aggregation")
    asked = set(params.addresses)
    seen: set[str] = set()
    sightings: list[m.Sighting] = []
    lookups: list[m.Lookup] = []
    if _whole(ips.get("sum_other_doc_count", 0), "the addresses left out") != 0:
        raise BadAnswer("addresses were left out of the answer")
    for bucket in _buckets(ips, "the addresses"):
        key = bucket.get("key")
        try:
            address = str(ipaddress.IPv4Address(key)) if isinstance(key, str) else None
        except ValueError:
            address = None
        if address is None or address not in asked or address in seen:
            raise BadAnswer("the answer names an address that was not asked about, or twice")
        seen.add(address)
        address_events = _whole(bucket.get("doc_count"), "an address's events", low=1)
        cardinality = bucket.get("accounts")
        total = _whole(
            cardinality.get("value") if isinstance(cardinality, Mapping) else None,
            "an address's accounts",
        )
        users = bucket.get("users")
        found = _buckets(users, "the accounts")
        if len(found) > m.MAX_USERS:
            raise BadAnswer("more accounts are listed than the template asks for")
        named: dict[str, m.Sighting] = {}
        keys: list[str] = []
        unusable = 0
        for entry in found:
            got = _user(entry, params, address)
            keys.append(entry["key"])
            if isinstance(got, int):
                unusable += 1
            else:
                named[got.user] = _combine(named[got.user], got) if got.user in named else got
        if len(set(keys)) != len(keys):
            raise BadAnswer("an account is listed twice")
        other = _whole(users.get("sum_other_doc_count", 0), "the accounts left out")  # type: ignore[union-attr]
        listed = list(named.values())
        collapsed = len(found) - unusable - len(listed)  # names that were one once made storable
        accounts = max(total - unusable - collapsed, len(listed))
        more = accounts - len(listed)
        if other > 0 and more == 0:  # events by accounts not listed: at least one more
            accounts += 1
            more = 1
        sightings.extend(listed)
        unnamed = address_events - sum(s.events for s in listed) - other
        if unnamed > 0:  # sign-ins by no account name: the day is not whole (D-223)
            lookups.append(
                m.Lookup(address, params.day, looked_at, False, 0, 0, m.UNNAMED, unnamed=unnamed)
            )
        else:
            lookups.append(m.Lookup(address, params.day, looked_at, True, accounts, more))
    for address in params.addresses:
        if address not in seen:  # asked, and no sign-in in the allowlisted actions
            lookups.append(m.Lookup(address, params.day, looked_at, True, 0, 0))
    lookups.sort(key=lambda lk: int(ipaddress.IPv4Address(lk.address)))
    return Parsed(tuple(lookups), tuple(sightings))


def incomplete(
    params: DayParams, looked_at: datetime, reason: str, *, only: Collection[str] | None = None
) -> tuple[m.Lookup, ...]:
    """A lookup for every address of a request (or just ``only`` those) that gave no usable
    answer."""
    if reason not in m.REASONS or reason == m.UNNAMED:  # unnamed_events comes with an answer
        raise ValueError(f"{reason} is not a reason a lookup can be incomplete without an answer")
    tries = 1 if reason == m.STORE_FAILED else 0
    return tuple(
        m.Lookup(address, params.day, looked_at, False, 0, 0, reason, store_failures=tries)
        for address in params.addresses
        if only is None or address in only
    )
