"""The identity seam (plan §4, §7.2): who a person is and what they may do, checked live.

ARGUS never trusts a capability snapshot it holds for a change: an approval waits for a live
check (at most 30 seconds old) of the approver, and every check is recorded
(``identity_checks``, through ``argus_identity_record()``), because the send-time check reads
them back: an approver whose check was denied since they approved, or who has no good check
within 12 hours, does not count (:mod:`argus.cases.sendcheck`).

:class:`IdentityProvider` is the seam. Q-E1 and Q-E2 plug in the real one (the person's ELK
credential checked against Elasticsearch: ``_has_privileges`` on the space, Kibana's case
privileges, the ``argus`` application privileges). Until then:

* :class:`LocalIdentityProvider` reads the local account (``users.capabilities``); it has no
  Kibana privileges to show, so a local approver can close a case in ARGUS but never approve a
  write to Kibana (plan §3 rule 6: a person makes ARGUS do only what their own ELK account
  may);
* :class:`FakeIdentityProvider` answers whatever a test or the local Kibana tier sets up.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.cases.signing import iso
from argus.web.capabilities import effective

Outcome = Literal["ok", "denied", "unavailable"]
Kind = Literal["person", "break_glass", "service"]
Purpose = Literal["signin", "recheck", "stepup", "request", "approval", "send"]
# Kibana privileges ARGUS acts on for a person (plan §7.1): a closure needs updateCase; opening
# a case createCase and createComment; alert status changes the alert-status privileges.
UPDATE_CASE = "updateCase"
SERVICE_ACCOUNTS = frozenset({"argus-assistant"})


@dataclass(frozen=True)
class LiveCheck:
    """One live check of a person: its outcome, what it showed and when."""

    user_id: int
    outcome: Outcome
    provider: str
    checked_at: datetime
    kind: Kind = "person"
    capabilities: frozenset[str] = frozenset()
    kibana: frozenset[str] = frozenset()
    argus_uid: str | None = None  # Q-E2: metadata.argus_uid, the person behind the ELK name
    email: str | None = None

    @property
    def good(self) -> bool:
        return self.outcome == "ok" and self.kind == "person"

    def snapshot(self) -> dict[str, Any]:
        """What the decision stores and the web signs (JSON; times in UTC microseconds)."""
        return {
            "user_id": str(self.user_id),
            "outcome": self.outcome,
            "provider": self.provider,
            "kind": self.kind,
            "checked_at": iso(self.checked_at),
            "capabilities": sorted(self.capabilities),
            "kibana": sorted(self.kibana),
            "argus_uid": self.argus_uid,
            "email": self.email,
        }


class IdentityProvider(Protocol):
    """Checks a person now. ``conn`` is the request's own connection (the local provider reads
    the account through it; the ELK one only for the person's stored credential)."""

    name: str

    async def check(
        self, conn: AsyncConnection, user_id: int, *, purpose: Purpose
    ) -> LiveCheck: ...


Clock = Callable[[AsyncConnection], Awaitable[datetime]]
_UNSET = datetime(1970, 1, 1, tzinfo=UTC)  # a set-up answer's time, replaced at each check


async def database_clock(conn: AsyncConnection) -> datetime:
    """The database's clock, which every expiry and age is measured against."""
    now: datetime = (await conn.execute(text("SELECT clock_timestamp()"))).scalar_one()
    return now


class LocalIdentityProvider:
    """Local accounts (today's sign-in): the account's own capabilities, no Kibana privileges.
    A disabled account is denied; ARGUS's service accounts are never a person."""

    name = "local"

    def __init__(self, clock: Clock = database_clock) -> None:
        self._clock = clock

    async def check(self, conn: AsyncConnection, user_id: int, *, purpose: Purpose) -> LiveCheck:
        now = await self._clock(conn)
        row = (
            await conn.execute(
                text("SELECT username, disabled, capabilities, kind FROM users WHERE id = :id"),
                {"id": user_id},
            )
        ).first()
        if row is None or row.disabled:
            return LiveCheck(user_id, "denied", self.name, now)
        kind: Kind = (
            "person" if row.kind == "person" and row.username not in SERVICE_ACCOUNTS else
            "break_glass" if row.kind == "break_glass" else "service"
        )  # fmt: skip
        caps = frozenset(c.value for c in effective(row.capabilities or ()))
        return LiveCheck(user_id, "ok", self.name, now, kind, caps)


@dataclass
class FakeIdentityProvider:
    """A provider for tests and the local Kibana tier: each person's answer is set up in
    ``people`` (a missing person is denied); ``calls`` records every check."""

    people: dict[int, LiveCheck] = field(default_factory=dict)
    clock: Clock = database_clock
    name: str = "fake"
    calls: list[tuple[int, Purpose]] = field(default_factory=list)

    def allow(
        self,
        user_id: int,
        capabilities: frozenset[str],
        kibana: frozenset[str] = frozenset({UPDATE_CASE}),
        *,
        argus_uid: str | None = None,
        email: str | None = None,
        kind: Kind = "person",
    ) -> None:
        self.people[user_id] = LiveCheck(
            user_id, "ok", self.name, _UNSET, kind, capabilities, kibana,
            argus_uid or f"uid-{user_id}", email or f"user{user_id}@example.org",
        )  # fmt: skip

    def deny(self, user_id: int, outcome: Outcome = "denied") -> None:
        known = self.people.get(user_id)
        self.people[user_id] = (
            replace(known, outcome=outcome)
            if known is not None
            else LiveCheck(user_id, outcome, self.name, _UNSET)
        )

    async def check(self, conn: AsyncConnection, user_id: int, *, purpose: Purpose) -> LiveCheck:
        self.calls.append((user_id, purpose))
        now = await self.clock(conn)
        known = self.people.get(user_id)
        if known is None:
            return LiveCheck(user_id, "denied", self.name, now)
        return replace(known, checked_at=now, provider=self.name)


async def record(conn: AsyncConnection, check: LiveCheck, purpose: Purpose) -> int:
    """Store a check (only ``argus_approvals`` and the web's role may: the runtime role cannot
    vouch for a person). A denied check voids the person's earlier approvals."""
    params = {"u": check.user_id, "o": check.outcome, "p": check.provider, "w": purpose,
              "s": json.dumps(check.snapshot())}  # fmt: skip
    sql = "SELECT argus_identity_record(:u, :o, :p, :w, CAST(:s AS jsonb))"
    recorded: int = (await conn.execute(text(sql), params)).scalar_one()
    return recorded


_RECORD_FN = "argus_identity_record(bigint, text, text, text, jsonb)"


async def record_if_allowed(conn: AsyncConnection, check: LiveCheck, purpose: Purpose) -> bool:
    """:func:`record`, when this login may (the web's own login, a member of argus_approvals);
    the web running as the runtime login records nothing (it cannot approve either)."""
    allowed = (
        await conn.execute(
            text("SELECT has_function_privilege(to_regprocedure(:f), 'EXECUTE')"),
            {"f": _RECORD_FN},
        )
    ).scalar_one()
    if not allowed:
        return False
    await record(conn, check, purpose)
    return True


def same_person(a: Mapping[str, Any], b: Mapping[str, Any]) -> bool:
    """Whether two checks' snapshots may be one real person (plan §7.1: two people are two
    ``argus_uid``s with different e-mail addresses). Different accounts with the same
    ``argus_uid`` or the same e-mail address count as one."""
    if a.get("user_id") == b.get("user_id"):
        return True
    for key in ("argus_uid", "email"):
        left, right = a.get(key), b.get(key)
        if isinstance(left, str) and isinstance(right, str) and left.casefold() == right.casefold():
            return True
    return False
