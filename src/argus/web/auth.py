"""Reviewer accounts and sessions (plan §9.1, D-052; Phase 3 §7.2, Q-A1, Q-E2): argon2id
passwords; a session is a random token kept only as its SHA-256, with an idle and an absolute
expiry, its own CSRF token, and the time its person last confirmed their password (step-up).

A session has a mode: ``local`` (a password checked against the account's hash), ``elk`` (the
person's own ELK account, its capabilities a snapshot that ``argus.web.elk`` keeps in step) or
``break_glass`` (the emergency account: view and review only)."""

from __future__ import annotations

import contextlib
import hashlib
import re
import secrets
from collections.abc import Callable, Collection, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from argus.db.audit import record_audit
from argus.web.capabilities import (
    BREAK_GLASS,
    LOCAL_DEFAULT,
    Capability,
    effective,
    ordered,
)

HASHER = PasswordHasher()  # argon2id with the library's current defaults
_DUMMY = HASHER.hash("argus-dummy-password")  # equal work for an unknown user
SEEN_EVERY = timedelta(minutes=1)  # how often a session's last_seen_at is written
USERNAME = re.compile(r"[a-z][a-z0-9_.-]{1,31}")  # as the users table's check constraint
DEFAULT_ABSOLUTE = timedelta(hours=8)  # a session's longest life (plan §7.2, DQ17)
STEP_UP_FAILURES = 3  # failed step-ups that end a session (plan §7.2)


def shown_name(username: str) -> str:
    """A login name as the audit trail may record it (never arbitrary input)."""
    return username if USERNAME.fullmatch(username) else "(not a valid name)"


async def one_at_a_time(conn: AsyncConnection, name_key: str, client: str) -> bool:
    """Take this name's and this client's sign-in locks until the transaction ends: password
    checks for one name (``name_key``: the name as the audit trail records it), or from one
    client, happen one after another, each refusal committed before the next check counts them,
    so a burst sent at once gets no more guesses than the throttle allows (Q-A1 review F4).

    The locks are **try-locks**: False when either is held, and the caller answers "busy" at
    once. A request that waited for a lock would hold a pooled connection while it waited, and a
    burst of sign-ins for one name would take every connection from the pages (Q-E2 review
    F11). Always the name first, then the client; the locks are never waited for, so no two
    requests wait for each other."""
    for key in (f"argus.signin.name:{name_key}", f"argus.signin.client:{client}"):
        got = await conn.scalar(
            text("SELECT pg_try_advisory_xact_lock(hashtextextended(:k, 0))"), {"k": key}
        )
        if not got:
            return False
    return True


@dataclass(frozen=True)
class Reviewer:
    """A person's live session: who they are, what they may do, and the session's times."""

    user_id: int
    username: str
    display_name: str
    csrf_token: str
    previous_seen_at: datetime | None  # end of the reviewer's previous session ("since")
    capabilities: frozenset[Capability] = field(default=frozenset())
    token_hash: str = ""
    last_seen_at: datetime | None = None
    expires_at: datetime | None = None  # the absolute end
    stepped_up_at: datetime | None = None
    mode: str = "local"  # local | elk | break_glass
    elk_username: str | None = None
    snapshot_at: datetime | None = None  # ELK: when the capabilities were last checked
    unverified_since: datetime | None = None  # ELK: ARGUS could not verify the person since
    unverified_why: str | None = None  # "outage" (the SIEM) or "refused" (ARGUS's own limits)
    no_custody: bool = False  # ELK: an admin account; there is no password to re-check with

    def can(self, capability: Capability | str) -> bool:
        return capability in self.capabilities

    @property
    def elk(self) -> bool:
        return self.mode == "elk"

    @property
    def kibana_ok(self) -> bool:
        """Whether a review made now may be written back to Kibana: the person's own ELK check
        showed the alert-status privileges (``review``) and ARGUS can still verify them. Never in
        an outage, after ARGUS's own refusal, in break-glass or in local mode."""
        return (
            self.mode == "elk"
            and self.unverified_since is None
            and (Capability.REVIEW in self.capabilities)
        )

    def named(self) -> list[str]:
        """Its capabilities' names, in their declared order (for pages and the API)."""
        return [c.value for c in ordered(self.capabilities)]


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def hash_password(password: str) -> str:
    if not 10 <= len(password) <= 256:
        raise ValueError("a password has 10 to 256 characters")
    return HASHER.hash(password)


async def add_user(
    conn: AsyncConnection,
    username: str,
    display_name: str,
    password: str,
    capabilities: Iterable[Capability] | None = None,
    kind: str = "person",
) -> int:
    """A local account; without ``capabilities``, what any reviewer could always do."""
    granted = [c.value for c in ordered(LOCAL_DEFAULT if capabilities is None else capabilities)]
    row = await conn.execute(
        text(
            "INSERT INTO users (username, display_name, password_hash, capabilities, kind)"
            " VALUES (:u, :d, :h, CAST(:c AS text[]), :k) RETURNING id"
        ),
        {"u": username, "d": display_name, "h": hash_password(password), "c": granted, "k": kind},
    )
    user_id: int = row.scalar_one()
    return user_id


@dataclass(frozen=True)
class Checked:
    """A password check: the account when the password is right and it may use ARGUS."""

    user_id: int | None
    why: str | None  # why it was refused: "no access" (the password was right), else None


async def check_password(conn: AsyncConnection, username: str, password: str) -> Checked:
    """Whether ``password`` is this enabled account's, with the same hashing work for a name
    that does not exist or cannot exist. An account without the ``view`` capability is
    refused like a wrong password (no password oracle for it)."""
    if not USERNAME.fullmatch(username):
        with contextlib.suppress(VerificationError, InvalidHashError):
            HASHER.verify(_DUMMY, password)
        return Checked(None, None)
    row = (
        await conn.execute(
            text(
                "SELECT id, password_hash, capabilities FROM users"
                " WHERE username = :u AND NOT disabled AND kind = 'person'"
            ),
            {"u": username},
        )
    ).first()
    stored = row.password_hash if row is not None and row.password_hash else _DUMMY
    try:
        HASHER.verify(stored, password)
    except (VerificationError, InvalidHashError):
        return Checked(None, None)
    if row is not None and not row.password_hash:  # an account that signs in through ELK only
        return Checked(None, None)
    if row is None:
        return Checked(None, None)
    if Capability.VIEW not in effective(row.capabilities or ()):
        return Checked(None, "no access")
    return Checked(int(row.id), None)


@dataclass(frozen=True)
class Granted:
    """What a sign-in other than a local password gives its session (Q-E2): the mode, and for
    an ELK session the capabilities ELK showed, when, and the capability map's version."""

    mode: str = "local"  # local | elk | break_glass
    snapshot: frozenset[Capability] | None = None  # ELK: what the check showed
    checked_at: datetime | None = None
    map_version: int | None = None
    no_custody: bool = False  # an admin account: there is no password to keep
    expires_at: datetime | None = None  # an earlier end than the absolute one (break-glass)


Seal = Callable[[str, str], bytes]
"""(token, token's hash) -> the sealed credential to store with the session."""


def capabilities_of(
    mode: str, snapshot: Iterable[object] | None, grants: Iterable[object] | None
) -> frozenset[Capability]:
    """What a session may do: an ELK session, its last snapshot (and the gold-key owners ARGUS
    names); break-glass, view and review; a local one, what its account has."""
    from argus.web.capabilities import elk_capabilities

    if mode == "elk":
        return elk_capabilities(snapshot or (), grants or ())
    if mode == "break_glass":
        return BREAK_GLASS
    return effective(grants or ())


async def start(
    conn: AsyncConnection,
    user_id: int,
    now: datetime,
    absolute: timedelta = DEFAULT_ABSOLUTE,
    *,
    granted: Granted | None = None,
    seal: Seal | None = None,
) -> tuple[str, Reviewer]:
    """A new session for an account whose password was just checked: (token, reviewer).
    ``granted`` makes an ELK or break-glass session; ``seal`` stores the person's credential
    sealed under this session's token (custody)."""
    given = granted or Granted()
    row = (
        await conn.execute(
            text(
                "SELECT u.username, u.display_name, u.capabilities, u.elk_username,"
                " (SELECT max(last_seen_at) FROM user_sessions s WHERE s.user_id = u.id)"
                " AS previous FROM users u WHERE u.id = :id"
            ),
            {"id": user_id},
        )
    ).one()
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    expires = now + absolute
    if given.expires_at is not None:
        expires = min(expires, given.expires_at)
    hashed = token_hash(token)
    sealed = seal(token, hashed) if seal is not None else None
    snapshot = None if given.snapshot is None else [c.value for c in ordered(given.snapshot)]
    if given.mode == "local":  # today's insert: the columns the runtime login may write
        await conn.execute(
            text(
                "INSERT INTO user_sessions (token_hash, user_id, csrf_token, last_seen_at,"
                " previous_seen_at, expires_at) VALUES (:t, :id, :c, :now, :prev, :exp)"
            ),
            {"t": hashed, "id": user_id, "c": csrf, "now": now, "prev": row.previous,
             "exp": expires},
        )  # fmt: skip
    else:
        await conn.execute(
            text(
                "INSERT INTO user_sessions (token_hash, user_id, csrf_token, last_seen_at,"
                " previous_seen_at, expires_at, mode, capabilities, checked_at, map_version,"
                " credential, no_custody) VALUES (:t, :id, :c, :now, :prev, :exp, :mode,"
                " CAST(:caps AS text[]), :checked, :map, :cred, :nc)"
            ),
            {"t": hashed, "id": user_id, "c": csrf, "now": now, "prev": row.previous,
             "exp": expires, "mode": given.mode, "caps": snapshot, "checked": given.checked_at,
             "map": given.map_version, "cred": sealed, "nc": given.no_custody},
        )  # fmt: skip
    reviewer = Reviewer(
        user_id,
        row.username,
        row.display_name,
        csrf,
        row.previous,
        capabilities_of(given.mode, given.snapshot, row.capabilities),
        hashed,
        now,
        expires,
        None,
        given.mode,
        row.elk_username,
        given.checked_at,
        None,
        None,
        given.no_custody,
    )
    return token, reviewer


async def login(
    conn: AsyncConnection,
    username: str,
    password: str,
    now: datetime,
    absolute: timedelta = DEFAULT_ABSOLUTE,
) -> tuple[str, Reviewer] | None:
    """A new session (token, reviewer) for the right password; None otherwise. A name that
    cannot exist is refused after the same hashing work as a wrong password."""
    checked = await check_password(conn, username, password)
    if checked.user_id is None:
        return None
    return await start(conn, checked.user_id, now, absolute)


async def session(
    conn: AsyncConnection,
    token: str,
    now: datetime,
    idle: timedelta,
    *,
    extend: bool = True,
    modes: Collection[str] | None = None,
) -> Reviewer | None:
    """The reviewer of a live session, or None: ended, idle longer than ``idle``, past its
    absolute end, its account disabled, or not of one of ``modes`` (the web's mode: a local
    session is no session once ELK sign-in is on, and the other way round). With ``extend`` (a
    person's own request, not a background one) the session is kept alive."""
    row = (
        await conn.execute(
            text(
                "SELECT s.token_hash, s.csrf_token, s.last_seen_at, s.previous_seen_at,"
                " s.expires_at, s.stepped_up_at, s.mode, s.capabilities AS snapshot,"
                " s.checked_at, s.unverified_since, s.unverified_why, s.no_custody,"
                " u.id, u.username, u.display_name, u.capabilities, u.elk_username"
                " FROM user_sessions s JOIN users u ON u.id = s.user_id"
                " WHERE s.token_hash = :t AND s.ended_at IS NULL AND NOT u.disabled"
            ),
            {"t": token_hash(token)},
        )
    ).first()
    if row is None or now - row.last_seen_at > idle or now > row.expires_at:
        return None
    if modes is not None and row.mode not in modes:
        return None
    seen = row.last_seen_at
    if extend and now - row.last_seen_at >= SEEN_EVERY:
        await conn.execute(
            text("UPDATE user_sessions SET last_seen_at = :now WHERE token_hash = :t"),
            {"now": now, "t": row.token_hash},
        )
        seen = now
    return Reviewer(row.id, row.username, row.display_name, row.csrf_token, row.previous_seen_at,
                    capabilities_of(row.mode, row.snapshot, row.capabilities), row.token_hash,
                    seen, row.expires_at, row.stepped_up_at, row.mode, row.elk_username,
                    row.checked_at, row.unverified_since, row.unverified_why,
                    row.no_custody)  # fmt: skip


async def logout(conn: AsyncConnection, token: str, now: datetime) -> None:
    await end(conn, token_hash(token), now, "signed_out")


async def end(conn: AsyncConnection, hashed: str, now: datetime, why: str | None = None) -> None:
    """End the session stored as ``hashed`` (a no-op if it has ended). Its sealed credential
    is wiped with it."""
    await conn.execute(
        text(
            "UPDATE user_sessions SET ended_at = :now, credential = NULL,"
            " ended_why = coalesce(:why, ended_why)"
            " WHERE token_hash = :t AND ended_at IS NULL"
        ),
        {"now": now, "t": hashed, "why": why},
    )


async def wipe_stale_credentials(conn: AsyncConnection, now: datetime, idle: timedelta) -> int:
    """Wipe the sealed credential of every session that is over (ended, past its absolute end,
    or idle longer than ``idle``): without the cookie it was useless, and now it is gone.
    Returns how many were wiped."""
    done = await conn.execute(
        text(
            "UPDATE user_sessions SET credential = NULL WHERE credential IS NOT NULL"
            " AND (ended_at IS NOT NULL OR expires_at < :now OR last_seen_at < :cut)"
        ),
        {"now": now, "cut": now - idle},
    )
    return int(done.rowcount or 0)


async def stepped_up(conn: AsyncConnection, hashed: str, now: datetime) -> None:
    """The session's person confirmed their password: record when, and forget failures."""
    await conn.execute(
        text(
            "UPDATE user_sessions SET stepped_up_at = :now, stepup_failures = 0"
            " WHERE token_hash = :t AND ended_at IS NULL"
        ),
        {"now": now, "t": hashed},
    )


async def step_up_open(conn: AsyncConnection, hashed: str) -> bool:
    """Whether the session may still try a step-up (live, fewer than three failures), its row
    locked until the transaction ends: step-ups of one session happen one after another, and
    each sees what the one before it committed (Q-A1 review F4)."""
    failures = await conn.scalar(
        text(
            "SELECT stepup_failures FROM user_sessions WHERE token_hash = :t"
            " AND ended_at IS NULL FOR UPDATE"
        ),
        {"t": hashed},
    )
    return failures is not None and int(failures) < STEP_UP_FAILURES


async def step_up_failed(conn: AsyncConnection, hashed: str, now: datetime) -> bool:
    """A wrong password at step-up; True when that ended the session (the third)."""
    failures = await conn.scalar(
        text(
            "UPDATE user_sessions SET stepup_failures = stepup_failures + 1"
            " WHERE token_hash = :t AND ended_at IS NULL RETURNING stepup_failures"
        ),
        {"t": hashed},
    )
    if failures is not None and int(failures) >= STEP_UP_FAILURES:
        await end(conn, hashed, now)
        return True
    return failures is None


async def password_is(conn: AsyncConnection, user_id: int, password: str) -> bool:
    """Whether ``password`` is this enabled account's (step-up), with the same hashing work
    when the account is gone or disabled."""
    stored = await conn.scalar(
        text("SELECT password_hash FROM users WHERE id = :id AND NOT disabled"), {"id": user_id}
    )
    try:
        HASHER.verify(stored if isinstance(stored, str) else _DUMMY, password)
    except (VerificationError, InvalidHashError):
        return False
    return isinstance(stored, str)


def same_secret(expected: str, presented: str | None) -> bool:
    """A constant-time comparison of a secret with what a request presented: any text,
    non-ASCII included (``secrets.compare_digest`` refuses non-ASCII strings)."""
    if presented is None:
        return False
    return secrets.compare_digest(
        expected.encode("utf-8", "replace"), presented.encode("utf-8", "replace")
    )


def csrf_ok(reviewer: Reviewer, presented: str | None) -> bool:
    return same_secret(reviewer.csrf_token, presented)


async def audit(conn: AsyncConnection, **event: Any) -> None:
    """``record_audit`` (redaction, limits) in the caller's connection and transaction."""
    session = AsyncSession(bind=conn)
    try:
        await record_audit(session, **event)  # it flushes into the connection
    finally:
        await session.close()
