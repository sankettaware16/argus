"""The cutover from local passwords to ELK sign-in (Q-E3, DQ18 (a); runbook ``elk-signin.md``).

The per-person steps, each a terminal command and an audit row:

1. **link** (``argus identity link`` / ``argus user link``): the local account gets its ELK
   username. Nothing else changes: ``users.id`` stays, so reviews, notes, approvals and the
   trail (``user:<handle>``) stay with the same person; the local password stays too.
2. **the person signs in through ELK** (Q-E2): the web finds the linked account and writes an
   audit ``login`` row with ``details.mode = 'elk'``.
3. **disable-local** (``argus identity disable-local``): only if that ``login`` row exists *after*
   the link, ARGUS drops the password hash. The database backs this up: it refuses a missing hash
   without ``elk_first_signin_at`` (``ck_users_password_or_elk``, 0036). Nothing was lost by
   dropping it that ELK does not give back: ``argus identity enable-local`` is the way back, with
   a new password, for a rollback to local mode.

``cutover status`` lists every account: linked or not, ELK sign-in seen or not, local password
on or off, and the reason an account stays local. The break-glass account (kind ``break_glass``)
is listed apart and is never touched here: it is off by design between windows and its password
is a one-time window password, not a local password (``argus break-glass``).

The functions take the caller's connection and transaction; the terminal commands are in
``argus.identity.cli`` and ``argus.web.cli``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus import site
from argus.config.settings import Settings
from argus.web import auth, breakglass
from argus.web.capabilities import Capability, effective
from argus.web.render import clock12

GOLD = Capability.ANSWER_GOLD.value
MIN_PASSWORD = 10
MAX_PASSWORD = 256  # the limits of ``auth.hash_password``


class CutoverError(Exception):
    """A refusal, in words for the terminal."""


def ist(when: datetime) -> str:
    local = when.astimezone(site.zone())
    return f"{local:%Y-%m-%d} {clock12(local)} {site.zone_label(local)}"


def name_problem(settings: Settings, elk_username: str) -> str | None:
    """Why ``elk_username`` can never be linked (a name the identity lane refuses before any
    request), or None."""
    from argus.identity.service import names

    return names(settings).refusal(elk_username)


# --------------------------------------------------------------------------- link


async def link(
    conn: AsyncConnection,
    username: str,
    elk_username: str,
    *,
    operator: str,
    different_person: bool = False,
) -> bool:
    """Tie the local account ``username`` to ``elk_username`` (audited ``user.link``). Returns
    whether ``answer_gold`` was taken away: in ELK mode only named owners answer gold items
    (DQ15), so linking removes it (Q-E2 review F8; ``argus user grant`` gives it back).

    An ELK name equal to *another* account's local handle is refused unless ``different_person``
    (the pair may be the wrong way round: that other person's own sign-in would land here). An
    account linked outside the tool (no ``user.link`` row) can be linked again with the same
    name, which puts the link in the trail."""
    row = (
        await conn.execute(
            text(
                "SELECT id, kind, disabled, elk_username, capabilities FROM users"
                " WHERE username = :u FOR UPDATE"
            ),
            {"u": username},
        )
    ).first()
    if row is None:
        raise CutoverError(f"no account {username}")
    if row.kind != "person":
        raise CutoverError(f"{username} is not a person's account")
    if row.disabled:
        raise CutoverError(f"{username} is disabled")
    if row.elk_username is not None and (
        row.elk_username != elk_username or await _in_trail(conn, username)
    ):
        raise CutoverError(f"{username} is already linked to {row.elk_username!r}")
    taken = await conn.scalar(
        text(
            "SELECT username FROM users WHERE elk_username = :n AND frozen_at IS NULL AND id <> :id"
        ),
        {"n": elk_username, "id": row.id},
    )
    if taken is not None:
        raise CutoverError(f"{elk_username!r} is already linked to {taken}")
    other = await conn.scalar(
        text("SELECT username FROM users WHERE username = lower(:n) AND id <> :id"),
        {"n": elk_username, "id": row.id},
    )
    if other is not None and not different_person:
        raise CutoverError(
            f"{elk_username!r} is also the local name of another account ({other}): linking"
            f" {username} to it is right only if it really is {username}'s ELK name, and"
            f" {other}'s own ELK sign-in would land on {username}'s account. If that is"
            " intended, add --yes-different-person"
        )
    held = list(row.capabilities or [])
    kept = [c for c in held if c != GOLD]
    await conn.execute(
        text("UPDATE users SET elk_username = :n, realm = 'native',"
             " capabilities = CAST(:c AS text[]) WHERE id = :id"),
        {"n": elk_username, "c": kept, "id": row.id},
    )  # fmt: skip
    stripped = len(kept) != len(held)
    await auth.audit(
        conn, actor="cli", action="user.link", target_type="user", target_id=username,
        details={"by": operator, "elk": elk_username, "answer_gold_removed": stripped},
    )  # fmt: skip
    return stripped


async def _in_trail(conn: AsyncConnection, username: str) -> bool:
    return (
        await conn.scalar(
            text(
                "SELECT 1 FROM audit_events WHERE action = 'user.link' AND outcome = 'success'"
                " AND target_type = 'user' AND target_id = :u LIMIT 1"
            ),
            {"u": username},
        )
        is not None
    )


# --------------------------------------------------------------------------- the list


@dataclass(frozen=True)
class Account:
    username: str
    display_name: str
    kind: str
    elk_username: str | None
    disabled: bool
    password_on: bool
    linked_at: datetime | None  # the last ``user.link`` audit row
    elk_seen_at: datetime | None  # the first ELK ``login`` audit row after that link
    first_elk_signin_at: datetime | None  # users.elk_first_signin_at

    @property
    def outside(self) -> bool:
        """Linked without a ``user.link`` row (by hand): its sign-in cannot be dated against a
        link, so none counts."""
        return (
            self.kind == "person"
            and self.elk_username is not None
            and self.linked_at is None
            and self.password_on
        )

    @property
    def seen(self) -> datetime | None:
        """When this person's ELK sign-in was first seen (after the link for a linked account;
        at the first sign-in for an account that began with ELK and has no link row; never for
        an account linked outside the tool)."""
        if self.linked_at is None:
            return None if self.outside else self.first_elk_signin_at
        return self.elk_seen_at

    @property
    def state(self) -> str:
        if self.kind == "service":
            return "service"
        if self.disabled:
            return "closed"
        if self.elk_username is None:
            return "local"
        if not self.password_on:
            return "done"
        return "ready" if self.elk_seen_at is not None else "waiting"

    @property
    def reason(self) -> str:
        user = self.username
        if self.state == "waiting" and self.outside:
            return (
                "linked outside the tool: link again with the command:"
                f" argus identity link {user} --elk {self.elk_username}"
            )
        return {
            "service": "a service identity: it never signs in",
            "closed": "disabled: it cannot sign in at all",
            "local": f"not linked to an ELK account: argus identity link {user} --elk <name>",
            "waiting": "linked; waiting for their first ELK sign-in",
            "ready": f"signed in through ELK: argus identity disable-local {user}",
            "done": "signs in through ELK only",
        }[self.state]


_ACCOUNTS = """
SELECT u.username, u.display_name, u.kind, u.elk_username, u.disabled,
       u.password_hash IS NOT NULL AS password_on, u.elk_first_signin_at, l.at AS linked_at,
       (SELECT min(a.occurred_at) FROM audit_events a
         WHERE a.action = 'login' AND a.outcome = 'success' AND a.actor = 'user:' || u.username
           AND a.details->>'mode' = 'elk' AND a.occurred_at > l.at) AS elk_seen_at
  FROM users u
  LEFT JOIN LATERAL (
       SELECT max(occurred_at) AS at FROM audit_events
        WHERE action = 'user.link' AND outcome = 'success' AND target_type = 'user'
          AND target_id = u.username) l ON true
 WHERE u.kind <> 'break_glass'
 ORDER BY u.username
"""


async def accounts(conn: AsyncConnection) -> list[Account]:
    """Every account except break-glass, with what the audit trail says of its ELK sign-in."""
    rows = (await conn.execute(text(_ACCOUNTS))).all()
    return [
        Account(r.username, r.display_name, r.kind, r.elk_username, r.disabled, r.password_on,
                r.linked_at, r.elk_seen_at, r.elk_first_signin_at)
        for r in rows
    ]  # fmt: skip


@dataclass(frozen=True)
class Glass:
    """The emergency account, listed apart: never disabled by the cutover."""

    exists: bool
    open_until: datetime | None  # a window is open now
    last_on: datetime | None
    last_signin: datetime | None


async def glass(conn: AsyncConnection) -> Glass:
    exists = await conn.scalar(text("SELECT 1 FROM users WHERE kind = 'break_glass'")) is not None
    window = await breakglass.active(conn)
    on, seen = (
        await conn.execute(
            text(
                "SELECT max(occurred_at) FILTER (WHERE action = 'break_glass.on'),"
                " max(occurred_at) FILTER (WHERE action = 'break_glass.signin')"
                " FROM audit_events WHERE action IN ('break_glass.on', 'break_glass.signin')"
            )
        )
    ).one()
    return Glass(exists, None if window is None else window.expires_at, on, seen)


def render(people: list[Account], emergency: Glass, *, elk_mode: bool) -> list[str]:
    """The status as lines: a summary, one line per account (the reason it stays local last),
    then the service identities and the break-glass account apart."""
    persons = [p for p in people if p.kind == "person"]

    def count(state: str) -> int:
        return sum(p.state == state for p in persons)

    held = " (waits for web.elk_signin)" if count("ready") and not elk_mode else ""
    lines = [
        "ELK sign-in is "
        + ("ON" if elk_mode else "OFF (web.elk_signin): local passwords are in use"),
        f"{len(persons)} account(s): {count('done')} ELK only, {count('ready')} ready to switch"
        f" off{held}, {count('waiting')} waiting for a first ELK sign-in,"
        f" {count('local')} not linked, {count('closed')} disabled",
    ]  # fmt: skip
    if persons:
        width = max(len(p.username) for p in persons)
        wide = max(len(p.elk_username or "-") for p in persons)
        for p in persons:
            seen = ist(p.seen) if p.seen else "not yet"
            lines.append(
                f"  {p.username:<{width}}  ELK {(p.elk_username or '-'):<{wide}}"
                f"  linked {'yes' if p.elk_username else 'no ':<3}"
                f"  ELK sign-in {seen:<24}  local password {'on ' if p.password_on else 'off'}"
                f"  {p.reason}"
            )  # fmt: skip
    for p in people:
        if p.kind != "person":
            lines.append(f"  {p.username} ({p.kind}): {p.reason}")
    lines.append("Break-glass (never disabled here; `argus break-glass`):")
    if not emergency.exists:
        lines.append("  no account yet: it is made when the first window is opened")
    else:
        now = f"ON until {ist(emergency.open_until)}" if emergency.open_until else "off"
        used = f"last window {ist(emergency.last_on)}" if emergency.last_on else "never opened"
        seen = (
            f"last sign-in {ist(emergency.last_signin)}" if emergency.last_signin else "never used"
        )
        lines.append(f"  {breakglass.NAME}: {now}; {used}; {seen}")
    return lines


# --------------------------------------------------------------------------- disable / enable


async def disable_local(
    conn: AsyncConnection, username: str, *, elk_mode: bool, operator: str
) -> bool:
    """Drop ``username``'s local password hash, only after their ELK sign-in worked at least once
    since the link (audited ``user.local_disabled``). Returns False if it was already off.

    Refuses the break-glass account and service identities, an account that is not linked, one
    whose link is not in the trail, one with no ELK ``login`` row after the link, and any call
    while ELK sign-in is off in this configuration (the person would have no way in). The
    person's open local sessions end (a rollback to local mode would otherwise bring them
    back)."""
    row = (
        await conn.execute(
            text(
                "SELECT id, kind, disabled, elk_username, password_hash IS NOT NULL AS password_on,"
                " elk_first_signin_at FROM users WHERE username = :u FOR UPDATE"
            ),
            {"u": username},
        )
    ).first()
    if row is None:
        raise CutoverError(f"no account {username}")
    if row.kind == "break_glass" or username == breakglass.NAME:
        raise CutoverError(
            f"{username} is the break-glass account: it is never disabled by the cutover"
            " (`argus break-glass off` closes its window)"
        )
    if row.kind != "person":
        raise CutoverError(f"{username} is not a person's account (it has no local sign-in)")
    if row.disabled:
        raise CutoverError(f"{username} is disabled: nothing to switch off")
    if row.elk_username is None:
        raise CutoverError(
            f"{username} is not linked to an ELK account: argus identity link {username} --elk"
            " <name>"
        )
    if not row.password_on:
        return False
    if not elk_mode:
        raise CutoverError(
            "web.elk_signin is off here: without a local password the person could not sign in"
            " at all. Switch ELK sign-in on first (runbooks/elk-signin.md)"
        )
    mine = next(a for a in await accounts(conn) if a.username == username)
    if mine.linked_at is None:
        raise CutoverError(f"the link of {username} is not in the audit trail: link it again")
    if mine.elk_seen_at is None or row.elk_first_signin_at is None:
        raise CutoverError(
            f"{username} has not signed in through ELK since the link ({ist(mine.linked_at)}):"
            " the local password stays until that sign-in has worked"
        )
    await conn.execute(text("UPDATE users SET password_hash = NULL WHERE id = :id"),
                       {"id": row.id})  # fmt: skip
    await conn.execute(
        text("UPDATE user_sessions SET ended_at = now(), credential = NULL,"
             " ended_why = 'local_password_disabled'"
             " WHERE user_id = :id AND ended_at IS NULL AND mode = 'local'"),
        {"id": row.id},
    )  # fmt: skip
    await auth.audit(
        conn, actor="cli", action="user.local_disabled", target_type="user", target_id=username,
        details={"by": operator, "elk": row.elk_username, "elk_signin_seen": mine.elk_seen_at},
    )  # fmt: skip
    return True


async def enable_local(
    conn: AsyncConnection, username: str, password: str, *, operator: str
) -> None:
    """The way back for a rollback to local mode: a new local password for a person whose was
    dropped (audited ``user.local_enabled``). It never replaces a password that is on."""
    if not MIN_PASSWORD <= len(password) <= MAX_PASSWORD:
        raise CutoverError(
            f"the password needs at least {MIN_PASSWORD} characters, at most {MAX_PASSWORD}"
        )
    row = (
        await conn.execute(
            text(
                "SELECT id, kind, disabled, password_hash IS NOT NULL AS password_on,"
                " capabilities FROM users WHERE username = :u FOR UPDATE"
            ),
            {"u": username},
        )
    ).first()
    if row is None:
        raise CutoverError(f"no account {username}")
    if row.kind != "person":
        raise CutoverError(f"{username} is not a person's account")
    if row.disabled:
        raise CutoverError(f"{username} is disabled")
    if row.password_on:
        raise CutoverError(f"{username} still has a local password")
    if Capability.VIEW not in effective(row.capabilities or ()):
        raise CutoverError(
            f"{username} began with ELK and has no local access (no capabilities of its own): a"
            " local password would still be refused at sign-in. Nothing was changed"
        )
    await conn.execute(text("UPDATE users SET password_hash = :h WHERE id = :id"),
                       {"h": auth.hash_password(password), "id": row.id})  # fmt: skip
    await auth.audit(conn, actor="cli", action="user.local_enabled", target_type="user",
                     target_id=username, details={"by": operator})  # fmt: skip
