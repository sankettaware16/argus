"""Break-glass (Q-E2, plan §7.2, DQ17): the one emergency account, for when ELK cannot be asked.

* **Off by default.** Switched on only at the host, by the person who holds it (the user, D-110):
  ``argus break-glass on`` asks for a typed reason, checks that the SIEM really is down (or takes a
  typed override), opens a window of at most 4 hours and prints a one-time password once.
* **One-time:** the first successful sign-in uses the password up; its session ends with the
  window at the latest. The account is ``break-glass`` (kind ``break_glass``, never a person: it
  never approves).
* **Only view and review** (``capabilities.BREAK_GLASS``): its reviews are never written back to
  Kibana (``review_events.kibana_ok`` false), it approves nothing, opens no case, changes no
  setting. Every page shows a banner while it is in use.
* **Fully audited:** the window (who, why, how long, override or not), every sign-in and refusal,
  its end.

The sign-in itself is :class:`argus.web.signin.ElkSignIn`; this module is the account and the
window.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.web import auth

NAME = "break-glass"  # the account's login name (an ARGUS handle, never an ELK name)
DISPLAY_NAME = "Break-glass (emergency)"
LONGEST = timedelta(hours=4)
MIN_REASON = 10
PASSWORD_BYTES = 18  # 144 bits, 24 characters


_ACTIVE = (
    "SELECT b.id, b.user_id, b.enabled_at, b.expires_at, b.consumed_at, u.password_hash"
    " FROM break_glass b JOIN users u ON u.id = b.user_id"
    " WHERE b.ended_at IS NULL AND b.expires_at > clock_timestamp()"
)
_ACTIVE_LOCKED = _ACTIVE + " FOR UPDATE OF b"


@dataclass(frozen=True)
class Window:
    id: int
    user_id: int
    enabled_at: datetime
    expires_at: datetime
    consumed_at: datetime | None
    password_hash: str | None


async def active(conn: AsyncConnection, *, lock: bool = False) -> Window | None:
    """The open window, if any: not ended, not past its end (the database's clock)."""
    row = (await conn.execute(text(_ACTIVE_LOCKED if lock else _ACTIVE))).first()
    if row is None:
        return None
    return Window(row.id, row.user_id, row.enabled_at, row.expires_at, row.consumed_at,
                  row.password_hash)  # fmt: skip


async def consume(conn: AsyncConnection, window: Window) -> bool:
    """Use the one-time password up; False if another sign-in did first."""
    done = await conn.execute(
        text(
            "UPDATE break_glass SET consumed_at = clock_timestamp()"
            " WHERE id = :id AND consumed_at IS NULL"
        ),
        {"id": window.id},
    )
    return bool(done.rowcount)


async def end_expired(conn: AsyncConnection, *, by: str) -> int:
    """Close the windows that ran out without anyone switching them off (``ended_at`` is what
    keeps the one-open-at-a-time rule; an expired window that is never ended would refuse every
    later window). Returns how many were closed; audited."""
    done = await conn.execute(
        text(
            "UPDATE break_glass SET ended_at = expires_at WHERE ended_at IS NULL"
            " AND expires_at <= clock_timestamp() RETURNING id"
        )
    )
    closed = len(done.all())
    if closed:
        await auth.audit(
            conn, actor=f"host:{by}", action="break_glass.expired", target_type="user",
            target_id=NAME, details={"windows": closed},
        )  # fmt: skip
    return closed


def new_password() -> str:
    return secrets.token_urlsafe(PASSWORD_BYTES)


async def open_window(
    conn: AsyncConnection,
    *,
    reason: str,
    enabled_by: str,
    minutes: int,
    override: bool,
) -> tuple[str, datetime]:
    """Open the window and make its password; returns (the password, when the window ends).
    Refuses (ValueError) a short reason, a window over 4 hours, or one already open."""
    reason = reason.strip()
    if len(reason) < MIN_REASON:
        raise ValueError(f"the reason needs at least {MIN_REASON} characters: say what happened")
    if len(reason) > 500:
        raise ValueError("the reason has at most 500 characters")
    if not 1 <= minutes <= LONGEST.total_seconds() // 60:
        raise ValueError("a window is 1 to 240 minutes")
    await end_expired(conn, by=enabled_by)
    if await active(conn) is not None:
        raise ValueError("break-glass is already on: switch it off first")
    password = new_password()
    hashed = auth.hash_password(password)
    user = await conn.scalar(text("SELECT id FROM users WHERE username = :u"), {"u": NAME})
    if user is None:
        user = (
            await conn.execute(
                text(
                    "INSERT INTO users (username, display_name, password_hash, kind, realm,"
                    " capabilities) VALUES (:u, :d, :h, 'break_glass', 'local',"
                    " CAST('{view,review}' AS text[])) RETURNING id"
                ),
                {"u": NAME, "d": DISPLAY_NAME, "h": hashed},
            )
        ).scalar_one()
    else:
        await conn.execute(
            text("UPDATE users SET password_hash = :h, disabled = false WHERE id = :id"),
            {"h": hashed, "id": user},
        )
    ends = (
        await conn.execute(
            text(
                "INSERT INTO break_glass (user_id, reason, enabled_by, expires_at, override)"
                " VALUES (:u, :r, :by, now() + make_interval(mins => :m), :o)"
                " RETURNING expires_at"
            ),
            {"u": user, "r": reason, "by": enabled_by, "m": minutes, "o": override},
        )
    ).scalar_one()
    await auth.audit(
        conn, actor=f"host:{enabled_by}", action="break_glass.on", target_type="user",
        target_id=NAME,
        details={"reason": reason, "minutes": minutes, "override": override},
    )  # fmt: skip
    return password, ends


async def close_window(conn: AsyncConnection, *, by: str) -> bool:
    """Switch break-glass off: the window ends, the account is disabled, its sessions end.
    True if a window was open."""
    ended = await conn.execute(
        text("UPDATE break_glass SET ended_at = now() WHERE ended_at IS NULL RETURNING id")
    )
    was_open = ended.first() is not None
    await conn.execute(text("UPDATE users SET disabled = true WHERE username = :u"), {"u": NAME})
    await conn.execute(
        text(
            "UPDATE user_sessions SET ended_at = now(), credential = NULL,"
            " ended_why = 'break_glass_off' WHERE ended_at IS NULL AND mode = 'break_glass'"
        )
    )
    await auth.audit(conn, actor=f"host:{by}", action="break_glass.off", target_type="user",
                     target_id=NAME, details={"was_open": was_open})  # fmt: skip
    return was_open
