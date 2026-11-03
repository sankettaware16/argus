"""The one sign-in (Q-E2, plan §7.2): every way in (``/signin``, ``/login``, ``/api/login``)
goes through :func:`attempt`: one at a time per name and per client (a second is answered "busy"
at once, never queued), the one throttle (:mod:`argus.web.throttle`), one identity provider, one
audit trail.

* :class:`LocalSignIn` checks the password against the account's argon2id hash (today's mode,
  and the rollback);
* :class:`ElkSignIn` checks the person's own ELK account against Elasticsearch through the
  identity lane (``whoami`` and ``verify``), finds or creates their account, and hands the
  session the capabilities ELK showed and, under DQ16 (a), their credential sealed for
  re-checks; in ELK mode the emergency account signs in here too (:mod:`argus.web.breakglass`).

A provider says what happened: ``Authenticated`` (an account and what its session gets),
``Refused`` (``counts``: the credential itself was refused; ARGUS's other refusals never count)
or ``Unavailable`` (ARGUS could not ask). :func:`attempt` writes the audit rows and the throttle
reads them, so what is counted and what is only recorded is decided in one place.

The caller answers every failure the same way, a fixed time after the request arrived
(``web.failure_delay_s``), after the transaction is over (``app``), so neither the time nor the
words show whether a name exists.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal, Protocol

from argon2.exceptions import InvalidHashError, VerificationError
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.cases import identity as cases_identity
from argus.config.settings import WebSettings
from argus.identity.lane import (
    IdentityDeniedError,
    IdentityRefusedError,
    IdentityUnavailableError,
    Kind,
)
from argus.identity.names import Credential
from argus.web import auth, breakglass, throttle
from argus.web.custody import Custody
from argus.web.elk import Elk, kibana_privileges

SIGNIN_TOTAL = timedelta(seconds=12)  # a sign-in's two checks, their admissions, all told
HANDLE = re.compile(r"[a-z][a-z0-9_.-]{1,31}")
# ARGUS's own identities: no ELK account may sign in as one, and no handle is made of one
SERVICE_HANDLES = frozenset({"argus", "argus-assistant", breakglass.NAME})
MAX_DEVICES = 20  # browsers remembered per person
DEVICE_SHAPE = re.compile(r"[A-Za-z0-9_-]{43}")
Status = Literal["signed_in", "wrong", "locked", "unavailable"]


@dataclass(frozen=True)
class Authenticated:
    user_id: int
    granted: auth.Granted
    password: SecretStr | None = None  # the credential to keep sealed (custody), or none
    elk_username: str | None = None
    check: cases_identity.LiveCheck | None = None  # the sign-in's check, recorded with the row


@dataclass(frozen=True)
class Refused:
    why: str | None  # a fixed code for the audit trail; None: a plain wrong password
    counts: bool  # the credential was refused (Elasticsearch's 401/403, or the local hash)


@dataclass(frozen=True)
class Unavailable:
    why: str


Result = Authenticated | Refused | Unavailable


class SignInProvider(Protocol):
    async def authenticate(
        self, conn: AsyncConnection, username: str, password: str, *, device: bool
    ) -> Result: ...


@dataclass(frozen=True)
class Outcome:
    status: Status
    token: str | None = None
    reviewer: auth.Reviewer | None = None
    device_token: str | None = None  # a new device cookie to set


# --------------------------------------------------------------------------- providers


class LocalSignIn:
    """Local accounts: the password against the account's hash. An account without access
    (no ``view``) is refused like a wrong password, and does not count."""

    name = "local"

    async def authenticate(
        self, conn: AsyncConnection, username: str, password: str, *, device: bool
    ) -> Result:
        checked = await auth.check_password(conn, username, password)
        if checked.user_id is None:
            return Refused(checked.why, counts=checked.why is None)
        return Authenticated(checked.user_id, auth.Granted())


class ElkSignIn:
    """The person's own ELK account (plan §7.2 steps 2 to 6)."""

    name = "elk"

    def __init__(self, elk: Elk, clock: Callable[[], datetime]) -> None:
        self.elk = elk
        self.clock = clock

    async def authenticate(
        self, conn: AsyncConnection, username: str, password: str, *, device: bool
    ) -> Result:
        if username == breakglass.NAME:
            return await self._break_glass(conn, password)
        if username.casefold() in SERVICE_HANDLES:  # ARGUS's own identities: 0 requests
            return Refused("service_name", counts=False)
        signins = self.elk._signins
        if signins.locked():
            return Unavailable("busy")
        async with signins:
            return await self._check(conn, username, password)

    async def _break_glass(self, conn: AsyncConnection, password: str) -> Result:
        """The emergency account: only while its window is open, once, view and review."""
        window = await breakglass.active(conn, lock=True)
        stored = window.password_hash if window is not None and window.password_hash else None
        try:  # the same hashing work whether or not a window is open
            auth.HASHER.verify(stored or auth._DUMMY, password)
        except (VerificationError, InvalidHashError):
            # a wrong guess never counts (the password is one-time and has 144 bits): a count
            # would let a stranger lock the holder out, and the lock's answer would show whether
            # a window is open
            return Refused("wrong_password" if window else "no_window", counts=False)
        if window is None or stored is None:
            return Refused("no_window", counts=False)
        if window.consumed_at is not None or not await breakglass.consume(conn, window):
            return Refused("already_used", counts=False)
        await auth.audit(conn, actor=f"user:{breakglass.NAME}", action="break_glass.signin",
                         target_type="break_glass", target_id=str(window.id))  # fmt: skip
        return Authenticated(
            window.user_id,
            auth.Granted(mode="break_glass", expires_at=window.expires_at),
        )

    async def _check(self, conn: AsyncConnection, username: str, password: str) -> Result:
        credential = Credential(username, SecretStr(password))
        deadline = self.elk.lane_clock() + SIGNIN_TOTAL
        try:
            checked = await asyncio.wait_for(
                self.elk.lane.check(credential, deadline=deadline, kind=Kind.SIGNIN),
                SIGNIN_TOTAL.total_seconds(),
            )
        except IdentityDeniedError as exc:
            return Refused(exc.reason, counts=exc.counts)
        except IdentityRefusedError as exc:
            return Refused(exc.reason, counts=False)
        except IdentityUnavailableError as exc:
            return Unavailable(exc.reason)
        except TimeoutError:
            return Unavailable("timeout")
        return await self._account(conn, checked, password)

    async def _account(self, conn: AsyncConnection, checked, password: str) -> Result:  # type: ignore[no-untyped-def]
        """Find, bind, freeze or create the account behind a good check (plan §7.2 step 6)."""
        identity, access = checked.identity, checked.access
        now = self.clock()
        found = (
            await conn.execute(
                text(
                    "SELECT id, kind, disabled, argus_uid, capabilities FROM users"
                    " WHERE elk_username = :n AND frozen_at IS NULL FOR UPDATE"
                ),
                {"n": identity.username},
            )
        ).first()
        if found is not None and found.argus_uid not in (None, identity.argus_uid):
            # a new argus_uid behind a known name is a new person: the old account is frozen
            # (disabled, so its approvals stop counting) and its sessions end
            await freeze(conn, found.id, now)
            await auth.audit(conn, actor="web", action="user.frozen", target_type="user",
                             target_id=str(found.id),
                             details={"why": "a new argus_uid behind the same name"})  # fmt: skip
            found = None
        if found is not None:
            if found.kind != "person":
                return Refused("not_a_person", counts=False)
            if found.disabled:
                return Refused("disabled", counts=False)
            if found.argus_uid is None:
                taken = await conn.scalar(
                    text("SELECT 1 FROM users WHERE argus_uid = :u"), {"u": identity.argus_uid}
                )
                if taken is not None:
                    return Refused("uid_in_use", counts=False)
            await conn.execute(
                text(
                    "UPDATE users SET argus_uid = :u, email = coalesce(:e, email),"
                    " display_name = coalesce(:d, display_name),"
                    " last_good_check_at = :now,"
                    " elk_first_signin_at = coalesce(elk_first_signin_at, :now) WHERE id = :id"
                ),
                {"u": identity.argus_uid, "e": identity.email, "now": now, "id": found.id,
                 "d": identity.full_name},
            )  # fmt: skip
            user_id = int(found.id)
        else:
            taken = await conn.scalar(
                text("SELECT 1 FROM users WHERE argus_uid = :u"), {"u": identity.argus_uid}
            )
            if taken is not None:
                return Refused("uid_in_use", counts=False)
            user_id = await create_account(conn, identity, now)
        granted = auth.Granted(
            mode="elk", snapshot=access.capabilities, checked_at=now,
            map_version=access.map_version, no_custody=not access.custody,
        )  # fmt: skip
        check = cases_identity.LiveCheck(
            user_id, "ok", "elk", now, "person", frozenset(c.value for c in access.capabilities),
            kibana_privileges(access.capabilities), identity.argus_uid, identity.email,
        )  # fmt: skip
        return Authenticated(
            user_id, granted, SecretStr(password) if access.custody else None,
            identity.username, check,
        )  # fmt: skip


async def freeze(conn: AsyncConnection, user_id: int, now: datetime) -> None:
    """Disable an account for good and end its sessions (a new person has its name)."""
    await conn.execute(
        text("UPDATE users SET disabled = true, frozen_at = :now WHERE id = :id"),
        {"now": now, "id": user_id},
    )
    await conn.execute(
        text(
            "UPDATE user_sessions SET ended_at = :now, credential = NULL, ended_why = 'frozen'"
            " WHERE user_id = :id AND ended_at IS NULL"
        ),
        {"now": now, "id": user_id},
    )


async def handle_for(conn: AsyncConnection, elk_username: str) -> str:
    """ARGUS's own 2 to 32 character handle for an ELK name: its lower-case letters, digits
    and ``_ . -``, a number added while the handle is taken (or is one of ARGUS's own)."""
    base = re.sub(r"[^a-z0-9_.-]", "-", elk_username.lower())
    if not base or not base[0].isalpha():
        base = "u" + base
    base = base[:28]
    for n in range(1, 10_000):
        candidate = base if n == 1 else f"{base[: 31 - len(str(n))]}-{n}"
        if not HANDLE.fullmatch(candidate) or candidate in SERVICE_HANDLES:
            continue
        if (
            await conn.scalar(text("SELECT 1 FROM users WHERE username = :u"), {"u": candidate})
            is None
        ):
            return candidate
    raise RuntimeError("no free handle")  # pragma: no cover - 10,000 collisions


async def create_account(conn: AsyncConnection, identity, now: datetime) -> int:  # type: ignore[no-untyped-def]
    """The account of a person who signs in through ELK for the first time: no password hash,
    nothing but what ELK shows (ARGUS's own gold-key grant is added at a terminal)."""
    handle = await handle_for(conn, identity.username)
    row = await conn.execute(
        text(
            "INSERT INTO users (username, display_name, kind, realm, elk_username, argus_uid,"
            " email, capabilities, elk_first_signin_at, last_good_check_at)"
            " VALUES (:h, :d, 'person', 'native', :n, :u, :e, CAST('{}' AS text[]), :now, :now)"
            " RETURNING id"
        ),
        {"h": handle, "d": identity.full_name or identity.username, "n": identity.username,
         "u": identity.argus_uid, "e": identity.email, "now": now},
    )  # fmt: skip
    user_id: int = row.scalar_one()
    await auth.audit(conn, actor="web", action="user.created", target_type="user",
                     target_id=handle, details={"realm": "native"})  # fmt: skip
    return user_id


# --------------------------------------------------------------------------- the attempt


@dataclass
class SignIn:
    """The sign-in of one app: its provider, mode and settings."""

    provider: SignInProvider
    web: WebSettings
    clock: Callable[[], datetime]
    custody: Custody | None = None
    elk: Elk | None = None

    @property
    def elk_mode(self) -> bool:
        return self.elk is not None

    def name_key(self, username: str) -> tuple[str, str]:
        """The name as the audit trail records it: the HMAC of what was typed in ELK mode (the
        trail never holds a raw name that failed), a valid ARGUS name otherwise."""
        if self.custody is not None:
            return "name_hmac", self.custody.name_hmac(username)
        return "username", auth.shown_name(username)

    @staticmethod
    def device_hash(cookie: str | None) -> str | None:
        if cookie is None or not DEVICE_SHAPE.fullmatch(cookie):
            return None
        return hashlib.sha256(cookie.encode()).hexdigest()

    async def attempt(
        self,
        conn: AsyncConnection,
        username: str,
        password: str,
        *,
        client: str,
        device_cookie: str | None,
    ) -> Outcome:
        field_, key = self.name_key(username)

        async def refuse(why: str | None, counted: bool) -> None:
            await throttle.record(conn, action="login", name_field=field_, name_key=key,
                                  client=client, counted=counted, why=why)  # fmt: skip
            if counted:
                await throttle.raise_alarm_if_due(conn)

        if not await auth.one_at_a_time(conn, key, client):
            # another check of this name (or from this client) is under way: never wait for it
            # (a waiting request holds a pooled connection), never count it
            await refuse("unavailable:busy", False)
            return Outcome("unavailable")
        dhash = self.device_hash(device_cookie)
        # a one-time password needs no guess limit, and a limit would be a lever on the holder
        glass = self.elk_mode and username == breakglass.NAME
        device = glass or await throttle.device_known(conn, dhash, username, elk=self.elk_mode)
        standing = await throttle.read_standing(conn, key, client)
        verdict = throttle.decide(
            standing, device=device, base=timedelta(seconds=self.web.signin_delay_s)
        )
        if verdict is not throttle.Verdict.GO:
            await refuse("throttled", False)
            if verdict is throttle.Verdict.SPRAY_LOCKED:  # the limit was crossed: say so once
                await throttle.raise_alarm_if_due(conn)
            return Outcome("locked")
        result = await self.provider.authenticate(conn, username, password, device=device)
        if isinstance(result, Unavailable):
            await refuse(f"unavailable:{result.why}", False)
            return Outcome("unavailable")
        if isinstance(result, Refused):
            await refuse(result.why, result.counts)
            if self.elk_mode and result.counts and device:  # the person's own browser
                await self._void(conn, username)
            return Outcome("wrong")
        return await self._signed_in(conn, result, dhash)

    async def _void(self, conn: AsyncConnection, username: str) -> None:
        """A denial from the person's own browser (a device cookie of theirs): their approvals
        stop counting, as any 401 or 403 in a sign-in, re-check or step-up does (plan §7.1). A
        refusal from a browser that never signed in as them is told from a guess by nothing, so
        it voids nothing."""
        row = (
            await conn.execute(
                text(
                    "SELECT id, argus_uid, email FROM users WHERE elk_username = :n"
                    " AND frozen_at IS NULL"
                ),
                {"n": username},
            )
        ).first()
        if row is None:
            return
        await cases_identity.record_if_allowed(
            conn, cases_identity.LiveCheck(row.id, "denied", "elk", self.clock()), "signin"
        )

    def sealer(self, ok: Authenticated) -> auth.Seal | None:
        """How this sign-in's credential is sealed under its session's token (custody), or
        None: an admin account keeps none (DQ15 (b)), and a local sign-in has none to keep."""
        if ok.password is None or ok.elk_username is None or self.custody is None:
            return None
        custody, secret, user_id, name = self.custody, ok.password, ok.user_id, ok.elk_username

        def seal(token: str, hashed: str) -> bytes:
            return custody.seal(secret, token=token, token_hash=hashed, user_id=user_id,
                                elk_username=name)  # fmt: skip

        return seal

    async def _signed_in(
        self, conn: AsyncConnection, ok: Authenticated, dhash: str | None
    ) -> Outcome:
        now = self.clock()
        seal = self.sealer(ok)

        token, reviewer = await auth.start(
            conn, ok.user_id, now, self.web.session_absolute, granted=ok.granted, seal=seal
        )
        await auth.wipe_stale_credentials(conn, now, self.web.session_idle)
        await auth.audit(conn, actor=f"user:{reviewer.username}", action="login",
                         details={"mode": ok.granted.mode})  # fmt: skip
        if ok.check is not None:
            await cases_identity.record_if_allowed(conn, ok.check, "signin")
        new_device = await self._device(conn, ok.user_id, dhash)
        return Outcome("signed_in", token, reviewer, new_device)

    async def _device(self, conn: AsyncConnection, user_id: int, dhash: str | None) -> str | None:
        """Remember this browser: its device cookie is kept (usage noted) when it already is
        this person's, else a new one is made. Returns the new cookie value, or None."""
        if dhash is not None:
            known = await conn.scalar(
                text(
                    "UPDATE user_devices SET last_used_at = now() WHERE token_hash = :t"
                    " AND user_id = :u RETURNING 1"
                ),
                {"t": dhash, "u": user_id},
            )
            if known is not None:
                return None
        held = await conn.scalar(
            text("SELECT count(*) FROM user_devices WHERE user_id = :u"), {"u": user_id}
        )
        if int(held or 0) >= MAX_DEVICES:  # the web may not delete: a person's list is capped
            return None
        raw = secrets.token_urlsafe(32)
        await conn.execute(
            text("INSERT INTO user_devices (user_id, token_hash) VALUES (:u, :t)"),
            {"u": user_id, "t": hashlib.sha256(raw.encode()).hexdigest()},
        )
        return raw
