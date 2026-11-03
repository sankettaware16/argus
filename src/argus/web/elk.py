"""ELK sessions (Q-E2, plan §7.2): keeping a signed-in person's access in step with ELK.

A session's capabilities are a **snapshot** of the last check of the person's own ELK account
(``identity.verify``). One rule keeps it in step:

* **pages come from the snapshot** and never wait: after 5 minutes a request starts a
  background re-check (with the credential kept under DQ16 (a)); the page is served from the
  snapshot anyway (D-103);
* **every change** waits for a live check unless the snapshot is at most 30 seconds old; no
  answer in 6 seconds and the change fails plainly (nothing is done);
* a 401 or 403 from ELK **ends the session** and voids the person's approvals (an identity
  check is recorded as denied, ``argus.cases.identity``). So reading stops within 5 minutes
  plus one read, and changes within 30 seconds.

**When ARGUS cannot verify** the person (``unverified_since`` on the session):

* in a *verified the SIEM outage* (the SIEM unreachable, slow or its security index not usable) the
  session keeps reading until its limit; reviews continue for 60 minutes, never written back
  to Kibana; approvals and every other write wait; only break-glass signs in;
* on *ARGUS's own refusal* (a switch, the lane's budget, a stop) a session reviews for
  15 minutes (never written back), is then read-only, and ends after 60 minutes.

Three people who were fine a minute ago failing with a 401 within two minutes also mean an
outage, not three revocations: the third and later 401s are "unavailable", and nothing is
counted. Only a 401 that the lane confirmed (its security-index check was good) is such a
failure: a 403, or an answer showing the account lost its access, is ELK answering, and notes
of suspected outages never count towards the next one. A session held this way is held for two
minutes at most, however many others fail after it: then its next 401 is final (a batch
revocation must not keep sessions open).

An admin account (DQ15 (b)) has no custody, so it cannot be re-checked: its changes need a
step-up (the password typed again) at most 30 seconds before.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Protocol

from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from argus.cases import identity as cases_identity
from argus.identity.lane import (
    Access,
    Checked,
    IdentityDeniedError,
    IdentityError,
    IdentityRefusedError,
    IdentityUnavailableError,
    Kind,
)
from argus.identity.names import Credential
from argus.web import auth
from argus.web.capabilities import Capability, ordered
from argus.web.custody import Custody
from argus.web.deps import Refusal, Surface

log = logging.getLogger(__name__)

RECHECK_AFTER = timedelta(minutes=5)  # a page's snapshot is re-checked in the background
CHANGE_FRESH = timedelta(seconds=30)  # a change needs a snapshot this young, or a live check
CHANGE_WAIT = timedelta(seconds=6)  # no answer by then: the change fails plainly
BACKGROUND_WAIT = timedelta(seconds=10)
RETRY_EVERY = timedelta(seconds=30)  # a session's background re-checks are at least this far apart
OUTAGE_REVIEWS = timedelta(minutes=60)  # reviews continue this long in a verified outage
REFUSED_REVIEWS = timedelta(minutes=15)  # ... and this long after ARGUS's own refusal
REFUSED_END = timedelta(minutes=60)  # a session ARGUS has refused to verify this long ends
SUSPECT_WINDOW = timedelta(seconds=120)
SUSPECT_PEOPLE = 3  # recent good people failing together mean an outage
CONCURRENT_CHECKS = 4  # live checks in flight at once: the pool keeps the rest for pages
REVIEW_CLASS = frozenset({Capability.REVIEW, Capability.ANSWER_GOLD})
# Why the lane could not verify that are ARGUS's own limits (a switch, the budget, a stop)
OWN_REFUSALS = frozenset({"stopped", "busy", "deadline_passed", "refused_by_argus"})
# Why it could not that make a *verified* the SIEM outage: the lane's own gate found the SIEM
# unreachable or overloaded (two failed requests in a minute, or an overload answer), ARGUS's
# key found the security index unusable, or three people failed together. A single timeout or an
# answer that makes no sense is none of these: that change fails plainly (it is not known to be
# an outage), and the session is held to the stricter timeline of ARGUS's own refusals.
VERIFIED_OUTAGE = frozenset({"unreachable", "overloaded", "security_index", "suspected_outage"})
# Refusals made before any request (names and password rules): no verdict about the account
EARLY = frozenset(
    {"reserved_name", "service_name", "not_a_name", "short_password", "long_password",
     "not_a_password"}
)  # fmt: skip
KIBANA_PRIVILEGES = {
    Capability.MANAGE_CASES: ("createCase", "createComment", "updateCase"),
    Capability.REOPEN: ("reopenCase",),
}
UNAVAILABLE_TEXT = (
    "ARGUS could not check your access in ELK just now, so nothing was changed. Reading still"
    " works. Try again in a minute."
)
OUTAGE_TEXT = (
    "ELK cannot be reached, so ARGUS cannot confirm your access. You can still read and review;"
    " this change has to wait."
)


class Checker(Protocol):
    """The identity lane, as the web uses it (``argus.identity.lane.IdentityLane``)."""

    async def verify(
        self, credential: Credential, *, deadline: datetime, kind: Kind = ...
    ) -> Access: ...

    async def check(
        self, credential: Credential, *, deadline: datetime, kind: Kind = ...
    ) -> Checked: ...


def fresh(now: datetime, then: datetime | None, limit: timedelta) -> bool:
    """Whether ``then`` is at most ``limit`` ago and not in the future: a clock stepped back
    makes an old snapshot look younger than it is, and must not make it fresh."""
    return then is not None and timedelta(0) <= now - then <= limit


def kibana_privileges(capabilities: frozenset[Capability]) -> frozenset[str]:
    """The Kibana privileges ARGUS acts on for a person (``argus.cases.identity``), from what
    the last check showed."""
    return frozenset(p for c in capabilities for p in KIBANA_PRIVILEGES.get(c, ()))


@dataclass(frozen=True)
class Probe:
    """One check of a person's own account, what it said."""

    kind: Literal["ok", "denied", "unavailable"]
    access: Access | None = None
    reason: str = ""
    counts: bool = False  # Elasticsearch refused the credential (the throttle counts it)
    early: bool = False  # refused before any request (a name or password rule)


class Elk:
    """The running state of ELK sessions for one web app: the lane, the custody key, the
    background re-checks."""

    def __init__(
        self,
        lane: Checker,
        custody: Custody,
        engine: AsyncEngine,
        clock: Callable[[], datetime],
        idle: timedelta,
        *,
        lane_clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.lane = lane
        self.custody = custody
        self.engine = engine
        self.clock = clock
        self.idle = idle
        self.lane_clock = lane_clock or (lambda: datetime.now(UTC))
        self.tasks: set[asyncio.Task[None]] = set()
        self._slots = asyncio.Semaphore(CONCURRENT_CHECKS)
        self._signins = asyncio.Semaphore(3)
        self._attempted: dict[str, datetime] = {}  # token hash -> when the last try began

    # ------------------------------------------------------------------ one check

    async def probe(
        self,
        elk_username: str,
        password: SecretStr,
        *,
        kind: Kind,
        wait: timedelta,
    ) -> Probe:
        """``identity.verify`` with the person's own credential, within ``wait``. Never raises
        for a verdict: ELK's refusal is ``denied``, anything ARGUS could not tell is
        ``unavailable``."""
        credential = Credential(elk_username, password)
        deadline = self.lane_clock() + wait
        try:
            access = await asyncio.wait_for(
                self.lane.verify(credential, deadline=deadline, kind=kind), wait.total_seconds()
            )
        except IdentityDeniedError as exc:
            return Probe("denied", reason=exc.reason, counts=exc.counts)
        except IdentityRefusedError as exc:
            return Probe("denied", reason=exc.reason, early=exc.reason in EARLY)
        except IdentityUnavailableError as exc:
            return Probe("unavailable", reason=exc.reason)
        except TimeoutError:
            return Probe("unavailable", reason="timeout")
        except IdentityError as exc:  # pragma: no cover - the three above are all it raises
            return Probe("unavailable", reason=exc.reason)
        return Probe("ok", access=access)

    async def credential_of(
        self, conn: AsyncConnection, reviewer: auth.Reviewer, token: str
    ) -> SecretStr | None:
        """The person's password out of the session's seal, or None (an admin account has
        none; a seal this secret and token do not open is no credential)."""
        if reviewer.elk_username is None or reviewer.no_custody:
            return None
        sealed = await conn.scalar(
            text("SELECT credential FROM user_sessions WHERE token_hash = :t AND ended_at IS NULL"),
            {"t": reviewer.token_hash},
        )
        if sealed is None:
            return None
        return self.custody.unseal(
            bytes(sealed), token=token, token_hash=reviewer.token_hash,
            user_id=reviewer.user_id, elk_username=reviewer.elk_username,
        )  # fmt: skip

    # ------------------------------------------------------------------ what a check does

    async def apply(
        self,
        conn: AsyncConnection,
        reviewer: auth.Reviewer,
        probe: Probe,
        purpose: cases_identity.Purpose,
    ) -> auth.Reviewer | None:
        """Put a check's verdict into the session: a good one renews the snapshot; ELK's
        refusal ends the session and voids the person's approvals; "unavailable" marks the
        session unverified. Returns the session as it now is, None when it ended."""
        now = self.clock()
        info = (
            await conn.execute(
                text("SELECT capabilities, argus_uid, email FROM users WHERE id = :id"),
                {"id": reviewer.user_id},
            )
        ).one()
        probe = await self.classify(conn, reviewer, probe)
        if probe.reason == "suspected_outage":
            await self._note(conn, reviewer, "session.suspected_outage", probe.reason)
        if probe.kind == "ok":
            assert probe.access is not None
            return await self._renewed(conn, reviewer, probe.access, info, now, purpose)
        if probe.kind == "denied":
            await auth.end(conn, reviewer.token_hash, now, "denied")
            await self._record(conn, reviewer, "denied", frozenset(), info, now, purpose)
            await self._note(conn, reviewer, "session.denied", probe.reason)
            return None
        why = "outage" if probe.reason in VERIFIED_OUTAGE else "refused"
        await conn.execute(
            text(
                "UPDATE user_sessions SET unverified_since = coalesce(unverified_since, :now),"
                " unverified_why = :why WHERE token_hash = :t AND ended_at IS NULL"
            ),
            {"now": now, "why": why, "t": reviewer.token_hash},
        )
        return replace(
            reviewer,
            unverified_since=reviewer.unverified_since or now,
            unverified_why=why,
        )

    async def classify(self, conn: AsyncConnection, reviewer: auth.Reviewer, probe: Probe) -> Probe:
        """A 401 that two other people got within two minutes too is an outage, not three
        revocations: "unavailable" (read only; nothing is written). A session already held
        this way for the whole window is not held again: its 401 stands."""
        if (
            probe.kind == "denied"
            and probe.reason == "unauthenticated"
            and probe.counts
            and not self._held_long_enough(reviewer)
            and await self._suspect_outage(conn, reviewer.user_id)
        ):
            return Probe("unavailable", reason="suspected_outage")
        return probe

    def _held_long_enough(self, reviewer: auth.Reviewer) -> bool:
        since = reviewer.unverified_since
        return since is not None and self.clock() - since >= SUSPECT_WINDOW

    async def _renewed(
        self,
        conn: AsyncConnection,
        reviewer: auth.Reviewer,
        access: Access,
        info: Any,
        now: datetime,
        purpose: cases_identity.Purpose,
    ) -> auth.Reviewer:
        shown = [c.value for c in ordered(access.capabilities)]
        no_custody = reviewer.no_custody or access.admin_account
        await conn.execute(
            text(
                "UPDATE user_sessions SET capabilities = CAST(:c AS text[]), checked_at = :now,"
                " map_version = :v, unverified_since = NULL, unverified_why = NULL,"
                " credential = CASE WHEN :nc THEN NULL ELSE credential END"
                " WHERE token_hash = :t AND ended_at IS NULL"
            ),
            {"c": shown, "now": now, "v": access.map_version, "nc": no_custody,
             "t": reviewer.token_hash},
        )  # fmt: skip
        await conn.execute(
            text("UPDATE users SET last_good_check_at = :now WHERE id = :id"),
            {"now": now, "id": reviewer.user_id},
        )
        caps = auth.capabilities_of("elk", access.capabilities, info.capabilities)
        await self._record(conn, reviewer, "ok", caps, info, now, purpose)
        return replace(
            reviewer, capabilities=caps, snapshot_at=now, unverified_since=None,
            unverified_why=None, no_custody=no_custody,
        )  # fmt: skip

    async def _record(
        self,
        conn: AsyncConnection,
        reviewer: auth.Reviewer,
        outcome: Literal["ok", "denied"],
        caps: frozenset[Capability],
        info: Any,
        now: datetime,
        purpose: cases_identity.Purpose,
    ) -> None:
        """The check, in ``identity_checks`` (the send-time check reads them; a denied one
        voids the person's approvals)."""
        check = cases_identity.LiveCheck(
            reviewer.user_id, outcome, "elk", now, "person",
            frozenset(c.value for c in caps), kibana_privileges(caps),
            info.argus_uid, info.email,
        )  # fmt: skip
        await cases_identity.record_if_allowed(conn, check, purpose)

    async def _note(self, conn: AsyncConnection, reviewer: auth.Reviewer, action: str,
                    reason: str) -> None:  # fmt: skip
        await auth.audit(
            conn, actor=f"user:{reviewer.username}", action=action,
            outcome="denied" if action == "session.denied" else "failure",
            target_type="session",
            details={"user_id": str(reviewer.user_id), "reason": reason},
        )  # fmt: skip

    async def _suspect_outage(self, conn: AsyncConnection, user_id: int) -> bool:
        """Two other people were denied with a 401 within two minutes: with this one, three.
        Only a denial that ended a session on a confirmed 401 counts: not a 403 or an answer
        showing the account lost its access (ELK is plainly up), and not a note of a suspected
        outage (they would keep each other's quorum alive for as long as anyone is re-checked)."""
        others = await conn.scalar(
            text(
                "SELECT count(DISTINCT details->>'user_id') FROM audit_events"
                " WHERE action = 'session.denied' AND details->>'reason' = 'unauthenticated'"
                " AND occurred_at > clock_timestamp() - make_interval(secs => :w)"
                " AND details->>'user_id' <> :me"
            ),
            {"w": SUSPECT_WINDOW.total_seconds(), "me": str(user_id)},
        )
        return int(others or 0) >= SUSPECT_PEOPLE - 1

    # ------------------------------------------------------------------ reads

    async def after_load(
        self, conn: AsyncConnection, reviewer: auth.Reviewer, token: str
    ) -> auth.Reviewer | None:
        """A page's session, from the snapshot: ended if ARGUS has refused to verify it for
        too long; otherwise served as it is, with a background re-check started when due."""
        now = self.clock()
        since = reviewer.unverified_since
        if (
            since is not None
            and reviewer.unverified_why == "refused"
            and now - since >= REFUSED_END
        ):
            await auth.end(conn, reviewer.token_hash, now, "unverified")
            return None
        if reviewer.no_custody:
            return reviewer
        # due when stale, and when the clock says the snapshot is from the future
        age = None if reviewer.snapshot_at is None else now - reviewer.snapshot_at
        due = age is None or age < timedelta(0) or age >= RECHECK_AFTER
        if due:
            self._schedule(reviewer, token)
        return reviewer

    def _schedule(self, reviewer: auth.Reviewer, token: str) -> None:
        key, now = reviewer.token_hash, self.clock()
        last = self._attempted.get(key)
        if last is not None and timedelta(0) <= now - last < RETRY_EVERY:
            return
        if self._slots.locked():
            return
        self._attempted[key] = now
        if len(self._attempted) > 10_000:  # forget the oldest half
            for old in sorted(self._attempted, key=self._attempted.__getitem__)[:5_000]:
                del self._attempted[old]
        task = asyncio.get_running_loop().create_task(self._background(key, token))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def _background(self, hashed: str, token: str) -> None:
        try:
            async with self._slots:
                async with self.engine.connect() as conn:
                    reviewer = await auth.session(conn, token, self.clock(), self.idle,
                                                  extend=False, modes=("elk",))  # fmt: skip
                    if reviewer is None or reviewer.token_hash != hashed:
                        return
                    password = await self.credential_of(conn, reviewer, token)
                if password is None or reviewer.elk_username is None:
                    return
                probe = await self.probe(reviewer.elk_username, password, kind=Kind.RECHECK,
                                         wait=BACKGROUND_WAIT)  # fmt: skip
                async with self.engine.begin() as conn:
                    await self.apply(conn, reviewer, probe, "recheck")
        except Exception:
            log.exception("web: a background re-check failed")
        finally:
            self._attempted[hashed] = self.clock()

    async def settle(self) -> None:
        """Wait for the background re-checks in flight (tests, shutdown)."""
        while self.tasks:
            await asyncio.gather(*list(self.tasks), return_exceptions=True)

    # ------------------------------------------------------------------ changes

    async def gate_change(
        self,
        conn: AsyncConnection,
        reviewer: auth.Reviewer,
        token: str,
        capability: Capability,
        surface: Surface,
    ) -> auth.Reviewer:
        """Before a change: the snapshot is at most 30 seconds old, or the person's access is
        checked now (no answer in 6 seconds: it fails plainly). Returns the session as the
        check left it (capabilities renewed); raises ``Refusal``. What a refusal must leave
        behind (an ended session, a session marked unverified) is written by the refusal's
        ``after``, once the request's own transaction has been rolled back."""
        now = self.clock()
        verified = reviewer.unverified_since is None
        if verified and fresh(now, reviewer.snapshot_at, CHANGE_FRESH):
            return reviewer
        if reviewer.no_custody:
            raise Refusal(
                403, "stepup_required",
                "ARGUS keeps no copy of your password, so it cannot check your access for you:"
                " confirm it is you on the step-up page, then try again",
                surface, reviewer,
            )  # fmt: skip
        password = await self.credential_of(conn, reviewer, token)
        if password is None or reviewer.elk_username is None:
            gone = Probe("denied", reason="no_credential")
            raise Refusal(401, "unauthenticated", "sign in again", surface,
                          after=self._later(reviewer, gone))  # fmt: skip
        if self._slots.locked():
            raise Refusal(503, "unavailable", UNAVAILABLE_TEXT, surface, reviewer)
        async with self._slots:
            probe = await self.probe(reviewer.elk_username, password, kind=Kind.RECHECK,
                                     wait=CHANGE_WAIT)  # fmt: skip
        probe = await self.classify(conn, reviewer, probe)
        if probe.kind == "denied":
            raise Refusal(
                401, "unauthenticated", "your access in ELK has changed: sign in again",
                surface, after=self._later(reviewer, probe),
            )  # fmt: skip
        if probe.kind == "ok":
            renewed = await self.apply(conn, reviewer, probe, "recheck")
            assert renewed is not None
            return renewed
        # ARGUS could not check: in a verified outage, or after ARGUS's own refusal, a review
        # may still be made inside its window (never written back); anything else waits, and a
        # check that failed for no known reason (a timeout) fails plainly
        since = reviewer.unverified_since or now
        why = "outage" if probe.reason in VERIFIED_OUTAGE else "refused"
        window = OUTAGE_REVIEWS if why == "outage" else REFUSED_REVIEWS
        known = probe.reason in VERIFIED_OUTAGE or probe.reason in OWN_REFUSALS
        if known and capability in REVIEW_CLASS and now - since <= window:
            renewed = await self.apply(conn, reviewer, probe, "recheck")
            assert renewed is not None
            return renewed
        raise Refusal(503, "unavailable", OUTAGE_TEXT if why == "outage" else UNAVAILABLE_TEXT,
                      surface, reviewer, after=self._later(reviewer, probe))  # fmt: skip

    def _later(self, reviewer: auth.Reviewer, probe: Probe) -> Callable[[], Awaitable[None]]:
        """What a refused change leaves behind, written on a connection of its own."""

        async def persist() -> None:
            async with self.engine.begin() as conn:
                if probe.reason == "no_credential":
                    await auth.end(conn, reviewer.token_hash, self.clock(), "no_credential")
                else:
                    await self.apply(conn, reviewer, probe, "recheck")

        return persist

    # ------------------------------------------------------------------ step-up

    async def step_up_probe(self, reviewer: auth.Reviewer, password: SecretStr) -> Probe:
        """The password typed at step-up, checked against ELK now."""
        if reviewer.elk_username is None:
            return Probe("denied", reason="no_elk_name")
        if self._slots.locked():  # as every live check: the pool keeps its connections for pages
            return Probe("unavailable", reason="busy")
        async with self._slots:
            return await self.probe(reviewer.elk_username, password, kind=Kind.RECHECK,
                                    wait=CHANGE_WAIT)  # fmt: skip


@dataclass
class ElkIdentityProvider:
    """``argus.cases.identity.IdentityProvider`` for a person signed in through ELK: a live
    check with the credential their session keeps, for the approval routes (Q-B3) and the
    send-time checks. Built per request, with the session's token (the seal needs it); an admin
    account's answer is the snapshot a step-up renewed, only while it is at most 30 s old."""

    elk: Elk
    token: str
    name: str = "elk"

    async def check(
        self, conn: AsyncConnection, user_id: int, *, purpose: cases_identity.Purpose
    ) -> cases_identity.LiveCheck:
        now = self.elk.clock()
        reviewer = await auth.session(conn, self.token, now, self.elk.idle,
                                      extend=False, modes=("elk",))  # fmt: skip
        if reviewer is None or reviewer.user_id != user_id:
            return cases_identity.LiveCheck(user_id, "denied", self.name, now)
        info = (
            await conn.execute(
                text("SELECT argus_uid, email FROM users WHERE id = :id"), {"id": user_id}
            )
        ).one()
        if reviewer.no_custody:
            current = reviewer.unverified_since is None and fresh(
                now, reviewer.snapshot_at, CHANGE_FRESH
            )
            return self._made("ok" if current else "unavailable", reviewer, info, now)
        password = await self.elk.credential_of(conn, reviewer, self.token)
        if password is None or reviewer.elk_username is None:
            return self._made("unavailable", reviewer, info, now)
        probe = await self.elk.probe(reviewer.elk_username, password, kind=Kind.RECHECK,
                                     wait=CHANGE_WAIT)  # fmt: skip
        after = await self.elk.apply(conn, reviewer, probe, "recheck")
        if after is None:
            return cases_identity.LiveCheck(user_id, "denied", self.name, now)
        return self._made("ok" if probe.kind == "ok" else "unavailable", after, info, now)

    def _made(
        self, outcome: cases_identity.Outcome, reviewer: auth.Reviewer, info: Any, now: datetime
    ) -> cases_identity.LiveCheck:
        if outcome != "ok":
            return cases_identity.LiveCheck(reviewer.user_id, outcome, self.name, now)
        caps = reviewer.capabilities
        return cases_identity.LiveCheck(
            reviewer.user_id, "ok", self.name, now, "person",
            frozenset(c.value for c in caps), kibana_privileges(caps),
            info.argus_uid, info.email,
        )  # fmt: skip
