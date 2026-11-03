"""The identity lane (Q-E1, plan §5 and §7.2): ``identity.whoami`` and ``identity.verify``
with a person's own ELK credential.

Each call, in this order, stops at the first refusal:

1. **Before any request** (``names``): reserved and service names, names ELK cannot hold,
   passwords under 10 characters: refused (``IdentityRefusedError``), no request, no budget.
2. **The identity gate** (``reach``): while its own requests found the SIEM unreachable or
   overloaded, unavailable (``IdentityUnavailableError``) at once. Never the SIEM's health
   state, a STOP from ARGUS's own key or a stale probe (DQ9 (b)).
3. **The lane** (``LaneGate``): the ``identity`` and global kill switches, the identity lane's
   own budget and its 6 checks a minute, of which a sign-in leaves 2 to re-checks (§7.8). A
   switch is ARGUS's own refusal (unavailable, ``stopped``); a lane that frees up too late is
   unavailable, ``busy``.
4. **One request** through the identity transport, with the person's header for that request
   only; no retry. A row in the request ledger without the name.
5. **The answer:** a 2xx is read strictly (``whoami``: realm ``native``, enabled, the exact
   name, an ``argus_uid``, no ``argus_service``; ``verify``: the capability map, superusers and
   admin accounts as DQ15 says, no entry without view). **A 403 is a denial. A 401 is a denial
   only after the security-index check** (with ARGUS's own key, through the gateway): while the
   index is not usable every native user gets 401, so a 401 then, or when the check cannot be
   made, is unavailable. Anything else (a timeout, no connection, 5xx, 429, a redirect, an
   answer that is not what was asked) is unavailable.

Only a denial (``IdentityDeniedError``) is Elasticsearch refusing the credential, so only it
counts towards Q-E2's throttle (``counts``); refusals and "unavailable" never do.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Protocol

from pydantic import SecretStr

from argus.gateway.errors import (
    BudgetExhaustedError,
    DeadlinePassedError,
    DeferredError,
    GatewayError,
    RefusedError,
    StoppedError,
    TimedOutError,
    TransportFailedError,
)
from argus.gateway.gateway import LaneGate
from argus.gateway.lanes import Lane
from argus.gateway.responses import OVERLOAD_TYPES, error_types, parse_json
from argus.gateway.state import LedgerEntry
from argus.gateway.templates import Purpose
from argus.gateway.transport import WireResponse
from argus.identity import capmap
from argus.identity.names import Credential, NamePolicy, refusal
from argus.identity.reach import ReachState, Signal
from argus.identity.transport import (
    TOTAL_TIMEOUT_S,
    IdentityRequest,
    IdentityTransport,
    Route,
    authorization,
)
from argus.web.capabilities import Capability

COMPONENT = "identity"
TEMPLATES: Mapping[Route, tuple[str, int]] = {
    Route.WHOAMI: ("identity.whoami", 1),
    Route.VERIFY: ("identity.verify", capmap.MAP_VERSION),
}
KEPT_FOR_RECHECKS = 2  # of the lane's 6 checks a minute (plan §7.8)
ESTIMATE_MS = 50  # the light class's estimate: what a call that answered costs at least
INDEX_CHECK_FRESH = timedelta(seconds=15)  # a usable security index is believed this long


class Kind(StrEnum):
    SIGNIN = "signin"  # a first check: leaves KEPT_FOR_RECHECKS a minute to re-checks
    RECHECK = "recheck"  # an open session's re-check (Q-E2)


class AdminAccounts(StrEnum):
    """DQ15: an account holding an admin canary (not a superuser)."""

    REFUSE = "refuse"  # (a): refused; the admin uses a second, ordinary account
    WITHOUT_CUSTODY = "without_custody"  # (b): let in, ARGUS keeps no copy of the password


# --------------------------------------------------------------------------- outcomes


class IdentityError(Exception):
    """A check that did not give an identity or access. ``reason`` is a fixed code (audit,
    ledger); ``counts`` says whether it counts towards the throttle (only ELK's refusals)."""

    counts = False

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class IdentityRefusedError(IdentityError):
    """ARGUS refuses: before any request (a name, a password) or after a good answer (a
    superuser, an admin account, a service account, another realm, no ARGUS id, no access)."""


class IdentityDeniedError(IdentityError):
    """Elasticsearch refused the credential: a 403, or a 401 with the security index usable."""

    counts = True


class IdentityUnavailableError(IdentityError):
    """ARGUS could not tell: the SIEM unreachable, overloaded or slow, the security index not
    usable or not checked, the lane stopped or busy, an answer not as asked."""


@dataclass(frozen=True)
class Identity:
    """Who the credential belongs to (``_authenticate``)."""

    username: str
    argus_uid: str
    full_name: str | None
    email: str | None
    realm: str = "native"


@dataclass(frozen=True)
class Access:
    """What the credential may do in ARGUS (``_has_privileges`` through the map)."""

    username: str
    capabilities: frozenset[Capability]
    admin_account: bool  # let in under DQ15 (b): no custody
    map_version: int
    checked_at: datetime

    @property
    def custody(self) -> bool:
        """May ARGUS keep this person's credential for re-checks (DQ16 (a))? Never for an
        admin account (DQ15 (b))."""
        return not self.admin_account


@dataclass(frozen=True)
class Checked:
    identity: Identity
    access: Access


# --------------------------------------------------------------------------- state


class IdentityState(Protocol):
    """The identity gate's shared state (``siem_state`` row ``identity``)."""

    async def identity_reach_admit(self, now: datetime) -> tuple[bool, ReachState]: ...
    async def identity_reach_report(self, now: datetime, signal: Signal) -> ReachState: ...
    async def record(self, entry: LedgerEntry) -> None: ...


IndexCheck = Callable[[datetime], Awaitable[bool | None]]
"""The security index's health with ARGUS's own key, by ``deadline``: True usable, False not,
None could not tell. ``gateway_index_check`` builds it on the Elasticsearch gateway."""


def gateway_index_check(gateway: Any, component: str = COMPONENT) -> IndexCheck:
    """The check through ``Gateway.run`` (template ``health.security_index``, the identity
    purpose: every health state, the identity lane's budget). Any refusal or error is None."""
    from argus.gateway.builtin import SecurityIndexHealth
    from argus.gateway.templates import NoParams

    async def check(deadline: datetime) -> bool | None:
        try:
            result = await gateway.run(
                SecurityIndexHealth(), NoParams(), purpose=Purpose.IDENTITY,
                component=component, deadline=deadline,
            )  # fmt: skip
        except GatewayError:
            return None
        return SecurityIndexHealth.usable(result.body)

    return check


def utcnow() -> datetime:
    return datetime.now(UTC)


# --------------------------------------------------------------------------- the lane


@dataclass(frozen=True)
class Sent:
    """One identity request's answer (or why there was none)."""

    response: WireResponse | None
    failure: GatewayError | None = None


class IdentityLane:
    def __init__(
        self,
        transport: IdentityTransport,
        state: IdentityState,
        gate: LaneGate,
        *,
        names: NamePolicy | None = None,
        targets: capmap.Targets | None = None,
        index_check: IndexCheck | None = None,
        admin_accounts: AdminAccounts = AdminAccounts.REFUSE,
        timeout_s: float = TOTAL_TIMEOUT_S,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        if not 0 < timeout_s <= TOTAL_TIMEOUT_S:
            raise ValueError(f"an identity call takes at most {TOTAL_TIMEOUT_S:.0f} s")
        self.transport = transport
        self.state = state
        self.gate = gate
        self.names = names or NamePolicy()
        self.targets = targets or capmap.Targets()
        self.index_check = index_check
        self.admin_accounts = admin_accounts
        self.timeout_s = timeout_s
        self.clock = clock
        self._index_ok_at: datetime | None = None

    # ------------------------------------------------------------------ public

    async def whoami(
        self, credential: Credential, *, deadline: datetime, kind: Kind = Kind.SIGNIN
    ) -> Identity:
        """Who this credential is (``GET /_security/_authenticate``)."""
        self._refuse_early(credential)
        body = await self._call(Route.WHOAMI, credential, None, deadline, kind)
        return read_identity(body, credential.username)

    async def verify(
        self, credential: Credential, *, deadline: datetime, kind: Kind = Kind.SIGNIN
    ) -> Access:
        """What this credential may do (``POST /_security/user/_has_privileges``)."""
        self._refuse_early(credential)
        request = json.dumps(capmap.request_body(self.targets)).encode()
        body = await self._call(Route.VERIFY, credential, request, deadline, kind)
        if not isinstance(body, Mapping) or body.get("username") != credential.username:
            raise IdentityUnavailableError("answer_mismatch")
        try:
            privileges = capmap.read(body, self.targets)
        except capmap.IncompleteAnswerError:
            raise IdentityUnavailableError("answer_incomplete") from None
        if privileges.superuser:
            raise IdentityRefusedError("superuser")
        if privileges.admin_account and self.admin_accounts is AdminAccounts.REFUSE:
            raise IdentityRefusedError("admin_account")
        if Capability.VIEW not in privileges.capabilities:
            raise IdentityRefusedError("no_access")
        return Access(
            username=credential.username,
            capabilities=privileges.capabilities,
            admin_account=privileges.admin_account,
            map_version=privileges.map_version,
            checked_at=self.clock(),
        )

    async def check(
        self, credential: Credential, *, deadline: datetime, kind: Kind = Kind.SIGNIN
    ) -> Checked:
        """Both: who, then what (two requests)."""
        identity = await self.whoami(credential, deadline=deadline, kind=kind)
        access = await self.verify(credential, deadline=deadline, kind=kind)
        return Checked(identity, access)

    # ------------------------------------------------------------------ steps

    def _refuse_early(self, credential: Credential) -> None:
        if not isinstance(credential, Credential):
            raise TypeError("a Credential")
        why = refusal(credential, self.names)
        if why is not None:
            raise IdentityRefusedError(why)

    async def _call(
        self,
        route: Route,
        credential: Credential,
        body: bytes | None,
        deadline: datetime,
        kind: Kind,
    ) -> Any:
        now = self.clock()
        if now >= deadline:
            raise IdentityUnavailableError("deadline_passed")
        ok, reach = await self.state.identity_reach_admit(now)
        if not ok:
            raise IdentityUnavailableError(reach.reason or "unreachable")
        # a sign-in leaves two checks a minute to re-checks; its first request (whoami) leaves
        # one more, so that its second (verify) is not the one refused "busy" after the
        # password was already checked (review E1-8; two sign-ins at once still fit)
        kept = 0
        if kind is Kind.SIGNIN:
            kept = KEPT_FOR_RECHECKS + (1 if route is Route.WHOAMI else 0)
        try:
            sent = await self._send(route, credential, body, deadline, kept)
        except StoppedError:
            raise IdentityUnavailableError("stopped") from None
        except (DeadlinePassedError, BudgetExhaustedError, DeferredError):
            raise IdentityUnavailableError("busy") from None
        except RefusedError:  # pragma: no cover - LaneGate raises only the three above
            raise IdentityUnavailableError("refused_by_argus") from None
        return await self._judge(sent, deadline)

    async def _send(
        self,
        route: Route,
        credential: Credential,
        body: bytes | None,
        deadline: datetime,
        kept: int,
    ) -> Sent:
        """One request inside the lane: admitted, sent once, charged, reported to the gate
        and written to the ledger, whatever happens (a cancellation included)."""
        name, version = TEMPLATES[route]
        async with self.gate.hold(Purpose.IDENTITY, deadline=deadline, kept=kept) as spend:
            started = self.clock()
            left = (deadline - started).total_seconds()
            if left <= 0:
                spend.charge(0)
                raise DeadlinePassedError("the deadline passed in the lane's queue")
            timeout = min(self.timeout_s, left)
            request = IdentityRequest(route, body, timeout)
            auth: SecretStr | None = authorization(credential)
            response: WireResponse | None = None
            failure: GatewayError | None = None
            outcome = "aborted"
            began = time.monotonic()
            try:
                try:
                    assert auth is not None
                    response = await self.transport.send(request, auth)
                except GatewayError as exc:  # no usable answer (the transport's typed errors)
                    failure = exc
                finally:
                    auth = None  # the header lives for this one request only
                if failure is not None:
                    spend.charge(_charge_failure(failure, timeout, time.monotonic() - began))
                    outcome = failure.reason
                    signal = Signal.UNREACHABLE  # no answer: slow, reset, not there, too big
                else:
                    assert response is not None
                    spend.charge(max(int(response.elapsed_ms + 0.999), ESTIMATE_MS))
                    outcome = _outcome(response.status)
                    signal = _signal(response)
                await self.state.identity_reach_report(self.clock(), signal)
            finally:
                elapsed = max(int((time.monotonic() - began) * 1000), 0)
                if spend.took_ms is None:  # cancelled or broken while out: it may have landed
                    spend.charge(max(elapsed, ESTIMATE_MS))
                charged = spend.took_ms
                assert charged is not None
                await asyncio.shield(
                    self.state.record(
                        LedgerEntry(
                            at=started,
                            component=COMPONENT,
                            purpose=Purpose.IDENTITY.value,
                            template=name,
                            version=version,
                            indices=(),
                            outcome=outcome,
                            http_status=None if response is None else response.status,
                            took_ms=charged,
                            elapsed_ms=elapsed,
                            response_bytes=0 if response is None else len(response.body),
                            attempts=1,
                            lane=Lane.IDENTITY.value,
                            health=spend.health,
                            switches=spend.switches,
                        )
                    )
                )
        return Sent(response, failure)

    async def _judge(self, sent: Sent, deadline: datetime) -> Any:
        if sent.response is None:
            assert sent.failure is not None
            raise IdentityUnavailableError(sent.failure.reason)
        status = sent.response.status
        if 200 <= status < 300:
            body = parse_json(sent.response.body)
            if not isinstance(body, Mapping):
                raise IdentityUnavailableError("answer_not_json")
            return body
        # only Elasticsearch's own refusal counts (review E1-3): a proxy's or firewall's
        # 401/403 (an HTML page, another error type) is "unavailable", never a denial
        if status in (401, 403) and "security_exception" not in error_types(
            parse_json(sent.response.body)
        ):
            raise IdentityUnavailableError("not_elasticsearch")
        if status == 403:
            raise IdentityDeniedError("forbidden")
        if status == 401:
            if await self._index_usable(deadline):
                raise IdentityDeniedError("unauthenticated")
            raise IdentityUnavailableError("security_index")
        raise IdentityUnavailableError(_outcome(status))

    async def _index_usable(self, deadline: datetime) -> bool:
        """Is the security index usable, so that a 401 is the password's? A recent usable
        answer is believed for ``INDEX_CHECK_FRESH``; no check configured, no answer, or an
        unusable index: False."""
        now = self.clock()
        if self._index_ok_at is not None and now - self._index_ok_at < INDEX_CHECK_FRESH:
            return True
        if self.index_check is None:
            return False
        usable = await self.index_check(deadline)
        if usable is True:
            self._index_ok_at = self.clock()
            return True
        self._index_ok_at = None
        return False


def _charge_failure(failure: GatewayError, timeout_s: float, elapsed_s: float) -> int:
    """What a request without an answer costs the lane (plan §7.8): no connection nothing,
    a timeout its whole timeout, anything else max(round trip, the light estimate)."""
    if isinstance(failure, TransportFailedError) and not failure.reached:
        return 0
    if isinstance(failure, TimedOutError):
        return int(timeout_s * 1000)
    return max(int(elapsed_s * 1000 + 0.999), ESTIMATE_MS)


def _outcome(status: int) -> str:
    if 200 <= status < 300:
        return "ok"
    if status in (401, 403):
        return "auth_failed"
    if status == 429:
        return "overloaded"
    return f"http_{status}" if 100 <= status <= 599 else "http_unknown"


def _signal(response: WireResponse) -> Signal:
    """What an answer says about the SIEM: overloaded (429, 503, a rejected execution or a
    tripped breaker), else it answered."""
    if response.status in (429, 503):
        return Signal.OVERLOADED
    if not 200 <= response.status < 300:
        types = error_types(parse_json(response.body))
        if OVERLOAD_TYPES.intersection(types):
            return Signal.OVERLOADED
    return Signal.ANSWERED


def read_identity(body: Any, username: str) -> Identity:
    """``_authenticate``'s answer as an ``Identity``, or why not. The answer must be for the
    exact name asked; realm and lookup realm native; authenticated by its password (not a key
    or a token); enabled; carrying an ``argus_uid``; not ARGUS's service identity."""
    if not isinstance(body, Mapping) or body.get("username") != username:
        raise IdentityUnavailableError("answer_mismatch")
    realm = body.get("authentication_realm")
    lookup = body.get("lookup_realm")
    realm_type = realm.get("type") if isinstance(realm, Mapping) else None
    lookup_type = lookup.get("type") if isinstance(lookup, Mapping) else None
    kind = body.get("authentication_type")
    enabled = body.get("enabled")
    # a field the answer does not state is an incomplete answer, not a verdict about the
    # person (review E1-5); a field it states against the rule is a refusal
    if None in (realm_type, lookup_type, kind) or not isinstance(enabled, bool):
        raise IdentityUnavailableError("answer_incomplete")
    if realm_type != "native" or lookup_type != "native":
        raise IdentityRefusedError("not_native")
    if kind != "realm":
        raise IdentityRefusedError("not_a_password")
    if enabled is not True:
        raise IdentityRefusedError("disabled")
    metadata = body.get("metadata")
    metadata = metadata if isinstance(metadata, Mapping) else {}
    if "argus_service" in metadata:  # the plan: no such metadata at all (review E1-6)
        raise IdentityRefusedError("service_account")
    uid = metadata.get("argus_uid")
    if not isinstance(uid, str) or not _is_uuid(uid):
        raise IdentityRefusedError("no_argus_uid")
    return Identity(
        username=username,
        argus_uid=str(uuid.UUID(uid)),
        full_name=_text(body.get("full_name")),
        email=_text(body.get("email")),
        realm="native",
    )


def _is_uuid(value: str) -> bool:
    if len(value) != 36:
        return False
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    return True


def _text(value: Any) -> str | None:
    return value[:256] if isinstance(value, str) and value else None
