"""The Kibana lane (Q-D2): the only path from ARGUS to Kibana.

``KibanaGateway.read`` and ``.write`` decide, in this order, and stop at the first refusal:

1. the deadline has not passed;
2. no kill switch stops the work (``global``; ``kibana`` for reads, ``cases`` for case writes,
   ``writeback`` for alert writes) and the SIEM's health allows it (reads: NORMAL, CAUTION and
   DEGRADED at a reduced share; writes: NORMAL only); Kibana is not stopped (a 401);
3. a write: its class is switched on at the host and not paused, the run verified Kibana's
   pinned version and the licence (``start_run``), the context names its outbox row, the hash
   of exactly this payload and, for a closure, its approval;
4. the template builds its request and the validator accepts the **final** request;
5. Kibana's own breaker is closed, and so is the SIEM's (every Kibana call is load on the SIEM:
   Kibana keeps its cases there, an attach and an alert status change write the alerts, the
   keys' self-check goes to the SIEM itself); the SIEM's is only looked at, never tried or tripped;
6. the lane's budget admits it (waiting within the deadline; steps 2-5 are asked again after
   every wait), within D-022's concurrency shared by every lane (``lanes.shared_wait``);
7. just before sending, steps 2, 3 and 5 are asked once more (the kill switch before every
   request), the transport says it can send it (its route allowlist, the key installed), then
   a write takes its place in the caps (window, gaps, per run, per day) and Kibana's breaker
   its trial, if one is due.

It sends **once**: no request of the Kibana lane is retried, and a write whose outcome is unknown
is never resent (plan §3 rule 4). A write's error answer says it may have landed
(``maybe_applied``) unless it is one Kibana gives before changing anything (``may_have_landed``).
The answer is checked by the template (a check that crashes is a wrong answer); a Kibana 401 stops
Kibana work only, a 403 pauses only the write's class (its outbox row is the caller's), and a
read's 403 stops Kibana work (DQ9 (b)); 429 and 503 open Kibana's breaker, never the SIEM's. Each
request is charged max(round trip, the template's estimate) to its lane (a timeout its whole
timeout, ``kibana.timeout``; no connection nothing), and every request that left gets a ledger
row: lane, outbox row, payload hash, class, approval, the SIEM's health and the stopped switches. A
request the transport refused never left: no ledger row, and no place in the caps.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Protocol

from pydantic import BaseModel

from argus import site
from argus.gateway.budget import Lease, Verdict
from argus.gateway.builtin import ClusterLicense, KeyPrivileges
from argus.gateway.errors import (
    BreakerOpenError,
    BudgetExhaustedError,
    DeadlinePassedError,
    TemplateRejectedError,
)
from argus.gateway.gateway import (
    POLL,
    Gateway,
    Seen,
    admitted_by_state,
    lane_admit,
    lane_settle,
    utcnow,
)
from argus.gateway.health import HealthConfig
from argus.gateway.kibana import writes
from argus.gateway.kibana.errors import (
    AnswerMismatchError,
    KibanaAuthError,
    KibanaConflictError,
    KibanaForbiddenError,
    KibanaNoChangeError,
    KibanaNotFoundError,
    KibanaOverloadedError,
    KibanaRejectedError,
    KibanaResponseError,
    KibanaServerError,
    KibanaStoppedError,
    UnknownOutcomeError,
    WriteRefusedError,
)
from argus.gateway.kibana.paths import KEndpoint, wire_path
from argus.gateway.kibana.templates import (
    TIMEOUT,
    CasesConfigure,
    KeyRole,
    KibanaStatus,
    KibanaTemplate,
    KSpec,
    NoParams,
)
from argus.gateway.kibana.transport import KibanaTransport, KResponse, KWire
from argus.gateway.kibana.validator import KFinal, encode, request_hash, validate
from argus.gateway.kibana.writes import WriteCaps, WriteClass
from argus.gateway.lanes import lane_of
from argus.gateway.state import GatewayState, KibanaState, LedgerEntry
from argus.gateway.templates import CostClass, Purpose
from argus.gateway.templates import NoParams as EsNoParams
from argus.gateway.transport import wire_path as es_wire_path
from argus.gateway.validator import FinalRequest
from argus.gateway.validator import encode_body as es_encode
from argus.gateway.validator import validate as es_validate
from argus.site import LicenceFacts, VersionRange

READ_MIN_LEFT = timedelta(seconds=1)
# The error answers to a write that Kibana gives before it changes anything: 401 (the key is
# checked first), a create's or a PATCH's 400 (the body's schema), a PATCH's 404, 406 and 409
# (the case, its changes and its version are checked before the update). Any other answer may
# come after a part of the write landed: Q-D1's tier saw attaches answered 400 and 403 after
# the attachment was saved, a status change and an attach answered 500 after Kibana saved them,
# and a 429 or 503 can come from Elasticsearch after the case was written.
BEFORE_ANY_CHANGE: dict[KEndpoint, frozenset[int]] = {
    KEndpoint.CASE_CREATE: frozenset({400, 401}),
    KEndpoint.CASES_UPDATE: frozenset({400, 401, 404, 406, 409}),
    KEndpoint.CASE_COMMENT_EDIT: frozenset({400, 401, 404, 409}),
}


def may_have_landed(spec: KSpec, status: int) -> bool:
    """Whether a write answered ``status`` (not 2xx) may have taken effect."""
    return status not in BEFORE_ANY_CHANGE.get(spec.endpoint, frozenset({401}))


class Store(GatewayState, KibanaState, Protocol):
    """A store that keeps both the gateway's and the Kibana lane's state."""


@dataclass(frozen=True)
class KibanaTargets:
    """Where the Kibana lane acts: unless given, the site profile's space and Kibana versions."""

    space: str = field(default_factory=lambda: site.active().space)
    versions: VersionRange = field(default_factory=lambda: site.active().kibana_range)
    # a write run is refused on a Kibana version outside the range
    author: str | None = "argus"  # the created_by every ARGUS case must show

    @property
    def alerts_index_prefix(self) -> str:
        return site.active().alerts_backing_of(self.space)


@dataclass(frozen=True)
class WriteContext:
    """Who asked for a write and what it is bound to (plan §3 rule 1, §7.1). ``payload_hash``
    is the hash of the exact request (``KibanaGateway.payload_hash``: template, route, URL
    parameters and body bytes), which the writer computes from the body it rendered and records
    with the send; it is also the ledger row's. Q-C1's approvals bind the case change's intent
    (``argus.cases.kibana.payload_hash``); the writer (Q-D4) checks the approval, then renders."""

    write_class: WriteClass
    outbox_id: str
    payload_hash: str
    approval_id: str | None = None


@dataclass(frozen=True)
class WriteRun:
    """A write run's verified facts (``start_run``): Kibana's version, whether the case
    configuration lets a create through, the licence, and when they were read."""

    run_id: str
    version: str
    creates_blocked: bool
    licence: tuple[str, str]
    checked_at: datetime

    @property
    def facts(self) -> LicenceFacts:
        """What the licence the run saw allows (``argus.site.LicenceFacts``)."""
        return LicenceFacts(*self.licence)


@dataclass(frozen=True)
class KResult:
    body: Any  # the template's checked answer
    status: int
    elapsed_ms: int
    date: str | None  # Kibana's Date header


def build_final(
    template: KibanaTemplate, params: BaseModel, space: str, alerts_index_prefix: str
) -> KFinal:
    """The exact request ``template`` makes for ``params`` in ``space``, validated. Nothing is
    sent and no gateway is needed: a preview and a plan hash use it too."""
    plan = template.plan(params)
    method, path = wire_path(plan.spec.endpoint, space, plan.target)
    if plan.raw_body is not None:  # a file: the multipart bytes, checked by the validator
        body: bytes | None = plan.raw_body
    else:
        body = None if plan.body is None else encode(plan.body.model_dump(mode="json"))
    final = KFinal(plan.spec, method, path, plan.target, plan.url_params, body, plan.as_user)
    validate(final, space, alerts_index_prefix)
    return final


class KibanaGateway:
    def __init__(
        self,
        transport: KibanaTransport,
        state: Store,
        *,
        targets: KibanaTargets | None = None,
        caps: WriteCaps | None = None,
        classes: frozenset[WriteClass] = frozenset(),
        health_config: HealthConfig | None = None,
        es_gateway: Gateway | None = None,
        timeout: timedelta = TIMEOUT,
        clock: Callable[[], datetime] = utcnow,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        if timeout <= timedelta(0):
            raise ValueError("a Kibana request needs a timeout")
        self.transport = transport
        self.state = state
        self.targets = targets or KibanaTargets()
        self.caps = caps or WriteCaps()
        self.classes = classes  # switched on at the host (kibana.write_classes); none by default
        self.health_config = health_config or HealthConfig()
        self.es_gateway = es_gateway
        self.timeout = timeout  # kibana.timeout: every Kibana lane request's whole deadline
        self.clock = clock
        self.sleep = sleep
        self._runs: dict[str, WriteRun] = {}

    # ------------------------------------------------------------------ public

    def final(self, template: KibanaTemplate, params: BaseModel) -> KFinal:
        """The exact request ``template`` makes for ``params``, validated."""
        return build_final(template, params, self.targets.space, self.targets.alerts_index_prefix)

    def payload_hash(self, template: KibanaTemplate, params: BaseModel) -> str:
        """What an outbox row records for this write, and its approval binds (plan §7.1)."""
        return request_hash(self.final(template, params))

    async def read(
        self,
        template: KibanaTemplate,
        params: BaseModel,
        *,
        component: str,
        deadline: datetime,
    ) -> KResult:
        if type(template).spec().write:
            raise TemplateRejectedError("not_a_read", f"{template.name} is a write")
        return await self._run(template, params, Purpose.KIBANA_READ, component, deadline)

    async def start_run(self, *, component: str, deadline: datetime) -> WriteRun:
        """Before a write run (plan §5 Q-D2): Kibana's version must be in the site's range
        (``site.kibana_versions``) and its status available, the licence active (any level: the
        cases ARGUS writes need no paid feature; ``WriteRun.facts`` says what a paid level adds),
        and the case configuration is read (a required custom field without a default blocks
        creates)."""
        status = await self.read(KibanaStatus(), NoParams(), component=component, deadline=deadline)
        version, level = status.body
        if not self.targets.versions.allows(version):
            raise WriteRefusedError(
                "version_not_pinned",
                f"Kibana is {version[:20]}, writes need {self.targets.versions.describe()}",
            )
        if level != "available":
            raise WriteRefusedError("kibana_not_available", f"Kibana's status is {level[:20]}")
        if self.es_gateway is None:
            raise WriteRefusedError("no_licence_check", "the licence cannot be read")
        lic = await self.es_gateway.run(
            ClusterLicense(), EsNoParams(), purpose=Purpose.KIBANA_READ,
            component=component, deadline=deadline,
        )  # fmt: skip
        licence = ClusterLicense.summary(lic.body)
        if licence is None or not LicenceFacts(*licence).writes_allowed:
            raise WriteRefusedError("licence", "writes need an active licence")
        configure = await self.read(
            CasesConfigure(), NoParams(), component=component, deadline=deadline
        )
        run = WriteRun(
            uuid.uuid4().hex,
            version,
            CasesConfigure.blocks_creates(configure.body),
            licence,
            self.clock(),
        )
        self._runs[run.run_id] = run
        return run

    async def write(
        self,
        template: KibanaTemplate,
        params: BaseModel,
        *,
        run: WriteRun,
        context: WriteContext,
        component: str,
        deadline: datetime,
        before_send: Callable[[], Awaitable[None]] | None = None,
    ) -> KResult:
        """Send one write. ``before_send`` (the writer's: commit ``sending``, plan §7.1) runs
        after every check has passed and a place in the caps is taken, and just before the
        request leaves; if it raises, nothing is sent."""
        spec = type(template).spec()
        if not spec.write:
            raise TemplateRejectedError("not_a_write", f"{template.name} is a read")
        purpose = (
            Purpose.WRITEBACK if context.write_class is WriteClass.WA else Purpose.KIBANA_WRITE
        )
        return await self._run(
            template, params, purpose, component, deadline, context, run, before_send
        )

    async def key_privileges(
        self,
        role: KeyRole,
        body: dict[str, Any],
        *,
        component: str,
        deadline: datetime,
    ) -> KResult:
        """What one of ARGUS's Kibana keys holds: Elasticsearch's ``_has_privileges`` sent with
        that key (any key may check its own privileges). The body is held to the Elasticsearch
        validator's has_privileges rules; the request spends the Kibana read lane, and a 401
        or 403 stops Kibana work, never the SIEM's (DQ9 (b))."""
        now = self.clock()
        if now >= deadline:
            raise DeadlinePassedError("the deadline passed before the request started")
        spec = KeyPrivileges.spec()
        es_validate(FinalRequest(spec, body=body))
        method, path = es_wire_path(FinalRequest(spec, body=body))
        purpose = Purpose.KIBANA_READ
        seen = await self._admitted(purpose, CostClass.LIGHT, now, False)
        await self._breaker_closed(now)
        lease, seen = await self._lease(purpose, CostClass.LIGHT, seen, deadline, None, None, None)
        lane = lane_of(purpose)
        try:
            now = self.clock()
            seen = await self._admitted(purpose, CostClass.LIGHT, now, False)
            await self._breaker_closed(now)
            timeout = min(self.timeout, KeyPrivileges.timeout, deadline - now).total_seconds()
            wire = KWire(
                "es", role, method, path, (), es_encode(body),
                KeyPrivileges.opaque_id(component), max(timeout, 0.001),
            )  # fmt: skip
            refused = self.transport.refusal(wire)
            if refused is not None:
                raise refused
        except BaseException:
            await asyncio.shield(lane_settle(self.state, lane, lease, 0, self.clock(), seen.scale))
            raise
        return await self._exchange(
            wire, f"{spec.name}:{role.value}", spec.version, 50, self._privileges_answer,
            lease, seen, purpose, component, None, None,
        )  # fmt: skip

    @staticmethod
    def _privileges_answer(response: KResponse) -> Any:
        if response.status == 401:
            raise KibanaAuthError("the key is not accepted (401)", status=401)
        if response.status == 403:
            raise KibanaForbiddenError("the key may not check itself (403)", status=403)
        if not 200 <= response.status < 300:
            raise KibanaRejectedError(
                f"Elasticsearch answered {response.status}", status=response.status
            )
        try:
            payload = json.loads(response.body)
        except (UnicodeDecodeError, ValueError, RecursionError):
            raise AnswerMismatchError("the answer is not JSON", status=response.status) from None
        if not isinstance(payload, dict):
            raise AnswerMismatchError("not a privilege report", status=response.status)
        return payload

    # ------------------------------------------------------------------ steps

    async def _write_rules(
        self,
        spec: KSpec,
        final: KFinal,
        context: WriteContext,
        run: WriteRun,
        now: datetime,
    ) -> None:
        cls = context.write_class
        if cls not in spec.classes:
            raise WriteRefusedError("wrong_class", f"{spec.name} is not a {cls} write")
        if cls is WriteClass.WT:
            raise WriteRefusedError("class_off", "alert tags (WT) are not written (DQ11)")
        if cls not in self.classes:
            raise WriteRefusedError("class_off", f"{cls} is not switched on at this host")
        lane = await self.state.kibana_lane()
        if lane.is_paused(cls):
            raise WriteRefusedError("class_paused", f"{cls} is paused: {lane.paused[cls.value]}")
        if self._runs.get(run.run_id) != run:
            raise WriteRefusedError("no_run", "the run was not started by this gateway")
        if not self.targets.versions.allows(run.version):
            raise WriteRefusedError("version_not_pinned", "the run saw another Kibana version")
        if now - run.checked_at > writes.RUN_FRESH or now < run.checked_at:
            raise WriteRefusedError("run_stale", "the run's Kibana status is too old")
        if run.creates_blocked and spec.name == "cases.create":
            raise WriteRefusedError("creates_blocked", "a required custom field has no default")
        if not context.outbox_id or len(context.outbox_id) > 200:
            raise WriteRefusedError("no_outbox", "a write is sent only for its outbox row")
        if cls in writes.NEEDS_APPROVAL and not context.approval_id:
            raise WriteRefusedError("no_approval", f"a {cls} write needs its approval")
        if request_hash(final) != context.payload_hash:
            raise WriteRefusedError("payload_changed", "the payload is not the one recorded")
        if not writes.in_window(now, self.caps):
            raise WriteRefusedError("outside_window", "outside the write window")

    async def _admitted(
        self, purpose: Purpose, cost: CostClass, now: datetime, write: bool
    ) -> Seen:
        seen = await admitted_by_state(self.state, purpose, cost, now, self.health_config)
        lane = await self.state.kibana_lane()
        if lane.stopped is not None:
            raise KibanaStoppedError(f"Kibana work is stopped ({lane.stopped})")
        return seen

    async def _run(
        self,
        template: KibanaTemplate,
        params: BaseModel,
        purpose: Purpose,
        component: str,
        deadline: datetime,
        context: WriteContext | None = None,
        run: WriteRun | None = None,
        before_send: Callable[[], Awaitable[None]] | None = None,
    ) -> KResult:
        now = self.clock()
        if now >= deadline:
            raise DeadlinePassedError("the deadline passed before the request started")
        spec = type(template).spec()
        cost = spec.cost  # light: the template's estimate is charged at least, afterwards
        write = context is not None
        seen = await self._admitted(purpose, cost, now, write)
        final = self.final(template, params)
        if write:
            assert context is not None
            assert run is not None
            await self._write_rules(spec, final, context, run, now)
        await self._breaker_closed(now)
        lease, seen = await self._lease(purpose, cost, seen, deadline, final, context, run)
        lane = lane_of(purpose)
        try:
            now = self.clock()
            # a write goes out only with its whole timeout ahead: one cut short would end as an
            # unknown outcome while Kibana goes on with it; a read needs a second
            needed = self.timeout if write else READ_MIN_LEFT
            if deadline - now < needed:
                raise DeadlinePassedError(f"less than {needed.total_seconds():.0f} s left to send")
            seen = await self._admitted(purpose, cost, now, write)  # the switch before sending
            await self._breaker_closed(now)
            wire = self._wire(template, final, component, deadline, now)
            refused = self.transport.refusal(wire)  # a missing key: before any place is taken
            if refused is not None:
                raise refused
            if write:
                assert context is not None
                assert run is not None
                await self._write_rules(spec, final, context, run, now)
                units = template.plan(params).units
                assert units is not None
                await self._take_place(context.write_class, units, now, run.run_id)
            ok, until = await self.state.kibana_breaker_admit(now)
            if not ok:
                raise BreakerOpenError(until)
            if before_send is not None:  # the last step before the request leaves
                await before_send()
        except BaseException:
            await asyncio.shield(lane_settle(self.state, lane, lease, 0, self.clock(), seen.scale))
            raise
        return await self._send(template, params, final, wire, lease, seen, purpose, component,
                                context)  # fmt: skip

    async def _take_place(
        self, cls: WriteClass, units: writes.WriteUnits, now: datetime, run_id: str
    ) -> None:
        def change(
            state: writes.KibanaLaneState,
        ) -> tuple[str | None, writes.KibanaLaneState]:
            return writes.admit_write(state, cls, units, now, run_id, self.caps)

        refused = await self.state.kibana_change(change)
        if refused == "kibana_stopped":
            raise KibanaStoppedError("Kibana work is stopped")
        if refused is not None:
            raise WriteRefusedError(refused, f"the {cls} write waits ({refused})")

    async def _breaker_closed(self, now: datetime) -> None:
        """Kibana's breaker and the SIEM's must both be closed (looked at only: no trial)."""
        for peek in (self.state.kibana_breaker_peek, self.state.breaker_peek):
            ok, until = await peek(now)
            if not ok:
                raise BreakerOpenError(until)

    def _wire(
        self,
        template: KibanaTemplate,
        final: KFinal,
        component: str,
        deadline: datetime,
        now: datetime,
    ) -> KWire:
        timeout = min(self.timeout, deadline - now).total_seconds()
        spec = final.spec
        return KWire(
            "kibana", spec.key, final.method, final.path, final.url_params, final.body,
            type(template).opaque_id(component), max(timeout, 0.001),
            final.as_user, final.content_type,
        )  # fmt: skip

    async def _lease(
        self,
        purpose: Purpose,
        cost: CostClass,
        seen: Seen,
        deadline: datetime,
        final: KFinal | None,
        context: WriteContext | None,
        run: WriteRun | None,
    ) -> tuple[Lease, Seen]:
        lease_id = uuid.uuid4().hex
        lane = lane_of(purpose)
        while True:
            now = self.clock()
            admission = await lane_admit(self.state, lane, cost, now, seen.scale, lease_id)
            if admission.verdict is Verdict.ADMITTED:
                assert admission.lease is not None
                return admission.lease, seen
            if admission.verdict is Verdict.EXHAUSTED:
                raise BudgetExhaustedError(f"the {lane} lane's {admission.reason} budget is spent")
            retry_at = admission.retry_at or now + timedelta(seconds=1)
            if admission.reason == "concurrency":
                retry_at = min(retry_at, now + POLL)
            if retry_at >= deadline:
                raise DeadlinePassedError(f"the {lane} lane ({admission.reason}) frees up too late")
            await self.sleep(max((retry_at - now).total_seconds(), 0.01))
            now = self.clock()
            seen = await self._admitted(purpose, cost, now, context is not None)
            if context is not None:
                assert run is not None
                assert final is not None
                await self._write_rules(final.spec, final, context, run, now)
            await self._breaker_closed(now)

    async def _send(
        self,
        template: KibanaTemplate,
        params: BaseModel,
        final: KFinal,
        wire: KWire,
        lease: Lease,
        seen: Seen,
        purpose: Purpose,
        component: str,
        context: WriteContext | None,
    ) -> KResult:
        spec = final.spec
        return await self._exchange(
            wire,
            spec.name,
            spec.version,
            spec.estimate_ms,
            lambda response: self._checked(template, params, response, context),
            lease,
            seen,
            purpose,
            component,
            context,
            None if context is None else request_hash(final),
        )

    async def _exchange(
        self,
        wire: KWire,
        name: str,
        version: int,
        estimate_ms: int,
        check: Callable[[KResponse], Any],
        lease: Lease,
        seen: Seen,
        purpose: Purpose,
        component: str,
        context: WriteContext | None,
        payload_hash: str | None,
    ) -> KResult:
        """Send ``wire`` once, check the answer, settle the lease and write the ledger row."""
        lane = lane_of(purpose)
        started = self.clock()
        status: int | None = None
        size = 0
        settled = False

        async def finish(outcome: str, took: int) -> None:
            nonlocal settled
            settled = True
            now = self.clock()
            await lane_settle(self.state, lane, lease, took, now, seen.scale)
            await self.state.record(
                LedgerEntry(
                    at=started,
                    component=component,
                    purpose=purpose.value,
                    template=name,
                    version=version,
                    indices=(),
                    outcome=outcome,
                    http_status=status,
                    took_ms=took,
                    elapsed_ms=max(int((now - started).total_seconds() * 1000), 0),
                    response_bytes=size,
                    attempts=1,
                    lane=None if lane is None else lane.value,
                    target="kibana" if wire.target == "kibana" else "elasticsearch",
                    outbox_id=None if context is None else context.outbox_id,
                    payload_hash=payload_hash,
                    write_class=None if context is None else context.write_class.value,
                    approval_id=None if context is None else context.approval_id,
                    health=seen.health,
                    switches=seen.stopped,
                )
            )

        try:
            try:
                response = await self.transport.send(wire)
            except TemplateRejectedError:  # the transport refused it: nothing left, no row
                settled = True
                await lane_settle(self.state, lane, lease, 0, self.clock(), seen.scale)
                raise
            except UnknownOutcomeError as exc:
                if not exc.reached:  # no connection: Kibana did no work (D-093)
                    charged = 0
                elif exc.timed_out:
                    charged = int(wire.timeout_s * 1000)
                else:
                    charged = self._ms(started)
                await finish(exc.reason, charged)
                raise
            status, size = response.status, len(response.body)
            took = max(int(response.elapsed_ms + 0.999), estimate_ms)
            try:
                body = check(response)
            except KibanaResponseError as exc:
                await self._after_error(exc, context)
                await finish(exc.reason, took)
                raise
            await self.state.kibana_breaker_success(self.clock())
            await finish("ok", took)
            return KResult(body, response.status, int(response.elapsed_ms), response.date)
        except BaseException:
            if not settled:  # cancelled, or a bug: the lease is settled all the same
                await asyncio.shield(finish("aborted", self._ms(started)))
            raise

    def _checked(
        self,
        template: KibanaTemplate,
        params: BaseModel,
        response: KResponse,
        context: WriteContext | None,
    ) -> Any:
        status = response.status
        if 200 <= status < 300:
            try:
                payload = json.loads(response.body)
            except (UnicodeDecodeError, ValueError, RecursionError):
                raise AnswerMismatchError("Kibana's answer is not JSON", status=status) from None
            try:
                return template.check(params, payload, self.targets.author)
            except AnswerMismatchError as exc:
                raise AnswerMismatchError(str(exc), status=status) from None
            except Exception as exc:  # a check that crashes on an answer: a wrong answer
                raise AnswerMismatchError(
                    f"Kibana's answer could not be checked ({type(exc).__name__})", status=status
                ) from None
        error = self._error(status)
        if context is not None:  # a write: may it have landed?
            error.maybe_applied = may_have_landed(type(template).spec(), status)
        raise error

    @staticmethod
    def _error(status: int) -> KibanaResponseError:
        if status == 401:
            return KibanaAuthError("Kibana does not accept the key (401)", status=status)
        if status == 403:
            return KibanaForbiddenError("the key may not do this (403)", status=status)
        if status == 404:
            return KibanaNotFoundError("not found (404)", status=status)
        if status == 406:
            return KibanaNoChangeError("nothing to change (406)", status=status)
        if status == 409:
            return KibanaConflictError("the case changed (409)", status=status)
        if status in (429, 503):
            return KibanaOverloadedError(f"Kibana is overloaded ({status})", status=status)
        if 300 <= status < 400:
            return KibanaRejectedError(f"a redirect ({status}) is never followed", status=status)
        if status >= 500:
            error = KibanaServerError(f"Kibana failed ({status})", status=status)
            error.maybe_applied = False  # a read's; a write's is set by the caller
            return error
        return KibanaRejectedError(f"Kibana refused the request ({status})", status=status)

    async def _after_error(self, exc: KibanaResponseError, context: WriteContext | None) -> None:
        """DQ9 (b): a 401 stops Kibana work; a write's 403 or wrong answer pauses its class; a
        read's 403 stops Kibana work (the reader key lacks Cases Read); 429/503 open Kibana's
        breaker. Never the SIEM's health or breaker."""
        now = self.clock()
        if isinstance(exc, KibanaAuthError) or (
            isinstance(exc, KibanaForbiddenError) and context is None
        ):
            reason = "401" if isinstance(exc, KibanaAuthError) else "403 on a read"
            await self.state.kibana_change(lambda s: (None, writes.stop(s, reason, now)))
        elif context is not None and isinstance(exc, KibanaForbiddenError | AnswerMismatchError):
            cls = context.write_class
            reason = "403" if isinstance(exc, KibanaForbiddenError) else exc.reason
            await self.state.kibana_change(lambda s: (None, writes.pause(s, cls, reason)))
        if isinstance(exc, KibanaOverloadedError):
            await self.state.kibana_breaker_overload(now)
        else:
            await self.state.kibana_breaker_success(now)  # Kibana answered: not overloaded

    def _ms(self, since: datetime) -> int:
        return max(int((self.clock() - since).total_seconds() * 1000), 0)
