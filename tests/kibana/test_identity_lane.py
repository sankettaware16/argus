"""Q-E1's identity lane on the local tier (§12 #14 through ARGUS's own code; D-109: the SIEM is
never contacted): every seeded kind of account through ``IdentityLane.check``, the capability
map on Elasticsearch 8.19.12's real answers, the refusals before any request, a 401 counted
only after the security-index check, and the lane working while ARGUS's own key is refused.

The lane's requests go through ``TierIdentity``, which sends them with the tier's recorded
clients (so the cassettes hold them, never a password); the real HTTPS transport (pinned CA,
the person's header per call) is proven live only, at the end. The lane runs on a fake clock,
its state in memory.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import SecretStr

from argus.gateway.gateway import Gateway, LaneGate, Targets
from argus.gateway.health import HealthMemory, HealthState
from argus.gateway.state import MemoryStore
from argus.gateway.transport import WireRequest, WireResponse
from argus.identity import capmap
from argus.identity.lane import (
    AdminAccounts,
    IdentityDeniedError,
    IdentityError,
    IdentityLane,
    IdentityRefusedError,
    gateway_index_check,
)
from argus.identity.names import Credential
from argus.identity.transport import ROUTES, IdentityRequest, authorization
from argus.web.capabilities import Capability
from tests.kibana import kit
from tests.kibana.tier import SPACE, Tier, seed
from tests.unit.gateway.fakes import FakeClock

T0 = datetime(2026, 10, 23, 10, 0, tzinfo=UTC)
TARGETS = capmap.Targets(space=SPACE)


@dataclass
class TierIdentity:
    """The identity transport through the tier's recorded clients: a credential's header is
    mapped back to the tier principal that holds it (the recorder names principals, never
    passwords)."""

    kt: Tier
    principals: dict[str, str] = field(default_factory=dict)
    sent: list[tuple[str, str]] = field(default_factory=list)

    def credential(self, principal: str, username: str | None = None) -> Credential:
        kind, _, name = principal.partition(":")
        password = self._password(principal, kind, name)
        credential = Credential(username or self._username(kind, name), SecretStr(password))
        self.principals[authorization(credential).get_secret_value()] = principal
        return credential

    def _username(self, kind: str, name: str) -> str:
        return self.kt.name(name) if kind == "run-user" else name

    def _password(self, principal: str, kind: str, name: str) -> str:
        if not self.kt.live:
            return f"replay-password-of-{principal}"  # never sent anywhere
        if kind == "user":
            return str(self.kt.data["passwords"][name])
        if kind == "run-user":
            return kit._run_password(self.kt, principal)
        return f"not-the-password-{self.kt.run}"  # wrong:<name>

    async def send(self, request: IdentityRequest, auth: SecretStr) -> WireResponse:
        principal = self.principals[auth.get_secret_value()]
        method, path = ROUTES[request.route]
        self.sent.append((principal, request.route.value))
        body = None if request.body is None else json.loads(request.body)
        reply = self.kt.es(principal).call(method, path, body)
        return WireResponse(reply.status, json.dumps(reply.body).encode(), 5.0)


@dataclass
class TierElasticsearch:
    """ARGUS's own Elasticsearch key for the security-index check."""

    kt: Tier
    principal: str = "key:argus-reader"

    async def send(self, request: WireRequest) -> WireResponse:
        reply = self.kt.es(self.principal).call(
            request.method,
            request.path,
            None if request.body is None else json.loads(request.body),
            params=dict(request.params),
        )
        return WireResponse(reply.status, json.dumps(reply.body).encode(), 5.0)


def lane(
    kt: Tier,
    *,
    admin_accounts: AdminAccounts = AdminAccounts.REFUSE,
    es_principal: str = "key:argus-reader",
) -> tuple[IdentityLane, TierIdentity, MemoryStore, FakeClock]:
    clock = FakeClock(T0)
    store = MemoryStore(memory=HealthMemory(probed_at=T0))
    es = Gateway(TierElasticsearch(kt, es_principal), store, targets=Targets(), clock=clock,
                 sleep=clock.sleep)  # fmt: skip
    transport = TierIdentity(kt)
    identity = IdentityLane(
        transport, store, LaneGate(store, clock=clock, sleep=clock.sleep), targets=TARGETS,
        index_check=gateway_index_check(es), admin_accounts=admin_accounts, clock=clock,
    )  # fmt: skip
    return identity, transport, store, clock


async def outcome(identity: IdentityLane, clock: FakeClock, credential: Credential) -> Any:
    """The capabilities a check gives, or the error's class and reason."""
    try:
        checked = await identity.check(credential, deadline=clock.now + timedelta(minutes=10))
    except IdentityError as exc:
        return (type(exc).__name__, exc.reason)
    assert checked.identity.username == credential.username
    return sorted(c.value for c in checked.access.capabilities)


VIEW = ["view"]
REVIEW = ["review", "view"]
CASES = ["manage_cases", "reopen", "view"]
ANALYST = ["manage_cases", "reopen", "review", "view"]


async def test_every_seeded_account_through_the_lane(kt: Tier) -> None:
    identity, transport, store, clock = lane(kt)
    got = {name: await outcome(identity, clock, transport.credential(f"user:{name}"))
           for name in seed.USERS}  # fmt: skip
    assert got == {
        "tier-superuser": ("IdentityRefusedError", "superuser"),
        "tier-elkadmin": ("IdentityRefusedError", "admin_account"),
        "tier-argusadmin": ["admin", "view"],
        "tier-approver": ["approve", *ANALYST],
        "tier-analyst": ANALYST,
        "tier-manager": CASES,
        "tier-reviewer": REVIEW,
        "tier-viewer": VIEW,
        "tier-disabled": ("IdentityDeniedError", "unauthenticated"),
        "tier-otherspace": ("IdentityRefusedError", "no_access"),
    }
    assert sorted(seed.USERS) == sorted(got)
    # a denial is ELK's; a refusal is ARGUS's (never counted towards the throttle)
    assert IdentityDeniedError.counts
    assert not IdentityRefusedError.counts
    wrong = await outcome(identity, clock, transport.credential("wrong:tier-viewer"))
    unknown = await outcome(identity, clock, transport.credential("wrong:tier-nobody-here"))
    assert wrong == unknown == ("IdentityDeniedError", "unauthenticated")
    # every request was the lane's: whoami and verify with the person's own credential, and
    # the security-index check with ARGUS's key; none named in the ledger
    assert {entry.template for entry in store.ledger} == {
        "identity.whoami", "identity.verify", "health.security_index"
    }  # fmt: skip
    assert {entry.lane for entry in store.ledger} == {"identity"}
    assert all("tier-" not in json.dumps(entry.__dict__, default=str) for entry in store.ledger)


async def test_refused_before_any_request(kt: Tier) -> None:
    identity, transport, store, clock = lane(kt)
    for principal in ("user:argus", "user:elastic", "user:kibana_system"):
        name = principal.split(":", 1)[1]
        credential = Credential(name, SecretStr("a-long-enough-password"))
        with pytest.raises(IdentityRefusedError) as refused:
            await identity.check(credential, deadline=clock.now + timedelta(minutes=1))
        assert refused.value.reason in ("service_name", "reserved_name")
    short = Credential("tier-viewer", SecretStr("short"))
    with pytest.raises(IdentityRefusedError, match="short_password"):
        await identity.check(short, deadline=clock.now + timedelta(minutes=1))
    assert transport.sent == []
    assert store.ledger == []


async def test_admin_accounts_without_custody(kt: Tier) -> None:
    """DQ15 (b) as a setting: an admin account is let in without custody, with what its
    actions give (the seeded ELK admin: Kibana ``all`` and every index, but no ``argus``
    privilege); a superuser never."""
    identity, transport, _store, clock = lane(kt, admin_accounts=AdminAccounts.WITHOUT_CUSTODY)
    admin = await identity.check(transport.credential("user:tier-elkadmin"),
                                 deadline=clock.now + timedelta(minutes=10))  # fmt: skip
    assert admin.access.admin_account
    assert not admin.access.custody
    assert sorted(c.value for c in admin.access.capabilities) == sorted([*ANALYST, "see_logs"])
    superuser = await outcome(identity, clock, transport.credential("user:tier-superuser"))
    assert superuser == ("IdentityRefusedError", "superuser")
    role = kit.make_es_role(kt, "kadm", {"cluster": ["manage_api_key"]})
    viewer = kit.make_kibana_role(kt, "kadm-v", seed.KIBANA_ROLES["acme_viewer"])
    kit.make_user(kt, "kadm", [viewer, role], metadata={"argus_uid": seed.argus_uid("kadm")})
    checked = await identity.check(transport.credential("run-user:kadm"),
                                   deadline=clock.now + timedelta(minutes=10))  # fmt: skip
    assert checked.access.admin_account
    assert not checked.access.custody
    assert checked.access.capabilities == frozenset({Capability.VIEW})
    refusing, transport2, _s, clock2 = lane(kt)
    with pytest.raises(IdentityRefusedError, match="admin_account"):
        await refusing.check(transport2.credential("run-user:kadm"),
                             deadline=clock2.now + timedelta(minutes=10))  # fmt: skip


async def test_actions_not_role_names(kt: Tier) -> None:
    """The map reads actions: log read gives see_logs whatever the role is called; a role
    called like a reviewer's that grants nothing gives nothing; approve needs manage cases;
    an account without argus_uid, or marked as ARGUS's service, is refused."""
    identity, transport, _store, clock = lane(kt)
    viewer = kit.make_kibana_role(kt, "act-v", seed.KIBANA_ROLES["acme_viewer"])
    logs = kit.make_es_role(
        kt,
        "act-logs",
        {"indices": [{"names": ["acme-logs-*"], "privileges": ["read", "view_index_metadata"]}]},
    )
    fake = kit.make_es_role(kt, "acme_reviewer", {"cluster": []})
    approver_only = kit.make_es_role(
        kt,
        "act-ap",
        {
            "applications": [
                {"application": "argus", "privileges": ["approver"], "resources": ["*"]}
            ]
        },
    )
    uid = {"argus_uid": seed.argus_uid("act")}
    kit.make_user(kt, "act-logs", [viewer, logs], metadata=uid)
    kit.make_user(kt, "act-fake", [viewer, fake], metadata=uid)
    kit.make_user(kt, "act-ap", [viewer, approver_only], metadata=uid)
    kit.make_user(kt, "act-nouid", [viewer])
    kit.make_user(kt, "act-svc", [viewer], metadata={**uid, "argus_service": True})
    got = {suffix: await outcome(identity, clock, transport.credential(f"run-user:{suffix}"))
           for suffix in ("act-logs", "act-fake", "act-ap", "act-nouid", "act-svc")}  # fmt: skip
    assert got == {
        "act-logs": ["see_logs", "view"],
        "act-fake": VIEW,
        "act-ap": VIEW,  # argus:approve held, but approve needs manage cases
        "act-nouid": ("IdentityRefusedError", "no_argus_uid"),
        "act-svc": ("IdentityRefusedError", "service_account"),
    }


async def test_the_lane_works_with_the_reader_key_refused(kt: Tier) -> None:
    """ARGUS's own key refused (an invalidated reader key): the security-index check fails,
    which puts the SIEM in STOP for ARGUS, but the identity lane still checks people; a 401 can
    then not be told from an index outage, so it is "unavailable", never a denial."""
    owner = kit.make_user(kt, "rk", ["argus_es_reader"])
    key, minted = kit.grant_key(kt, "rk", owner, "rk-key", {"m": {"cluster": ["monitor"]}})
    assert minted.status == 200, minted.body
    gone = kt.es("elastic").delete(
        "/_security/api_key", {"ids": [minted.body["id"]]},
        keep=lambda b: {"errors": b["error_count"]},
    )  # fmt: skip
    assert (gone.status, gone.body) == (200, {"errors": 0})
    identity, transport, store, clock = lane(kt, es_principal=key)
    wrong = await outcome(identity, clock, transport.credential("wrong:tier-viewer"))
    assert wrong == ("IdentityUnavailableError", "security_index")
    assert store.memory.state is HealthState.STOP  # ARGUS's key: the gateway stopped the SIEM
    assert await outcome(identity, clock, transport.credential("user:tier-viewer")) == VIEW
    assert await outcome(identity, clock, transport.credential("user:tier-reviewer")) == REVIEW


async def test_the_real_transport_on_the_tier(live_kt: Tier) -> None:
    """Live only: the identity lane's HTTPS transport with the tier's CA pinned and the
    person's header per call; a wrong password is a 401, never a crash."""
    from argus.gateway.transport import pinned_context
    from argus.identity.transport import HttpxIdentityTransport, IdentityRequest, Route

    settings = live_kt.settings
    real = HttpxIdentityTransport(settings.es_url, pinned_context(settings.paths.ca_crt))
    good = Credential("tier-viewer", SecretStr(str(live_kt.data["passwords"]["tier-viewer"])))
    bad = Credential("tier-viewer", SecretStr("not-the-password-" + live_kt.run))
    try:
        me = await real.send(IdentityRequest(Route.WHOAMI, None, 5), authorization(good))
        assert me.status == 200
        assert json.loads(me.body)["username"] == "tier-viewer"
        body = json.dumps(capmap.request_body(TARGETS)).encode()
        held = await real.send(IdentityRequest(Route.VERIFY, body, 5), authorization(good))
        assert held.status == 200
        assert capmap.read(json.loads(held.body), TARGETS).capabilities == frozenset(
            {Capability.VIEW}
        )
        refused = await real.send(IdentityRequest(Route.WHOAMI, None, 5), authorization(bad))
        assert refused.status == 401
    finally:
        await real.aclose()
