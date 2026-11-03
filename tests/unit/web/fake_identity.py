"""A fake identity lane for the web's tests (Q-E2): scripted ELK accounts, no network. It
keeps ``IdentityLane``'s contract: names and passwords ARGUS refuses are refused before any
request (``calls`` stays empty), a wrong password or a disabled account is a denial (a 401),
a role change shows in the next check, and ``down``/``delay`` stand for an outage or a slow
Elasticsearch."""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from argus.identity.lane import (
    Access,
    Checked,
    Identity,
    IdentityDeniedError,
    IdentityRefusedError,
    IdentityUnavailableError,
    Kind,
)
from argus.identity.names import Credential, NamePolicy, refusal
from argus.web.capabilities import Capability

C = Capability
ANALYST = frozenset({C.VIEW, C.SEE_LOGS, C.REVIEW, C.MANAGE_CASES, C.REOPEN})
REVIEWER = frozenset({C.VIEW, C.SEE_LOGS, C.REVIEW})
VIEWER = frozenset({C.VIEW})
PASSWORD = "an elk password 1234"


def uid() -> str:
    return str(uuid.uuid4())


@dataclass
class Account:
    password: str = PASSWORD
    capabilities: frozenset[Capability] = REVIEWER
    argus_uid: str = field(default_factory=uid)
    admin: bool = False
    enabled: bool = True
    full_name: str | None = None
    email: str | None = None
    forbidden: bool = False  # a 403 instead of a 401 for a refusal


@dataclass
class FakeLane:
    accounts: dict[str, Account] = field(default_factory=dict)
    names: NamePolicy = field(default_factory=lambda: NamePolicy.of(["kibana.service_user"]))
    down: str | None = None  # every call is "unavailable" for this reason
    delay: float = 0.0  # seconds every call takes
    admin_accounts_allowed: bool = False
    calls: list[tuple[str, str, Kind]] = field(default_factory=list)
    deadlines: list[datetime] = field(default_factory=list)
    in_flight: int = 0
    max_in_flight: int = 0

    def add(self, name: str, **kw: object) -> Account:
        account = Account(**kw)  # type: ignore[arg-type]
        self.accounts[name] = account
        return account

    async def _answer(self, credential: Credential, route: str, kind: Kind) -> Account:
        why = refusal(credential, self.names)
        if why is not None:
            raise IdentityRefusedError(why)
        self.calls.append((route, credential.username, kind))
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
        finally:
            self.in_flight -= 1
        if self.down is not None:
            raise IdentityUnavailableError(self.down)
        account = self.accounts.get(credential.username)
        wrong = (
            account is None
            or account.password != credential.password.get_secret_value()
            or not account.enabled
        )
        if wrong or account is None:
            raise IdentityDeniedError("unauthenticated")
        if account.forbidden:
            raise IdentityDeniedError("forbidden")
        return account

    def _access(self, credential: Credential, account: Account) -> Access:
        if account.admin and not self.admin_accounts_allowed:
            raise IdentityRefusedError("admin_account")
        if C.VIEW not in account.capabilities:
            raise IdentityRefusedError("no_access")
        return Access(
            credential.username, account.capabilities, account.admin, 1, datetime.now(UTC)
        )

    async def verify(
        self, credential: Credential, *, deadline: datetime, kind: Kind = Kind.SIGNIN
    ) -> Access:
        self.deadlines.append(deadline)
        account = await self._answer(credential, "verify", kind)
        return self._access(credential, account)

    async def check(
        self, credential: Credential, *, deadline: datetime, kind: Kind = Kind.SIGNIN
    ) -> Checked:
        self.deadlines.append(deadline)
        account = await self._answer(credential, "whoami", kind)
        identity = Identity(
            credential.username, account.argus_uid, account.full_name, account.email
        )
        return Checked(identity, self._access(credential, account))

    def requests(self, route: str | None = None) -> int:
        return sum(1 for r, _n, _k in self.calls if route is None or r == route)


@dataclass
class Clock:
    """A clock a test moves."""

    now: datetime = field(default_factory=lambda: datetime.now(UTC).replace(microsecond=0))

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kw: float) -> None:
        self.now += timedelta(**kw)
