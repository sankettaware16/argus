"""The case team's Kibana users, made by ARGUS from one administrator login (``argus case team
provision``, D-303).

The case team posts an incident case as seven Kibana users (``model.Author``). This makes what they
need on the SIEM, the way D-159 made them by hand: two roles in the site's space only
(``argus_case_lead``: Cases all, Security read, and write on the space's alerts so it attaches and
tags them; ``argus_case_commenter``: the same with the alerts read-only), one user per teammate
with a random password nobody sees, and one API key per user, granted with that password and
written to the writer's credential folder (``case_team.<agent>_api_key``, mode 600).

The administrator's login is asked once and held in memory for the run: never stored, printed or
logged. Every call is paced, and what is printed is the method, the path and the status. A
teammate whose key file exists is kept; one whose user exists without a key file gets a new
password and a new key; delete a key file to re-key that teammate. Nothing is posted: posting
stays off until the operator switches it on (``case_team.post``, write class WC).
"""

from __future__ import annotations

import os
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from argus.caseteam.model import Author
from argus.site import SiteSettings

LEAD_ROLE = "argus_case_lead"
COMMENTER_ROLE = "argus_case_commenter"
KIBANA_APP = "kibana-.kibana"
OPTIONAL = frozenset({Author.VISUALISER})  # its step is skipped without a key (D-250)
PACE_S = 1.0  # the least between two calls to the SIEM


class ProvisionError(Exception):
    """The run stops here; the message says why and what to do."""


@dataclass(frozen=True)
class Teammate:
    author: Author
    role: str

    @property
    def user(self) -> str:
        return self.author.value

    @property
    def short(self) -> str:
        return self.user.removeprefix("argus-")

    @property
    def title(self) -> str:
        return f"ARGUS · {self.short.title()}"

    @property
    def key_file(self) -> str:
        return f"case_team.{self.short}_api_key"

    @property
    def key_name(self) -> str:
        return f"{self.user}-case-team"


@dataclass(frozen=True)
class Plan:
    space: str
    roles: Mapping[str, dict[str, Any]]
    team: tuple[Teammate, ...]
    credentials: Path
    expiration_days: int


def roles_for(site: SiteSettings) -> dict[str, dict[str, Any]]:
    """The two roles, in ``site``'s space only."""
    alerts = [site.alerts_index_name, f"{site.alerts_backing_prefix}*"]
    features = site.kibana_features
    kibana = [
        {
            "application": KIBANA_APP,
            "privileges": [f"feature_{features.cases}.all", f"feature_{features.security}.read"],
            "resources": [f"space:{site.space}"],
        }
    ]

    def role(privileges: list[str], purpose: str) -> dict[str, Any]:
        return {
            "cluster": [],
            "indices": [
                {"names": alerts, "privileges": privileges, "allow_restricted_indices": False}
            ],
            "applications": kibana,
            "metadata": {"application": "argus", "purpose": purpose},
        }

    return {
        LEAD_ROLE: role(
            ["read", "view_index_metadata", "write", "maintenance"],
            "the case team's lead: cases, and attaching and tagging the space's alerts",
        ),
        COMMENTER_ROLE: role(
            ["read", "view_index_metadata"], "the case team's commenters: cases, alerts read"
        ),
    }


def plan_for(
    site: SiteSettings, credentials: Path, *, visualiser: bool = True, expiration_days: int = 365
) -> Plan:
    if not 1 <= expiration_days <= 3650:
        raise ProvisionError("--expiration is a number of days from 1 to 3650")
    team = tuple(
        Teammate(a, LEAD_ROLE if a is Author.LEAD else COMMENTER_ROLE)
        for a in Author
        if visualiser or a not in OPTIONAL
    )
    return Plan(site.space, roles_for(site), team, credentials, expiration_days)


def describe(plan: Plan) -> list[str]:
    """The plan as lines a person reads before ``--apply`` (no secret in it)."""
    import json

    lines = [f"The case team in Kibana space {plan.space} (nothing is sent without --apply):", ""]
    for name, body in plan.roles.items():
        lines.append(f"role {name}:")
        lines += ["  " + line for line in json.dumps(body, indent=2).splitlines()]
    lines.append("")
    for mate in plan.team:
        lines.append(
            f"user {mate.user} ({mate.title}), role {mate.role}; one API key "
            f"({plan.expiration_days} days) -> {plan.credentials / mate.key_file} (mode 600)"
        )
    lines += [
        "",
        "With --apply: an Elasticsearch administrator login is asked once (a superuser, or a user",
        "with the manage_security cluster privilege); it is never stored, printed or logged.",
        "Posting stays off until you switch it on (case_team.post, write class WC).",
    ]
    return lines


@dataclass(frozen=True)
class Answer:
    status: int
    body: Any


class Siem(Protocol):
    """The calls provisioning makes, with the administrator's login (or a key's)."""

    def call(
        self, method: str, path: str, body: Any = None, *, api_key: str | None = None
    ) -> Answer: ...


@dataclass
class Outcome:
    made: list[str] = field(default_factory=list)
    rekeyed: list[str] = field(default_factory=list)
    kept: list[str] = field(default_factory=list)
    expires: date | None = None


def _ok(answer: Answer, what: str) -> Any:
    if not 200 <= answer.status < 300:
        raise ProvisionError(f"{what}: HTTP {answer.status}")
    return answer.body


def apply(
    plan: Plan,
    siem: Siem,
    *,
    say: Callable[[str], None],
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    password: Callable[[], str] = lambda: secrets.token_urlsafe(32),
) -> Outcome:
    """Make or keep what ``plan`` names. Raises ProvisionError on the first problem; what was
    done before it is kept (a rerun continues)."""
    who = _ok(siem.call("GET", "/_security/_authenticate"), "signing in")
    say(f"signed in as {who.get('username', '?')}")
    held = _ok(
        siem.call("POST", "/_security/user/_has_privileges", {"cluster": ["manage_security"]}),
        "checking the login's privileges",
    )
    if not held.get("cluster", {}).get("manage_security"):
        raise ProvisionError(
            "this login cannot manage users, roles and keys (it lacks manage_security):"
            " use a superuser such as elastic"
        )
    for name, body in plan.roles.items():
        _ok(siem.call("PUT", f"/_security/role/{name}", body), f"role {name}")
        say(f"role {name}: ready")
    plan.credentials.mkdir(mode=0o700, parents=True, exist_ok=True)
    out = Outcome()
    for mate in plan.team:
        path = plan.credentials / mate.key_file
        exists = siem.call("GET", f"/_security/user/{mate.user}").status == 200
        profile = {
            "roles": [mate.role],
            "full_name": mate.title,
            "metadata": {"argus_service": True, "argus_case_team": mate.short},
        }
        if exists and path.exists():
            _ok(siem.call("PUT", f"/_security/user/{mate.user}", profile), mate.user)
            out.kept.append(mate.user)
            say(f"{mate.user}: kept (its key file exists)")
            continue
        secret = password()
        if exists:
            _ok(siem.call("PUT", f"/_security/user/{mate.user}", profile), mate.user)
            _ok(
                siem.call("POST", f"/_security/user/{mate.user}/_password", {"password": secret}),
                f"{mate.user}'s password",
            )
        else:
            _ok(
                siem.call("POST", f"/_security/user/{mate.user}", {**profile, "password": secret}),
                f"creating {mate.user}",
            )
        key = _ok(
            siem.call(
                "POST",
                "/_security/api_key/grant",
                {
                    "grant_type": "password",
                    "username": mate.user,
                    "password": secret,
                    "api_key": {
                        "name": mate.key_name,
                        "expiration": f"{plan.expiration_days}d",
                        "metadata": {"application": "argus", "case_team": mate.short},
                    },
                },
            ),
            f"{mate.user}'s key",
        )
        del secret
        encoded = str(key["encoded"])
        _write_private(path, encoded)
        check = _ok(siem.call("GET", "/_security/_authenticate", api_key=encoded), mate.user)
        if check.get("username") != mate.user:
            raise ProvisionError(f"{mate.user}'s key does not authenticate as {mate.user}")
        (out.rekeyed if exists else out.made).append(mate.user)
        say(f"{mate.user}: {'new key' if exists else 'made'}, key written to {path} (mode 600)")
        out.expires = (now() + timedelta(days=plan.expiration_days)).date()
    return out


def _write_private(path: Path, value: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(value)
    os.chmod(path, 0o600)


class HttpSiem:
    """The SIEM over HTTPS with the pinned CA, as the administrator; paced; it prints only the
    method, the path and the status of each call."""

    def __init__(
        self,
        url: str,
        ca_file: Path,
        user: str,
        password: str,
        *,
        say: Callable[[str], None],
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        import httpx

        from argus.gateway.transport import pinned_context

        self._client = httpx.Client(
            base_url=url.rstrip("/"), verify=pinned_context(ca_file), timeout=30.0
        )
        self._auth = httpx.BasicAuth(user, password)
        self._say = say
        self._sleep = sleep
        self._last = 0.0

    def call(
        self, method: str, path: str, body: Any = None, *, api_key: str | None = None
    ) -> Answer:
        wait = PACE_S - (time.monotonic() - self._last)
        if wait > 0:
            self._sleep(wait)
        headers = {"Authorization": f"ApiKey {api_key}"} if api_key else None
        response = self._client.request(
            method, path, json=body, auth=None if api_key else self._auth, headers=headers
        )
        self._last = time.monotonic()
        self._say(f"   {method} {path}: {response.status_code}")
        try:
            parsed: Any = response.json()
        except ValueError:
            parsed = None
        return Answer(response.status_code, parsed)

    def close(self) -> None:
        self._client.close()
