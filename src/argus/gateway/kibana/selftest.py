"""``argus kibana selftest`` (Q-D2): each of ARGUS's Kibana keys holds what it must and none of
what it must not (plan §2: Security Read is not read-only; §5 Q-D2's canaries).

The check is Elasticsearch's ``_has_privileges`` with the key under test, asking Kibana's
application privileges in the space (``kibana-.kibana``, ``space:<space>``), the alerts
index and the cluster canaries in one request:

- the **reader** (Cases Read only) must hold the case reads, and none of the case writes;
- the **cases writer** (W1-W3) must hold the case reads and writes it uses and the "get" of
  Security's alerts (an attach reads the alert first);
- the **alert writer** (WA) must hold read, index and maintenance on the alerts;
- none may hold ``deleteCase``, ``pushCase``, ``createConfiguration``, ``updateConfiguration``,
  ``assignCase``, cluster ``all``/``manage``/``manage_security``/``manage_api_key``; the reader
  and the cases writer must not hold ``api:rac`` or the alert "update" actions (the RAC routes
  write alert status as Kibana's internal user, plan §2), nor write the alerts index; no key
  may hold ``all``, ``manage``, ``delete_index`` or ``create_index`` on the alerts.

DQ3's fallback cases writer (Cases All + Security Read, if a key limited to named actions is not
possible) holds ``api:rac``, the alert updates and ``deleteCase``: that residual is reported as
a problem unless ``kibana.accepted_residual`` names each privilege (a decision, recorded).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from argus import site
from argus.gateway.kibana.templates import KeyRole

APP = "kibana-.kibana"
CASES = "cases:securitySolution/"
SIEM_RULE_TYPES = (
    "siem.eqlRule",
    "siem.esqlRule",
    "siem.indicatorRule",
    "siem.mlRule",
    "siem.newTermsRule",
    "siem.notifications",
    "siem.queryRule",
    "siem.savedQueryRule",
    "siem.thresholdRule",
)  # Kibana 8.19.12's Security rule types (GET /api/security/privileges?includeActions)
ALERT_GETS = tuple(f"alerting:{t}/siem/alert/get" for t in SIEM_RULE_TYPES)
ALERT_UPDATES = tuple(f"alerting:{t}/siem/alert/update" for t in SIEM_RULE_TYPES)
CASE_READS = (
    "login:",
    f"{CASES}getCase",
    f"{CASES}getComment",
    f"{CASES}getUserActions",
    f"{CASES}findConfigurations",
)
CASE_WRITES = (
    f"{CASES}createCase",
    f"{CASES}updateCase",
    f"{CASES}createComment",
    f"{CASES}reopenCase",
)
NEVER = (
    f"{CASES}deleteCase",
    f"{CASES}pushCase",
    f"{CASES}createConfiguration",
    f"{CASES}updateConfiguration",
    f"{CASES}assignCase",
)
# The RAC routes (api:rac) and the alert updates write alert status as Kibana's internal user;
# the alert status route needs only api:securitySolution (kibana-identities.md).
RAC = ("api:rac", "api:securitySolution", *ALERT_UPDATES)
CLUSTER_CANARIES = ("all", "manage", "manage_security", "manage_api_key", "grant_api_key")
ALERT_WRITE = ("index", "write", "delete", "maintenance")
# What no key may hold on the alerts: these delete, close or recreate the index itself.
ALERT_DESTRUCTIVE = ("all", "manage", "delete_index", "create_index")
ALERT_WRITER_NEEDS = ("read", "index", "maintenance", "view_index_metadata")


@dataclass(frozen=True)
class Profile:
    """What a key must and must not hold."""

    must_app: tuple[str, ...]
    must_not_app: tuple[str, ...]
    must_index: tuple[str, ...]
    must_not_index: tuple[str, ...]


PROFILES: Mapping[KeyRole, Profile] = {
    KeyRole.READER: Profile(
        CASE_READS, (*CASE_WRITES, *NEVER, *RAC), (), (*ALERT_WRITE, *ALERT_DESTRUCTIVE)
    ),
    KeyRole.CASES: Profile(
        (*CASE_READS, *CASE_WRITES, "alerting:siem.queryRule/siem/alert/get"),
        (*NEVER, *RAC),
        (),
        (*ALERT_WRITE, *ALERT_DESTRUCTIVE),
    ),
    KeyRole.ALERTS: Profile(
        (), (*CASE_WRITES, *NEVER), ALERT_WRITER_NEEDS, ("delete", *ALERT_DESTRUCTIVE)
    ),
    # The case team's users (AR8, D-159): on Basic a key that comments also holds deleteCase
    # (cases: all), accepted by D-159 and kept off by the lane's routes; so the profile asks for
    # the reads and writes it uses and for nothing that destroys the alerts index.
    KeyRole.TEAM: Profile((*CASE_READS, *CASE_WRITES), (), (), (*ALERT_DESTRUCTIVE,)),
}


def request_body(role: KeyRole, space: str) -> dict[str, Any]:
    """The one ``_has_privileges`` body that answers every check of ``role``'s profile."""
    profile = PROFILES[role]
    app = sorted({*profile.must_app, *profile.must_not_app})
    index = sorted({*profile.must_index, *profile.must_not_index})
    body: dict[str, Any] = {
        "cluster": list(CLUSTER_CANARIES),
        "application": [{"application": APP, "resources": [f"space:{space}"], "privileges": app}],
    }
    if index:
        body["index"] = [{"names": [alerts_alias(space)], "privileges": index}]
    return body


def alerts_alias(space: str) -> str:
    return site.active().alerts_index_of(space)


@dataclass(frozen=True)
class Verdict:
    problems: tuple[str, ...]  # empty: the key is as it must be
    residual: tuple[str, ...]  # held privileges the profile forbids that were accepted


def judge(role: KeyRole, space: str, answer: Any, accepted_residual: Iterable[str] = ()) -> Verdict:
    """The key's problems from its ``_has_privileges`` answer. Anything the answer does not
    state counts against the key (unknown is not "not held")."""
    if not isinstance(answer, Mapping):
        return Verdict(("the answer is not a privilege report",), ())
    profile = PROFILES[role]
    accepted = frozenset(accepted_residual)
    problems: list[str] = []
    residual: list[str] = []
    cluster = answer.get("cluster")
    cluster = cluster if isinstance(cluster, Mapping) else {}
    for name in CLUSTER_CANARIES:
        if cluster.get(name) is not False:
            problems.append(f"holds cluster privilege {name}")
    app = answer.get("application")
    held = app.get(APP) if isinstance(app, Mapping) else None
    held = held.get(f"space:{space}") if isinstance(held, Mapping) else None
    held = held if isinstance(held, Mapping) else {}
    for name in profile.must_app:
        if held.get(name) is not True:
            problems.append(f"lacks {name}")
    for name in profile.must_not_app:
        if held.get(name) is not False:
            if name in accepted and held.get(name) is True:
                residual.append(name)
            else:
                problems.append(f"holds {name}")
    if profile.must_index or profile.must_not_index:
        index = answer.get("index")
        alias = alerts_alias(space)
        on = index.get(alias) if isinstance(index, Mapping) else None
        on = on if isinstance(on, Mapping) else {}
        for name in profile.must_index:
            if on.get(name) is not True:
                problems.append(f"lacks {name} on the alerts")
        for name in profile.must_not_index:
            if on.get(name) is not False:
                problems.append(f"holds {name} on the alerts")
    return Verdict(tuple(problems), tuple(residual))


async def run_selftest(
    gateway: Any,
    role: KeyRole,
    *,
    deadline: Any,
    accepted_residual: Iterable[str] = (),
    component: str = "selftest",
) -> tuple[str, Verdict]:
    """(Kibana's version, the key's verdict): ``kibana.status`` with the reader key, then the
    key's privileges with the key itself. ``gateway`` is a ``KibanaGateway``."""
    from argus.gateway.kibana.templates import KibanaStatus, NoParams

    status = await gateway.read(KibanaStatus(), NoParams(), component=component, deadline=deadline)
    version, _level = status.body
    space = gateway.targets.space
    answer = await gateway.key_privileges(
        role, request_body(role, space), component=component, deadline=deadline
    )
    verdict = judge(role, space, answer.body, accepted_residual)
    if not gateway.targets.versions.allows(version):
        problems = (f"Kibana is {version[:20]}, not {gateway.targets.versions.describe()}",)
        verdict = Verdict(problems + verdict.problems, verdict.residual)
    return version, verdict
