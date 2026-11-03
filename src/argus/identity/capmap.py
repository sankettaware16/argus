"""The capability map: what a person may do in ARGUS, from what their own ELK credential holds.

Versioned and built on **actions**, never role names. Capabilities: view, see_logs, review,
manage_cases, reopen, approve, admin (each checked with Kibana's ``ui:`` and API actions and index
privileges on the alerts and logs; see ``needs_for``). ``answer_gold`` is not ELK's to give: it is
review plus being a gold-key owner in ARGUS. The Kibana feature ids are the defaults of
``site.kibana_features``; a Kibana upgrade that renames a feature grants nothing until the ids are
updated (fail closed). A privilege counts only when the answer says ``true``; the **cluster
canaries** are the other way round: an account the answer leaves unclear counts as an admin account.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from argus import site
from argus.web.capabilities import Capability, effective

MAP_VERSION = 1
KIBANA_VERSION = "8.19.12"
SECURITY_FEATURE = "siemV2"
CASES_FEATURE = "securitySolutionCasesV3"
KIBANA_APP = "kibana-.kibana"  # Kibana's application in Elasticsearch's privilege store
ARGUS_APP = "argus"
ARGUS_RESOURCE = "*"  # argus_approver and argus_admin grant on "*"
CASES = "cases:securitySolution/"

# The cluster privileges an everyday account must not hold. ``all`` is a superuser's.
SUPERUSER_CANARY = "all"
ADMIN_CANARIES = (
    "manage",
    "manage_security",
    "manage_api_key",
    "grant_api_key",
    "manage_service_account",
)
CLUSTER_CANARIES = (SUPERUSER_CANARY, *ADMIN_CANARIES)


@dataclass(frozen=True)
class Needs:
    """What one capability checks: Kibana actions in the space, index privileges on the alerts
    or the logs, and ``argus`` actions."""

    kibana: tuple[str, ...] = ()
    alerts: tuple[str, ...] = ()
    logs: tuple[str, ...] = ()
    argus: tuple[str, ...] = ()


def needs_for(security_feature: str, cases_feature: str) -> Mapping[Capability, Needs]:
    """What each capability checks, for Kibana's Security and Cases feature ids."""
    return {
        Capability.VIEW: Needs(kibana=("login:", f"ui:{security_feature}/show"), alerts=("read",)),
        Capability.SEE_LOGS: Needs(logs=("read",)),
        Capability.REVIEW: Needs(alerts=("index", "maintenance")),
        Capability.MANAGE_CASES: Needs(
            kibana=(
                f"{CASES}createCase",
                f"{CASES}updateCase",
                f"{CASES}createComment",
                f"ui:{cases_feature}/create_cases",
                f"ui:{cases_feature}/update_cases",
                f"ui:{cases_feature}/create_comment",
            )
        ),
        Capability.REOPEN: Needs(kibana=(f"{CASES}reopenCase", f"ui:{cases_feature}/case_reopen")),
        Capability.APPROVE: Needs(argus=("argus:approve",)),
        Capability.ADMIN: Needs(argus=("argus:admin",)),
    }


NEEDS: Mapping[Capability, Needs] = needs_for(SECURITY_FEATURE, CASES_FEATURE)  # the defaults
FROM_ELK: tuple[Capability, ...] = tuple(NEEDS)  # every capability but answer_gold


@dataclass(frozen=True)
class Targets:
    """Where the map's privileges are checked: the space, the log indices and Kibana's feature
    ids (unless given, the site profile's). The log indices are the site's ``checked_log_patterns``
    (each family's own pattern unless the site names wider ones): a key granted exactly the
    families has ``see_logs``, one granted a wider ``logs-*`` that its own team's streams share
    is not asked about those."""

    space: str = field(default_factory=lambda: site.active().space)
    log_patterns: tuple[str, ...] = field(
        default_factory=lambda: site.active().checked_log_patterns
    )
    security_feature: str = field(default_factory=lambda: site.active().kibana_features.security)
    cases_feature: str = field(default_factory=lambda: site.active().kibana_features.cases)

    @property
    def needs(self) -> Mapping[Capability, Needs]:
        return needs_for(self.security_feature, self.cases_feature)

    @property
    def resource(self) -> str:
        return f"space:{self.space}"

    @property
    def alerts(self) -> tuple[str, ...]:
        """The alerts alias and its backing indices: both must grant (an alias can be granted
        apart from what it points to)."""
        return (
            site.active().alerts_index_of(self.space),
            site.active().alerts_backing_of(self.space) + "*",
        )


def _sorted_union(*parts: tuple[str, ...]) -> list[str]:
    return sorted({name for part in parts for name in part})


def request_body(targets: Targets) -> dict[str, Any]:
    """The one ``_has_privileges`` body that answers the whole map and the canaries."""
    needs = list(targets.needs.values())
    body: dict[str, Any] = {
        "cluster": list(CLUSTER_CANARIES),
        "index": [
            {"names": [name], "privileges": _sorted_union(*(n.alerts for n in needs))}
            for name in targets.alerts
        ]
        + (
            [
                {
                    "names": list(targets.log_patterns),
                    "privileges": _sorted_union(*(n.logs for n in needs)),
                }
            ]
            if targets.log_patterns
            else []
        ),
        "application": [
            {
                "application": KIBANA_APP,
                "resources": [targets.resource],
                "privileges": _sorted_union(*(n.kibana for n in needs)),
            },
            {
                "application": ARGUS_APP,
                "resources": [ARGUS_RESOURCE],
                "privileges": _sorted_union(*(n.argus for n in needs)),
            },
        ],
    }
    return body


def _held(table: Any, *path: str) -> Mapping[str, Any]:
    """``table[path...]`` if every step is a mapping, else an empty mapping."""
    for step in path:
        table = table.get(step) if isinstance(table, Mapping) else None
    return table if isinstance(table, Mapping) else {}


def _all_true(table: Mapping[str, Any], names: tuple[str, ...]) -> bool:
    return all(table.get(name) is True for name in names)


@dataclass(frozen=True)
class Privileges:
    """What the answer says the credential holds, reduced to the map's questions."""

    capabilities: frozenset[Capability]  # from ELK, prerequisites applied
    superuser: bool  # holds cluster ``all`` (or the answer does not say it does not)
    admin_account: bool  # holds an admin canary (or the answer does not say it does not)
    map_version: int = MAP_VERSION


class IncompleteAnswerError(ValueError):
    """The answer does not state every privilege the map asked about: it is no verdict."""


def _complete(table: Mapping[str, Any], names: Iterable[str], where: str) -> None:
    missing = [name for name in names if not isinstance(table.get(name), bool)]
    if missing:
        raise IncompleteAnswerError(f"{where}: {', '.join(sorted(missing))} not stated")


def read(answer: Any, targets: Targets) -> Privileges:
    """The map applied to a ``_has_privileges`` answer. Anything the answer does not state as
    ``true`` is not held; any canary it does not state as ``false`` is held. An answer that
    does not state every privilege asked (a truncated or partial one) is ``IncompleteAnswerError``:
    the caller treats it as unavailable, not as the person's verdict."""
    kibana = _held(answer, "application", KIBANA_APP, targets.resource)
    argus = _held(answer, "application", ARGUS_APP, ARGUS_RESOURCE)
    alerts = [_held(answer, "index", name) for name in targets.alerts]
    logs = [_held(answer, "index", name) for name in targets.log_patterns]
    asked = list(targets.needs.values())
    _complete(_held(answer, "cluster"), CLUSTER_CANARIES, "cluster")
    _complete(kibana, _sorted_union(*(n.kibana for n in asked)), KIBANA_APP)
    _complete(argus, _sorted_union(*(n.argus for n in asked)), ARGUS_APP)
    for name, table in zip(targets.alerts, alerts, strict=True):
        _complete(table, _sorted_union(*(n.alerts for n in asked)), name)
    for name, table in zip(targets.log_patterns, logs, strict=True):
        _complete(table, _sorted_union(*(n.logs for n in asked)), name)
    held = set()
    for capability, needs in targets.needs.items():
        if (
            _all_true(kibana, needs.kibana)
            and all(_all_true(table, needs.alerts) for table in alerts)
            and (not needs.logs or (bool(logs) and all(_all_true(t, needs.logs) for t in logs)))
            and _all_true(argus, needs.argus)
        ):
            held.add(capability)
    cluster = _held(answer, "cluster")
    return Privileges(
        capabilities=effective(held),
        superuser=cluster.get(SUPERUSER_CANARY) is not False,
        admin_account=any(cluster.get(name) is not False for name in ADMIN_CANARIES),
    )


def describe() -> list[tuple[str, str]]:
    """(capability, what it checks) in plain words, for ``argus identity map``."""
    out: list[tuple[str, str]] = []
    for capability, needs in NEEDS.items():
        parts = []
        if needs.kibana:
            parts.append("Kibana " + ", ".join(needs.kibana))
        if needs.alerts:
            parts.append(", ".join(needs.alerts) + " on the alerts")
        if needs.logs:
            parts.append(", ".join(needs.logs) + " on the logs")
        if needs.argus:
            parts.append("argus " + ", ".join(needs.argus))
        out.append((capability.value, "; ".join(parts)))
    out.append((Capability.ANSWER_GOLD.value, "review, and named a gold-key owner in ARGUS"))
    return out
