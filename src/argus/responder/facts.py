"""What a case shows, as a closed list of facts the catalogue's families are keyed on (Q-H2).

Each fact is something the packs already establish, read from the database only (the web's
login can run it: it reads tables the pages read, never ``signals``):

* ``c2_indicator``: the case holds a command-and-control address or name (role ``c2``), put
  there by threat intelligence or by a person (Q-C1, Q-C2);
* ``sensitive_file_served`` / ``attack_path_served``: a ``web.path_outcomes`` answer stored for
  one of the case's investigations shows a path of the kind (``web.categories``: config or
  backup files; traversal, admin pages, command injection, CMS probes) got a 2xx answer unlike
  the site's others (``paths.SUCCESS``: not the catch-all page, not "cannot compare"). That check
  needs a site and is off in production until its first run passes, so the same fact also holds
  when a log record ARGUS stored shows a 2xx answer to a path of the kind: a stored
  ``web.followups`` answer (the client's successful answers after the alert) or an alert that
  records its own one path and 2xx status (D-240). Only a path the case itself is about counts that
  way: one an alert of the case attacked or a stored path check asked about (D-245: a client's
  other 2xx answers, a public page or an image, say nothing about an attack). A path a stored
  ``web.path_outcomes`` answer decided was not served (the catch-all page, or refused) never
  counts that way;
* ``auth_failures``: an alert of a member investigation records a failed authentication
  (``event.category`` authentication with ``event.outcome`` failure) or its rule is tagged
  MITRE T1110 brute force (``kibana.alert.rule.threat``: threshold and sequence alerts copy no
  ``event.*`` fields, but they do carry the rule's tags);
* ``mail_user``: the case holds a user that is an e-mail address (the catalogue asks for a
  second fact before it advises about an account: an e-mail-shaped name alone is not an incident).

A fact is about what happened, not whether it still does: stored answers are never rewritten, so
a family stays matched after the action (the verifier says whether it went quiet). No rule name
or id is read: a rule cannot be hardcoded here (plan §3).
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.normalize.fields import values

if TYPE_CHECKING:
    from argus.context.paths import PathOutcome
    from argus.responder.catalogue import Catalogue, Family

FACTS = (
    "c2_indicator",
    "sensitive_file_served",
    "attack_path_served",
    "auth_failures",
    "mail_user",
)
SENSITIVE = "config or backup"
ATTACKS = frozenset({"traversal", "admin pages", "command injection", "cms probes"})
ALERTS_READ = 300  # the newest alerts of a case's members that are looked at
EVIDENCE_READ = 50  # stored answers read for a case: the first 50 and the newest 50 (served_paths)
BRUTE_FORCE = "T1110"  # MITRE ATT&CK: Brute Force (and its sub-techniques T1110.xxx)
THREAT_IDS = (
    "kibana.alert.rule.threat.technique.id",
    "kibana.alert.rule.threat.technique.subtechnique.id",
    "threat.technique.id",
    "threat.technique.subtechnique.id",
)
MAIL = re.compile(r"[^@\s]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,}")


@dataclass(frozen=True)
class Facts:
    """The facts a case shows, and for the web facts the paths they are about."""

    present: frozenset[str] = frozenset()
    paths: Mapping[str, frozenset[str]] = field(default_factory=lambda: MappingProxyType({}))

    def __post_init__(self) -> None:
        unknown = self.present - set(FACTS)
        if unknown:
            raise ValueError(f"no fact {', '.join(sorted(unknown))}")


def _brute_force(doc: Mapping[str, Any]) -> bool:
    """Whether an alert records failed authentications: by its event fields, or because its
    rule is tagged T1110 (a threshold or sequence alert has no ``event.*`` of its own)."""
    categories = {str(v).lower() for v in values(doc, "event.category")}
    outcomes = {str(v).lower() for v in values(doc, "event.outcome")}
    if "authentication" in categories and "failure" in outcomes:
        return True
    ids = (str(v).strip().upper() for path in THREAT_IDS for v in values(doc, path))
    return any(i == BRUTE_FORCE or i.startswith(BRUTE_FORCE + ".") for i in ids)


def outcomes_of(snapshot: Any, asked: Any) -> list[PathOutcome]:
    """The outcomes of a stored ``web.path_outcomes`` answer, or none when what is stored is not
    shaped like one (every access type-checked: one odd row must not take a case's advice down)."""
    from argus.context import paths

    if not isinstance(snapshot, Mapping) or not isinstance(asked, list):
        return []
    aggregations = snapshot.get("aggregations")
    if not isinstance(aggregations, Mapping):
        return []
    try:
        return paths.outcomes(aggregations, tuple(str(p) for p in asked))
    except (TypeError, ValueError, AttributeError, KeyError):
        return []


def _code(value: Any) -> int | None:
    try:
        return int(str(value))
    except ValueError:
        return None


def _success(source: Mapping[str, Any]) -> bool:
    return any(
        c is not None and 200 <= c < 300
        for c in (_code(v) for v in values(source, "http.response.status_code"))
    )


def answered_by_followups(snapshot: Any) -> list[str]:
    """The paths a stored ``web.followups`` answer shows with a 2xx status (the template asks for
    nothing else): the client's successful answers after the alert, each with its path."""
    rows = snapshot.get("rows") if isinstance(snapshot, Mapping) else None
    found: list[str] = []
    for row in rows if isinstance(rows, list) else []:
        source = row.get("_source") if isinstance(row, Mapping) else None
        if isinstance(source, Mapping) and _success(source):
            found += [str(v) for v in values(source, "url.path")][:5]
    return found


def answered_by_alert(doc: Mapping[str, Any]) -> list[str]:
    """The path an alert records with a 2xx status of its own: only when it names exactly one
    path (an alert of many paths and some statuses cannot say which was answered)."""
    paths_ = list(dict.fromkeys(str(v) for v in values(doc, "url.path")))
    return paths_ if len(paths_) == 1 and _success(doc) else []


def match(catalogue: Catalogue, facts: Facts) -> list[Family]:
    """The families of the case, in the catalogue's order: a family applies when every fact it
    names is present. A rule family (a noisy rule) belongs to no case."""
    return [f for f in catalogue.families if f.scope == "case" and set(f.when) <= facts.present]


SENSITIVE_FILES = frozenset(
    {".env", ".htpasswd", ".htaccess", "web.config", "wp-config.php", "config.php", "id_rsa",
     ".git", ".svn", "settings.py", "database.yml", "secrets.yml", ".npmrc", ".pgpass"}
)  # fmt: skip
SENSITIVE_EXTENSIONS = (".bak", ".old", ".sql", ".ini", ".env", ".pem", ".key")


def sensitive_file(path: str) -> bool:
    """Whether a path names a secrets, config or backup FILE exactly: its last segment is one of
    the known file names, or its final extension is one of the backup/config extensions (so
    ``/files/backup.old.pdf`` and ``/docs/config.php.txt`` are not; ``/x/.env`` and
    ``/web.config`` are). A 2xx answer to such a path is a served secret whatever the alert
    recorded (D-287); the fuzzier categories still need the case to be about the path (D-245)."""
    from argus.context import paths as outcome

    last = outcome.same_file(path).rstrip("/").rsplit("/", 1)[-1].lower()
    if not last:
        return False
    if last in SENSITIVE_FILES:
        return True
    parts = outcome.same_file(path).lower().split("/")
    if any(seg in (".git", ".svn") for seg in parts[:-1]):
        return True  # a file under a repository folder
    return any(last.endswith(ext) and last != ext for ext in SENSITIVE_EXTENSIONS)


def attacked_paths(docs: Iterable[Mapping[str, Any]], asked: Iterable[str] = ()) -> frozenset[str]:
    """The paths (as the web server serves them: decoded, ``same_file``) the case is about: those
    its alerts record and those a stored path check asked about."""
    from argus.context import paths as outcome

    named = (str(v) for d in docs for v in values(d, "url.path"))
    return frozenset(outcome.same_file(p) for p in (*named, *asked))


def from_parts(
    indicators: Iterable[tuple[str, str, str]],
    docs: Iterable[Mapping[str, Any]],
    served: Iterable[str],
    answered: Iterable[str] = (),
    denied: Iterable[str] = (),
    asked: Iterable[str] = (),
) -> Facts:
    """The facts from a case's indicators ``(kind, value, role)``, its members' alerts and the
    paths a stored ``web.path_outcomes`` answer showed served (pure). ``answered``: paths a log
    record stored with the case shows with a 2xx status (:func:`answered_by_followups`; an
    alert's own one is read here). They count as served only if the case is about them (an alert
    of the case recorded the path, or a stored path check asked about it: ``asked``) and not if
    ``denied`` (a stored ``web.path_outcomes`` answer decided the path was the catch-all page, or
    refused): a client's 2xx answer to any other page is no sign of an attack (D-245)."""
    from argus.context import paths as outcome
    from argus.context import web

    present: set[str] = set()
    held = list(indicators)
    docs = list(docs)
    wrong = {outcome.same_file(p) for p in denied}
    about = attacked_paths(docs, asked)
    about_the_case = [
        p for p in answered if outcome.same_file(p) in about or sensitive_file(web.decode(p))
    ]  # a served secrets file counts on its own (D-287): threshold alerts record no path
    own = [p for d in docs for p in answered_by_alert(d)]  # the alert is about its own path
    served = [*served, *(p for p in (*about_the_case, *own) if outcome.same_file(p) not in wrong)]
    if any(role == "c2" for _, _, role in held):
        present.add("c2_indicator")
    if any(kind == "user" and MAIL.fullmatch(value) for kind, value, _ in held):
        present.add("mail_user")
    if any(_brute_force(doc) for doc in docs):
        present.add("auth_failures")
    paths: dict[str, set[str]] = {}
    for path in sorted(set(served)):
        kinds = set(web.categories([web.decode(path)]))
        if SENSITIVE in kinds:
            paths.setdefault("sensitive_file_served", set()).add(path)
        if kinds & ATTACKS:
            paths.setdefault("attack_path_served", set()).add(path)
    present |= set(paths)
    return Facts(frozenset(present), MappingProxyType({k: frozenset(v) for k, v in paths.items()}))


_SERVED = (
    "SELECT e.params, e.snapshot FROM evidence e JOIN case_members m"
    " ON m.investigation_id = e.investigation_id WHERE m.case_id = :c"
    " AND m.removed_at IS NULL AND e.template = :t"
    " AND e.status IN ('ok', 'empty') AND e.snapshot IS NOT NULL"
    " ORDER BY e.collected_at {order}, e.task_key LIMIT :n"
)


async def _stored(conn: AsyncConnection, case_id: uuid.UUID, template: str) -> list[Any]:
    """The first and the newest stored answers of ``template`` for the case's investigations:
    the evidence the advice was first given on, which later checks must not push out, and the
    newest."""
    out: list[Any] = []
    for order in ("ASC", "DESC"):
        rows = await conn.execute(
            text(_SERVED.format(order=order)), {"c": case_id, "t": template, "n": EVIDENCE_READ}
        )
        out += rows.all()
    return out


async def path_checks(
    conn: AsyncConnection, case_id: uuid.UUID
) -> tuple[list[str], list[str], list[str]]:
    """(served, denied, asked): the paths a stored ``web.path_outcomes`` answer of the case's
    investigations shows served, those it decided were not (the catch-all page, or refused), and
    every path such a check asked about."""
    from argus.context import paths

    served: list[str] = []
    denied: list[str] = []
    every: list[str] = []
    for row in await _stored(conn, case_id, "web.path_outcomes"):
        asked = row.params.get("paths") if isinstance(row.params, Mapping) else None
        every += [str(p) for p in asked] if isinstance(asked, list) else []
        for o in outcomes_of(row.snapshot, asked):
            if o.outcome == paths.SUCCESS:
                served.append(o.path)
            elif o.outcome in (paths.CATCH_ALL, paths.REFUSED):
                denied.append(o.path)
    return served, denied, every


async def served_paths(conn: AsyncConnection, case_id: uuid.UUID) -> list[str]:
    """The paths a stored ``web.path_outcomes`` answer of the case's investigations shows served."""
    return (await path_checks(conn, case_id))[0]


async def answered_paths(conn: AsyncConnection, case_id: uuid.UUID) -> list[str]:
    """The paths a stored ``web.followups`` answer of the case's investigations shows with a
    2xx status (the client's successful answers after the alert)."""
    found: list[str] = []
    for row in await _stored(conn, case_id, "web.followups"):
        found += answered_by_followups(row.snapshot)
    return found


async def read_facts(conn: AsyncConnection, case_id: uuid.UUID) -> Facts:
    """The facts of a case from the database (bounded: the newest alerts and stored answers)."""
    indicators = [
        (r.kind, r.value, r.role)
        for r in await conn.execute(
            text(
                "SELECT kind, value, role FROM case_indicators WHERE case_id = :c"
                " AND removed_at IS NULL"
            ),
            {"c": case_id},
        )
    ]
    docs = [
        r.raw
        for r in await conn.execute(
            text(
                "SELECT a.raw FROM case_members m JOIN investigation_alerts l"
                " ON l.investigation_id = m.investigation_id AND l.duplicate_of IS NULL"
                " JOIN alert_records a ON a.alert_id = l.alert_id WHERE m.case_id = :c"
                " AND m.removed_at IS NULL AND a.raw IS NOT NULL"
                " ORDER BY a.detected_at DESC NULLS LAST, a.alert_id LIMIT :n"
            ),
            {"c": case_id, "n": ALERTS_READ},
        )
        if isinstance(r.raw, Mapping)
    ]
    served, denied, asked = await path_checks(conn, case_id)
    return from_parts(indicators, docs, served, await answered_paths(conn, case_id), denied, asked)


def required_paths(facts: Facts, family: Family) -> frozenset[str]:
    """The paths a web verifier must see refused for ``family``: those its facts are about."""
    out: set[str] = set()
    for fact in family.when:
        out |= facts.paths.get(fact, frozenset())
    return frozenset(out)
