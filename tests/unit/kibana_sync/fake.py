"""A fake Kibana for the read-back's tests: the cases API as Kibana 8.19.12 answers it (the
shapes of tests/kibana/cassettes, the tier's recordings), driven through the real Kibana lane
(``KibanaGateway``: budgets, health, switches, the ledger) and the Elasticsearch gateway.

People act on it as in Kibana's UI: each change makes the user actions Kibana records
(``create_case``, ``comment``, ``status``, ``tags``, ``settings``, ``title``, ...), moves the
case's version and ``updated_at``. Faults: ``down`` (no connection), ``hidden`` (a case
missing from finds: refresh lag), ``between_pages`` (a hook run between two pages of a find:
paging drift), ``offset`` (Kibana's clock against ARGUS's).
"""

from __future__ import annotations

import itertools
import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from typing import Any
from urllib.parse import unquote

from argus.gateway.budget import BudgetConfig
from argus.gateway.errors import TemplateRejectedError
from argus.gateway.gateway import Gateway, Targets
from argus.gateway.health import HealthMemory
from argus.gateway.kibana.errors import UnknownOutcomeError
from argus.gateway.kibana.gateway import KibanaGateway, KibanaTargets
from argus.gateway.kibana.transport import KResponse, KWire, wire_refusal
from argus.gateway.lanes import LanePlan
from argus.gateway.state import MemoryStore
from argus.gateway.transport import WireRequest, WireResponse
from argus.kibana_sync.cycle import SyncConfig, Syncer
from argus.kibana_sync.model import SentWrite
from argus.kibana_sync.store import MemorySyncStore

SPACE = "acme-soc"
T0 = datetime(2026, 10, 26, 9, 0, tzinfo=UTC)
INDEX = f".internal.alerts-security.alerts-{SPACE}-000001"


@dataclass
class Clock:
    now: datetime = T0

    def __call__(self) -> datetime:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


def _iso(at: datetime) -> str:
    return at.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _user(name: str) -> dict[str, Any]:
    return {"email": f"{name}@example.invalid", "full_name": name.title(), "username": name}


@dataclass
class FakeKibana:
    clock: Clock
    cases: dict[str, dict[str, Any]] = field(default_factory=dict)
    actions: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    alerts: dict[str, dict[str, Any]] = field(default_factory=dict)  # id -> _source
    offset: timedelta = timedelta(0)
    down: bool = False
    hidden: set[str] = field(default_factory=set)
    between_pages: Callable[[], None] | None = None
    requests: list[KWire] = field(default_factory=list)
    es_requests: list[WireRequest] = field(default_factory=list)
    ids: Any = field(default_factory=lambda: itertools.count(1))

    # ------------------------------------------------------------------ people and ARGUS

    def _now(self) -> datetime:
        return self.clock.now + self.offset

    def _act(
        self,
        case_id: str,
        by: str,
        kind: str,
        verb: str,
        payload: dict[str, Any],
        comment_id: str | None = None,
    ) -> None:
        n = next(self.ids)
        self.actions.setdefault(case_id, []).append(
            {
                "action": verb,
                "comment_id": comment_id,
                "created_at": _iso(self._now()),
                "created_by": _user(by),
                "id": str(uuid.UUID(int=n)),
                "owner": "securitySolution",
                "payload": payload,
                "type": kind,
                "version": f"WzEsMV0{n}",
            }
        )

    def _touch(self, case_id: str, by: str) -> None:
        case = self.cases[case_id]
        case["version"] = f"WzIsMV0{next(self.ids)}"
        case["updated_at"] = _iso(self._now())
        case["updated_by"] = _user(by)

    def create(
        self,
        *,
        by: str = "argus",
        argus_case: uuid.UUID | None = None,
        title: str = "[ARGUS 1] Regular beaconing from a campus host",
        tags: tuple[str, ...] | None = None,
    ) -> str:
        case_id = str(uuid.UUID(int=10_000 + next(self.ids)))
        if tags is None:
            tags = (
                "argus",
                f"argus:case:{argus_case or uuid.uuid4()}",
                "argus:owner:argus",
                "argus:state:open",
            )
        self.cases[case_id] = {
            "assignees": [],
            "category": None,
            "closed_at": None,
            "closed_by": None,
            "comments": [],
            "connector": {"fields": None, "id": "none", "name": "none", "type": ".none"},
            "created_at": _iso(self._now()),
            "created_by": _user(by),
            "customFields": [],
            "description": "ARGUS opened this case; decisions are made in ARGUS.",
            "duration": None,
            "external_service": None,
            "id": case_id,
            "observables": [],
            "owner": "securitySolution",
            "settings": {"syncAlerts": False},
            "severity": "medium",
            "status": "open",
            "tags": list(tags),
            "title": title,
            "totalAlerts": 0,
            "totalComment": 0,
            "updated_at": None,
            "updated_by": None,
            "version": f"WzAsMV0{next(self.ids)}",
        }
        self._act(
            case_id,
            by,
            "create_case",
            "create",
            {
                "title": title,
                "tags": list(tags),
                "status": "open",
                "severity": "medium",
                "settings": {"syncAlerts": False},
                "owner": "securitySolution",
            },
        )
        return case_id

    def comment(self, case_id: str, by: str, text: str = "Looked at it.") -> None:
        cid = str(uuid.UUID(int=20_000 + next(self.ids)))
        self.cases[case_id]["totalComment"] += 1
        self._act(
            case_id,
            by,
            "comment",
            "create",
            {"comment": {"comment": text, "owner": "securitySolution", "type": "user"}},
            cid,
        )
        self._touch(case_id, by)

    def attach(self, case_id: str, by: str, alert_id: str) -> None:
        cid = str(uuid.UUID(int=30_000 + next(self.ids)))
        self.cases[case_id]["totalAlerts"] += 1
        self._act(
            case_id,
            by,
            "comment",
            "create",
            {
                "comment": {
                    "alertId": [alert_id],
                    "index": [INDEX],
                    "type": "alert",
                    "owner": "securitySolution",
                    "rule": {"id": None, "name": None},
                }
            },
            cid,
        )
        self.alerts.setdefault(alert_id, {})
        ids = self.alerts[alert_id].setdefault("kibana.alert.case_ids", [])
        ids.append(case_id)
        self._touch(case_id, by)

    def set_status(self, case_id: str, by: str, status: str) -> None:
        self.cases[case_id]["status"] = status
        self._act(case_id, by, "status", "update", {"status": status})
        self._touch(case_id, by)

    def set_field(self, case_id: str, by: str, name: str, value: Any) -> None:
        self.cases[case_id][name] = value
        self._act(case_id, by, name, "update", {name: value})
        self._touch(case_id, by)

    def add_tags(self, case_id: str, by: str, *tags: str) -> None:
        self.cases[case_id]["tags"] += list(tags)
        self._act(case_id, by, "tags", "add", {"tags": list(tags)})
        self._touch(case_id, by)

    def sync_on(self, case_id: str, by: str) -> None:
        self.cases[case_id]["settings"] = {"syncAlerts": True}
        self._act(case_id, by, "settings", "update", {"settings": {"syncAlerts": True}})
        self._touch(case_id, by)

    def delete(self, case_id: str) -> None:
        del self.cases[case_id]
        self.actions.pop(case_id, None)

    def delete_comment(self, case_id: str, by: str, comment: dict[str, Any]) -> None:
        """A comment or an alert attachment removed: Kibana records a ``comment`` action
        ``delete`` whose payload is the removed comment (the tier's recording)."""
        self.cases[case_id]["totalComment"] = max(self.cases[case_id]["totalComment"] - 1, 0)
        self._act(case_id, by, "comment", "delete", {"comment": comment})
        self._touch(case_id, by)

    def lagging_status(self, case_id: str, by: str, status: str) -> Callable[[], None]:
        """Kibana saves the case, and its user action in a second write: for a moment the
        case shows the new status and the actions are the old ones. Returns what makes the
        action visible."""
        self.cases[case_id]["status"] = status
        self._touch(case_id, by)
        return lambda: self._act(case_id, by, "status", "update", {"status": status})

    def lagging_comment(self, case_id: str, by: str, text: str) -> Callable[[], None]:
        """As ``lagging_status``, for a comment (nothing on the case itself shows it)."""
        self.cases[case_id]["totalComment"] += 1
        self._touch(case_id, by)
        payload = {"comment": {"comment": text, "owner": "securitySolution", "type": "user"}}
        return lambda: self._act(case_id, by, "comment", "create", payload)

    def alert_status(self, alert_id: str, status: str, by: str | None) -> None:
        """A status change: by a person through Kibana's UI (``by`` and the time recorded), or
        through the internal RAC route (``by=None``): Q-D1's finding #7, it records neither
        ``workflow_user`` nor ``workflow_status_updated_at``."""
        source = self.alerts.setdefault(alert_id, {})
        source["kibana.alert.workflow_status"] = status
        if by is not None:
            source["kibana.alert.workflow_status_updated_at"] = _iso(self._now())
            source["kibana.alert.workflow_user"] = by

    # ------------------------------------------------------------------ the transport

    def refusal(self, request: KWire) -> TemplateRejectedError | None:
        why = wire_refusal(request, SPACE)
        return None if why is None else TemplateRejectedError("route_refused", why)

    def _answer(self, status: int, body: Any) -> KResponse:
        return KResponse(
            status, json.dumps(body).encode(), 20.0, format_datetime(self._now(), usegmt=True)
        )

    async def send(self, request: KWire) -> KResponse:
        assert request.method == "GET", "the read-back only reads"
        self.requests.append(request)
        if self.down:
            raise UnknownOutcomeError("connection refused", reached=False)
        params = dict(request.params)
        # a repeated key (reporters=a&reporters=b) is Kibana's "any of them"
        reporters = [v for k, v in request.params if k == "reporters"]
        if reporters:
            params["reporters"] = ",".join(reporters)
        api = f"/s/{SPACE}/api"
        path = unquote(request.path)
        if path == f"{api}/status":
            return self._answer(
                200,
                {
                    "name": "kibana",
                    "version": {"number": "8.19.12"},
                    "status": {"overall": {"level": "available"}},
                },
            )
        if path == f"{api}/cases/_find":
            return self._find(params)
        rest = path.removeprefix(f"{api}/cases/")
        if rest.endswith("/user_actions/_find"):
            case_id = rest.removesuffix("/user_actions/_find")
            if case_id not in self.cases:
                return self._answer(404, {"error": "Not Found"})
            page, per = int(params["page"]), int(params["perPage"])
            items = self.actions.get(case_id, [])
            return self._answer(
                200,
                {
                    "page": page,
                    "perPage": per,
                    "total": len(items),
                    "userActions": items[(page - 1) * per : page * per],
                },
            )
        if "/" not in rest:
            if rest not in self.cases:
                return self._answer(404, {"error": "Not Found"})
            return self._answer(200, self.cases[rest])
        raise AssertionError(f"unexpected {path}")

    def _find(self, params: dict[str, str]) -> KResponse:
        page, per = int(params["page"]), int(params["perPage"])
        cases = [c for c in self.cases.values() if c["id"] not in self.hidden]
        if "reporters" in params:
            wanted = params["reporters"].split(",")
            cases = [c for c in cases if c["created_by"]["username"] in wanted]
        if "status" in params:
            cases = [c for c in cases if c["status"] == params["status"]]
        field_ = "updated_at" if params.get("sortField") == "updatedAt" else "created_at"
        desc = params.get("sortOrder") == "desc"
        dated = sorted(
            (c for c in cases if c[field_]), key=lambda c: (c[field_], c["id"]), reverse=desc
        )
        undated = sorted((c for c in cases if not c[field_]), key=lambda c: c["id"])
        ordered = dated + undated  # missing values last, either way (Elasticsearch's default)
        if page > 1 and self.between_pages is not None:
            hook, self.between_pages = self.between_pages, None
            hook()
        chunk = ordered[(page - 1) * per : page * per]
        return self._answer(
            200,
            {
                "cases": chunk,
                "page": page,
                "per_page": per,
                "total": len(ordered),
                "count_open_cases": 0,
                "count_in_progress_cases": 0,
                "count_closed_cases": 0,
            },
        )


@dataclass
class FakeAlerts:
    """The Elasticsearch side: ``alerts.case_links`` over the fake's alerts."""

    kibana: FakeKibana

    async def send(self, request: WireRequest) -> WireResponse:
        self.kibana.es_requests.append(request)
        body = json.loads(request.body) if request.body else {}
        filters = body["query"]["bool"]["filter"]
        hits = []
        for alert_id, source in sorted(self.kibana.alerts.items()):
            ok = True
            for clause in filters:
                if "terms" in clause:
                    wanted = set(clause["terms"]["kibana.alert.case_ids"])
                    ok &= bool(wanted & set(source.get("kibana.alert.case_ids", [])))
                elif "ids" in clause:
                    ok &= alert_id in clause["ids"]["values"]
                elif "exists" in clause:
                    ok &= bool(source.get("kibana.alert.case_ids"))
            if ok:
                hits.append(
                    {
                        "_id": alert_id,
                        "_index": INDEX,
                        "_score": None,
                        "_source": dict(source),
                        "sort": [1, alert_id],
                    }
                )
        after = body.get("search_after")
        if after is not None:
            hits = [h for h in hits if h["_id"] > after[1]]
        hits = hits[: body["size"]]
        answer = {
            "took": 1,
            "timed_out": False,
            "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
            "hits": {"hits": hits, "max_score": None},
        }
        return WireResponse(200, json.dumps(answer).encode(), 5.0)


@dataclass
class Rig:
    clock: Clock
    kibana: FakeKibana
    lane: MemoryStore
    store: MemorySyncStore
    syncer: Syncer

    def healthy(self) -> None:
        """The health probe keeps running meanwhile (every few seconds in production): the
        memory stays fresh for the whole cycle."""
        self.lane.memory = HealthMemory(probed_at=self.clock.now + timedelta(hours=2))

    def sent(self, case: uuid.UUID, *writes: SentWrite) -> None:
        self.store.sent.setdefault(case, []).extend(writes)

    async def cycle(
        self,
        *,
        advance: timedelta = timedelta(minutes=10),
        within: timedelta = timedelta(minutes=9),
    ) -> Any:
        self.clock.now += advance
        self.healthy()
        return await self.syncer.cycle(deadline=self.clock.now + within)

    def reads(self, *, status: str | None = None) -> list[dict[str, str]]:
        """The ``cases.find`` requests so far (their query), optionally of one status."""
        found = [dict(w.params) for w in self.kibana.requests if w.path.endswith("/cases/_find")]
        return [p for p in found if status is None or p.get("status") == status]


def rig(*, config: SyncConfig | None = None, es: bool = True) -> Rig:
    clock = Clock()
    kibana = FakeKibana(clock)
    lane = MemoryStore(
        memory=HealthMemory(probed_at=T0), budget_config=BudgetConfig(), lane_plan=LanePlan()
    )
    es_gateway = (
        Gateway(FakeAlerts(kibana), lane, targets=Targets(), clock=clock, sleep=clock.sleep)
        if es
        else None
    )
    gateway = KibanaGateway(
        kibana,
        lane,
        targets=KibanaTargets(space=SPACE),
        clock=clock,
        sleep=clock.sleep,
        es_gateway=es_gateway,
    )
    store = MemorySyncStore()
    syncer = Syncer(
        gateway,
        store,
        lane,
        es=es_gateway,
        config=config or SyncConfig(),
        clock=clock,
        sleep=clock.sleep,
    )
    return Rig(clock, kibana, lane, store, syncer)


CREATE = SentWrite("create", frozenset(), 1)
COMMENT = SentWrite("comment", frozenset(), 1)
UPDATE_STATUS_TAGS = SentWrite("update", frozenset({"status", "argus_tags"}), 1)
