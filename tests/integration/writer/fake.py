"""A fake Kibana that takes writes (Q-D4's tests): the cases API as Kibana 8.19.12 answers it
(the shapes of tests/kibana/cassettes), behind the real Kibana lane.

It extends the read-back's fake (``tests/unit/kibana_sync/fake.py``) with POST (a case, a
comment, an alert attachment) and PATCH, the user actions Kibana records for each, the comments'
listing and the alerts' case ids. Faults, per request: ``fail`` (a status Kibana answers
without changing anything, or an unreadable answer), ``lose`` (the connection fails before
Kibana did anything), ``timeout`` (the answer never arrives: Kibana applies the request at once,
or ``land_after`` seconds later, by its own clock, or never)."""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any
from urllib.parse import unquote

from argus.gateway.kibana.errors import UnknownOutcomeError
from argus.gateway.kibana.transport import KResponse, KWire
from argus.gateway.transport import WireRequest, WireResponse
from tests.unit.kibana_sync.fake import (
    INDEX,
    SPACE,
    FakeAlerts,
    FakeKibana,
    _iso,
)

API = f"/s/{SPACE}/api"


@dataclass
class Fault:
    """What happens to the next request ``when`` matches; used once unless ``times`` says more."""

    when: Callable[[KWire], bool]
    kind: str  # "status", "lose", "timeout", "garbage"
    status: int = 500
    land_after: float | None = 0.0  # timeout: when Kibana applies it (seconds), None: never
    times: int = 1


def posts(path_end: str = "") -> Callable[[KWire], bool]:
    return lambda w: w.method == "POST" and w.path.endswith(path_end)


def patches() -> Callable[[KWire], bool]:
    return lambda w: w.method == "PATCH"


@dataclass
class WritableKibana(FakeKibana):
    author: str = "argus"
    faults: list[Fault] = field(default_factory=list)
    landing: list[tuple[Any, KWire]] = field(default_factory=list)  # (when, request)
    comments: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    writes: list[KWire] = field(default_factory=list)  # every write that reached Kibana
    written_at: list[Any] = field(default_factory=list)  # when each of them did
    extra_privileges: set[str] = field(default_factory=set)  # the writer key holds too much
    missing_privileges: set[str] = field(default_factory=set)  # ... or too little

    # ------------------------------------------------------------------ the transport

    async def send(self, request: KWire) -> KResponse:
        self.tick()
        if request.method == "GET":
            path = unquote(request.path)
            if path.endswith("/comments/_find"):
                return self._comments(path, dict(request.params))
            if path == f"{API}/cases/configure":
                return self._answer(200, [])
            return await super().send(request)
        self.requests.append(request)
        if self.down:
            raise UnknownOutcomeError("connection refused", reached=False)
        if request.target == "es":
            return self._answer(200, self._privileges(json.loads(request.body or b"{}")))
        fault = self._take_fault(request)
        if fault is not None:
            if fault.kind == "lose":
                raise UnknownOutcomeError(
                    "connection reset before Kibana did anything", reached=False
                )
            if fault.kind == "status":
                return self._answer(fault.status, {"message": "refused"})
            if fault.kind == "garbage":
                self._apply(request)  # Kibana did it; the answer is not JSON
                return KResponse(200, b"<html>", 20.0, None)
            if fault.kind == "timeout":
                if fault.land_after is not None and fault.land_after <= 0:
                    self._apply(request)
                elif fault.land_after is not None:
                    self.landing.append(
                        (self.clock.now + timedelta(seconds=fault.land_after), request)
                    )
                raise UnknownOutcomeError("timed out", reached=True, timed_out=True)
        status, body = self._apply(request)
        return self._answer(status, body)

    def _take_fault(self, request: KWire) -> Fault | None:
        for fault in self.faults:
            if fault.when(request):
                fault.times -= 1
                if fault.times <= 0:
                    self.faults.remove(fault)
                return fault
        return None

    def tick(self) -> None:
        """Requests that were still on their way when ARGUS gave up reach Kibana now."""
        due = [item for item in self.landing if item[0] <= self.clock.now]
        for item in due:
            self.landing.remove(item)
            self._apply(item[1], at=item[0])

    def _privileges(self, body: dict[str, Any]) -> dict[str, Any]:
        """``_has_privileges`` for the cases writer: what its profile holds, plus ``extra``
        (a privilege it should not have) and minus ``missing``."""
        from argus.gateway.kibana import selftest
        from argus.gateway.kibana.templates import KeyRole

        profile = selftest.PROFILES[KeyRole.CASES]
        held = (set(profile.must_app) | self.extra_privileges) - self.missing_privileges
        asked = body["application"][0]["privileges"]
        resource = body["application"][0]["resources"][0]
        answer: dict[str, Any] = {
            "has_all_requested": False,
            "cluster": dict.fromkeys(body.get("cluster", []), False),
            "application": {selftest.APP: {resource: {p: p in held for p in asked}}},
        }
        if "index" in body:
            names = body["index"][0]
            answer["index"] = {names["names"][0]: dict.fromkeys(names["privileges"], False)}
        return answer

    # ------------------------------------------------------------------ the cases API

    def _apply(self, request: KWire, at: Any = None) -> tuple[int, Any]:
        self.writes.append(request)
        self.written_at.append(at or self.clock.now)
        body = json.loads(request.body) if request.body else {}
        path = unquote(request.path)
        saved = self.clock.now
        if at is not None:
            self.clock.now = at
        try:
            if request.method == "POST" and path == f"{API}/cases":
                return 200, self._create(body)
            if request.method == "POST" and path.endswith("/comments"):
                case_id = path.removeprefix(f"{API}/cases/").removesuffix("/comments")
                return self._comment(case_id, body)
            if request.method == "PATCH" and path == f"{API}/cases":
                return self._patch(body)
        finally:
            self.clock.now = saved
        raise AssertionError(f"unexpected write {request.method} {path}")

    def _create(self, body: dict[str, Any]) -> dict[str, Any]:
        case_id = self.create(by=self.author, title=body["title"], tags=tuple(body["tags"]))
        case = self.cases[case_id]
        case["description"] = body["description"]
        case["severity"] = body["severity"]
        case["settings"] = dict(body["settings"])
        return dict(case)

    def _comment(self, case_id: str, body: dict[str, Any]) -> tuple[int, Any]:
        if case_id not in self.cases:
            return 404, {"message": "not found"}
        case = self.cases[case_id]
        if body["type"] == "user":
            self.comment(case_id, self.author, body["comment"])
            self.comments.setdefault(case_id, []).append(
                {"comment": body["comment"], "type": "user",
                 "created_by": {"username": self.author}, "created_at": _iso(self._now())}
            )  # fmt: skip
            return 200, dict(case)
        ids = body["alertId"]
        case["totalAlerts"] += len(ids)
        for alert_id in ids:
            self.alerts.setdefault(alert_id, {}).setdefault("kibana.alert.case_ids", []).append(
                case_id
            )
        self._act(case_id, self.author, "comment", "create", {"comment": body})
        self._touch(case_id, self.author)
        return 200, dict(case)

    def _patch(self, body: dict[str, Any]) -> tuple[int, Any]:
        out = []
        for change in body["cases"]:
            case = self.cases.get(change["id"])
            if case is None:
                return 404, {"message": "not found"}
            if case["version"] != change["version"]:
                return 409, {"message": "version conflict"}
            if "status" in change:
                self.set_status(case["id"], self.author, change["status"])
            if "severity" in change:
                self.set_field(case["id"], self.author, "severity", change["severity"])
            if "tags" in change:
                case["tags"] = list(change["tags"])
                self._act(case["id"], self.author, "tags", "add", {"tags": change["tags"]})
                self._touch(case["id"], self.author)
            out.append(dict(self.cases[change["id"]]))
        return 200, out

    def _comments(self, path: str, params: dict[str, str]) -> KResponse:
        case_id = path.removeprefix(f"{API}/cases/").removesuffix("/comments/_find")
        if case_id not in self.cases:
            return self._answer(404, {"message": "not found"})
        listed = list(self.comments.get(case_id, []))
        if params.get("sortOrder") == "desc":
            listed.reverse()
        page, per = int(params.get("page", "1")), int(params.get("perPage", "20"))
        chunk = listed[(page - 1) * per : page * per]
        return self._answer(
            200, {"comments": chunk, "page": page, "per_page": per, "total": len(listed)}
        )

    def _find(self, params: dict[str, str]) -> KResponse:
        if "tags" not in params:
            return super()._find(params)
        saved = set(self.hidden)
        self.hidden |= {c["id"] for c in self.cases.values() if params["tags"] not in c["tags"]}
        try:
            return super()._find(params)
        finally:
            self.hidden = saved

    # ------------------------------------------------------------------ what tests ask

    def ours(self, tag_prefix: str = "argus:case:") -> list[dict[str, Any]]:
        return [c for c in self.cases.values() if any(t.startswith(tag_prefix) for t in c["tags"])]

    def count(self, method: str, suffix: str = "") -> int:
        """Writes Kibana applied."""
        return sum(1 for w in self.writes if w.method == method and w.path.endswith(suffix))

    def attempts(self, method: str, suffix: str = "") -> int:
        """Requests that reached Kibana, applied or refused."""
        return sum(1 for w in self.requests if w.method == method and w.path.endswith(suffix))


@dataclass
class WritableEs(FakeAlerts):
    """The Elasticsearch side: the licence and the alerts' case ids."""

    async def send(self, request: WireRequest) -> WireResponse:
        if request.path.endswith("/_license"):
            body = {"license": {"type": "basic", "status": "active"}}
            return WireResponse(200, json.dumps(body).encode(), 3.0)
        return await super().send(request)


def make_alert(kibana: FakeKibana, alert_id: str, *, cases: int = 0) -> None:
    """An alert in the alerts index, already listed in ``cases`` other cases."""
    source = kibana.alerts.setdefault(alert_id, {})
    if cases:
        source["kibana.alert.case_ids"] = [str(uuid.UUID(int=900_000 + n)) for n in range(cases)]


__all__ = [
    "INDEX",
    "SPACE",
    "Fault",
    "WritableEs",
    "WritableKibana",
    "make_alert",
    "patches",
    "posts",
]
