"""A fake Kibana for the case team (AR8): the writable fake of the case writer's tests, taught the
case team's routes: a case opened by one of six users, comments by their own names, a file in
the Files tab, tags on alerts, and the case with its comments in every answer, as Kibana 8.19.12
answers (the shapes of tests/kibana/cassettes). Faults are the writable fake's (``fail``, ``lose``,
``timeout``, ``garbage``)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote

from argus.gateway.kibana import upload
from argus.gateway.kibana.errors import UnknownOutcomeError
from argus.gateway.kibana.templates import KeyRole
from argus.gateway.kibana.transport import KWire
from tests.integration.writer.fake import API, Fault, WritableEs, WritableKibana, posts
from tests.unit.kibana_sync.fake import INDEX, SPACE, _iso

__all__ = [
    "API",
    "INDEX",
    "SPACE",
    "Crash",
    "Fault",
    "TeamKibana",
    "WritableEs",
    "posts",
    "writes_by",
]


class Crash(BaseException):
    """The poster's process is killed while a request is on its way."""


def writes_by(user: str, path_end: str, nth: int = 1, *, containing: str = "") -> Any:
    """A matcher for the ``nth`` write of ``user`` to a path ending in ``path_end`` (whose body
    holds ``containing``); a fresh counter for each matcher."""
    seen = {"n": 0}

    def match(wire: KWire) -> bool:
        if wire.method != "POST" or wire.as_user != user or not wire.path.endswith(path_end):
            return False
        if containing and containing.encode() not in (wire.body or b""):
            return False
        seen["n"] += 1
        return seen["n"] == nth

    return match


@dataclass
class TeamKibana(WritableKibana):
    crashes: list[tuple[Any, bool]] = field(default_factory=list)  # (when, apply it first)
    alert_tags: dict[str, set[str]] = field(default_factory=dict)
    gone: set[str] = field(default_factory=set)  # alerts the index lifecycle removed
    comment_reads: int = 0  # pages of a case's comments asked for
    conflicts: dict[str, int] = field(default_factory=dict)  # alert -> tag calls it will refuse
    files: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    by_user: list[tuple[str, str]] = field(default_factory=list)  # (user, "METHOD path") of writes
    synced: list[tuple[str, str]] = field(default_factory=list)  # (alert, status) Sync alerts set

    async def send(self, request: KWire) -> Any:
        if self.down and request.method == "GET":  # a read finds Kibana down too
            self.requests.append(request)
            raise UnknownOutcomeError("connection refused", reached=False)
        for crash in list(self.crashes):
            when, applied = crash
            if when(request):
                self.crashes.remove(crash)
                self.requests.append(request)
                if applied:
                    self._apply(request)
                raise Crash(request.path)
        return await super().send(request)

    def _comments(self, path: str, params: dict[str, str]) -> Any:
        self.comment_reads += 1
        return super()._comments(path, params)

    def person_comment(self, case_id: str, by: str, text: str) -> str:
        """A person's comment, as Kibana keeps it: on the case, in its listing and its actions."""
        self.comment(case_id, by, text)
        entry = {
            "comment": text,
            "type": "user",
            "owner": "securitySolution",
            "created_by": {"username": by, "full_name": by, "email": f"{by}@example.invalid"},
            "created_at": _iso(self._now()),
            "updated_at": None,
            "updated_by": None,
            "id": f"p-{len(self.comments.get(case_id, [])) + 1}",
            "version": f"WzEsMV0{next(self.ids)}",
        }
        self.comments.setdefault(case_id, []).append(entry)
        case = self.cases[case_id]
        case["comments"] = [*case["comments"], entry]
        return str(entry["id"])

    def edit_comment(self, case_id: str, comment_id: str, by: str, text: str) -> None:
        """Somebody edits a comment, as Kibana records it: the new text, who changed it and when
        (``updated_by`` / ``updated_at``), and the case moves on."""
        for entry in (
            *self.comments.get(case_id, []),
            *self.cases[case_id]["comments"],
        ):
            if entry.get("id") == comment_id:
                entry["comment"] = text
                entry["version"] = f"WzEyLDFd{next(self.ids)}"
                entry["updated_by"] = {
                    "username": by, "full_name": by, "email": f"{by}@example.invalid"
                }  # fmt: skip
                entry["updated_at"] = _iso(self._now())
        self._touch(case_id, by)

    def _who(self, request: KWire) -> str:
        if request.key is KeyRole.TEAM:
            assert request.as_user is not None
            return request.as_user
        return self.author

    def _apply(self, request: KWire, at: Any = None) -> tuple[int, Any]:
        self.writes.append(request)
        self.written_at.append(at or self.clock.now)
        who = self._who(request)
        path = unquote(request.path)
        self.by_user.append((who, f"{request.method} {path.removeprefix(API)}"))
        saved = self.clock.now
        if at is not None:
            self.clock.now = at
        try:
            if request.method == "POST" and path.endswith("/files"):
                return self._file(
                    path.removeprefix(f"{API}/cases/").removesuffix("/files"), who, request
                )
            body = json.loads(request.body) if request.body else {}
            if request.method == "POST" and path == f"{API}/cases":
                return 200, self._create_as(who, body)
            if request.method == "POST" and path.endswith("/comments"):
                return self._comment_as(
                    who, path.removeprefix(f"{API}/cases/").removesuffix("/comments"), body
                )
            if request.method == "POST" and path.endswith("/signals/tags"):
                return 200, self._tags(body)
            if request.method == "PATCH" and path == f"{API}/cases":
                return self._patch_team(who, body)
            if request.method == "PATCH" and path.endswith("/comments"):
                return self._edit_as(
                    who, path.removeprefix(f"{API}/cases/").removesuffix("/comments"), body
                )
        finally:
            self.clock.now = saved
        raise AssertionError(f"unexpected write {request.method} {path}")

    def _patch_team(self, who: str, body: dict[str, Any]) -> tuple[int, Any]:
        """PATCH /api/cases as Kibana answers it: 404 for a case it does not hold, 409 when the
        version is not the case's, else the new title and description and the updated case."""
        out = []
        for change in body["cases"]:
            case = self.cases.get(change["id"])
            if case is None:
                return 404, {"message": "not found"}
            if case["version"] != change["version"]:
                return 409, {"message": "version conflict"}
            extra = set(change) - {"id", "version", "title", "description"}
            if extra:
                return 400, {"message": f"unexpected {sorted(extra)}"}
            for field_name in ("title", "description"):
                if field_name in change:
                    case[field_name] = change[field_name]
                    # Kibana records each as a user action of its own (the read-back's evidence)
                    self._act(
                        case["id"], who, field_name, "update", {field_name: change[field_name]}
                    )
            self._touch(case["id"], who)
            out.append(dict(case))
        return 200, out

    def _edit_as(self, who: str, case_id: str, body: dict[str, Any]) -> tuple[int, Any]:
        """PATCH /api/cases/{id}/comments: only the comment's author may edit it, against the
        comment's version; the answer is the whole case."""
        case = self.cases.get(case_id)
        if case is None:
            return 404, {"message": "not found"}
        for entry in case["comments"]:
            if entry.get("id") != body["id"]:
                continue
            if entry["created_by"]["username"] != who:
                return 403, {"message": "only the author may edit a comment"}
            if entry.get("version") != body["version"]:
                return 409, {"message": "version conflict"}
            if body["type"] != entry["type"] or body["owner"] != entry["owner"]:
                return 400, {"message": "type and owner cannot change"}
            entry["comment"] = body["comment"]
            entry["version"] = f"WzEwLDFd{next(self.ids)}"
            entry["updated_by"] = {"username": who, "full_name": who}
            entry["updated_at"] = _iso(self._now())
            self._act(case_id, who, "comment", "update", {"comment": dict(entry)}, str(entry["id"]))
            self._touch(case_id, who)
            return 200, dict(case)
        return 404, {"message": "no such comment"}

    def person_edits_title(self, case_id: str, by: str, title: str) -> None:
        """A person changes the case's title in Kibana."""
        self.cases[case_id]["title"] = title
        self._touch(case_id, by)

    def person_edits_description(self, case_id: str, by: str, text: str) -> None:
        self.cases[case_id]["description"] = text
        self._touch(case_id, by)

    def _create_as(self, who: str, body: dict[str, Any]) -> dict[str, Any]:
        case_id = self.create(by=who, title=body["title"], tags=tuple(body["tags"]))
        case = self.cases[case_id]
        case["description"] = body["description"]
        case["severity"] = body["severity"]
        case["settings"] = dict(body["settings"])
        return dict(case)

    def _comment_as(self, who: str, case_id: str, body: dict[str, Any]) -> tuple[int, Any]:
        if case_id not in self.cases:
            return 404, {"message": "not found"}
        case = self.cases[case_id]
        if body["type"] == "user":
            self.comment(case_id, who, body["comment"])
            entry = {
                "comment": body["comment"],
                "type": "user",
                "owner": "securitySolution",
                "created_by": {
                    "username": who,
                    "full_name": who,
                    "email": f"{who}@example.invalid",
                },
                "created_at": _iso(self._now()),
                "id": f"c-{len(self.comments.get(case_id, [])) + 1}",
                "version": f"WzEsMV0{next(self.ids)}",
            }
            self.comments.setdefault(case_id, []).append(entry)
            case["comments"] = [*list(case["comments"]), entry]
            return 200, dict(case)
        ids = body["alertId"]
        case["totalAlerts"] += len(ids)
        if case["settings"].get("syncAlerts"):  # Kibana sets the alerts to the case's status
            for alert_id in ids:
                self.alerts.setdefault(alert_id, {})["kibana.alert.workflow_status"] = case[
                    "status"
                ]
                self.synced.append((alert_id, case["status"]))
        for alert_id in ids:
            self.alerts.setdefault(alert_id, {}).setdefault("kibana.alert.case_ids", []).append(
                case_id
            )
        self._act(case_id, who, "comment", "create", {"comment": body})
        self._touch(case_id, who)
        return 200, dict(case)

    def _file(self, case_id: str, who: str, request: KWire) -> tuple[int, Any]:
        if case_id not in self.cases:
            return 404, {"message": "not found"}
        assert request.body is not None
        made = upload.decode(request.body)
        assert request.content_type.startswith("multipart/form-data; boundary=")
        case = self.cases[case_id]
        meta = {
            "files": [
                {
                    "name": made.filename,
                    "extension": made.full_name.rsplit(".", 1)[1],
                    "mimeType": made.mime,
                    "size": len(made.data),
                }
            ]
        }
        entry = {
            "type": "externalReference",
            "externalReferenceAttachmentTypeId": ".files",
            "externalReferenceMetadata": meta,
            "owner": "securitySolution",
            "created_by": {"username": who},
            "created_at": _iso(self._now()),
            "id": f"f-{len(self.files.get(case_id, [])) + 1}",
        }
        self.files.setdefault(case_id, []).append(
            {"name": made.full_name, "mime": made.mime, "data": made.data, "by": who}
        )
        case["comments"] = [*list(case["comments"]), entry]
        case["totalComment"] += 1
        self._act(case_id, who, "comment", "create", {"comment": entry}, entry["id"])
        self._touch(case_id, who)
        return 200, dict(case)

    def _tags(self, body: dict[str, Any]) -> dict[str, Any]:
        """Kibana's update report: only alerts the index still holds are matched (``total``), a
        matched alert may meet a version conflict (a rule rewrote it) and is then not updated."""
        named = list(body["ids"])
        here = [a for a in named if a in self.alerts and a not in self.gone]
        conflicts = 0
        for alert_id in here:
            if self.conflicts.get(alert_id, 0) > 0:
                self.conflicts[alert_id] -= 1
                conflicts += 1
                continue
            self.alert_tags.setdefault(alert_id, set()).update(body["tags"]["tags_to_add"])
        return {
            "took": 3,
            "timed_out": False,
            "total": len(here),
            "updated": len(here) - conflicts,
            "deleted": 0,
            "batches": 1,
            "version_conflicts": conflicts,
            "noops": 0,
            "failures": [],
        }

    def lose_alerts(self, *alert_ids: str) -> None:
        """Index lifecycle removed these alerts: the index no longer holds them."""
        for alert_id in alert_ids:
            self.gone.add(alert_id)
            self.alerts.pop(alert_id, None)

    # ------------------------------------------------------------------ what tests ask

    def team_cases(self) -> list[dict[str, Any]]:
        return [c for c in self.cases.values() if "incident" in c["tags"]]

    def user_comments(self, case_id: str) -> list[tuple[str, str]]:
        return [
            (c["created_by"]["username"], c["comment"])
            for c in self.cases[case_id]["comments"]
            if c["type"] == "user"
        ]
