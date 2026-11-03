"""The Kibana lane's only path builder (Q-D2): every path ARGUS can send to Kibana.

One function, ``wire_path``, turns an endpoint and its ids into (method, path), exhaustively:
each endpoint has its own case and an endpoint without one is an error, never a fallback.
Every path starts with the space prefix ``/s/<space>/api/`` (plan §7.10, tenant isolation: a
credential of two spaces would otherwise act in the default space, and the alert status route
answers 200 there having changed nothing). No path deletes, pushes, writes the case
configuration or reaches ``/internal/``: such endpoints do not exist here, and ``refusal``
names the reason for any path that would (the validator and the transport ask it again).
``built`` is the allowlist the transport holds every request to: the (method, path) must be one
``wire_path`` builds, for some endpoint and well-formed ids.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from functools import cache
from typing import assert_never

SPACE = re.compile(r"[a-z0-9_-]{1,64}")
CASE_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
ALERT_ID = re.compile(r"[A-Za-z0-9_-]{1,128}")
METHODS = frozenset({"GET", "POST", "PATCH"})
WRITE_METHODS = frozenset({"POST", "PATCH"})


class KEndpoint(StrEnum):
    STATUS = "status"  # GET  api/status
    CASES_FIND = "cases_find"  # GET  api/cases/_find
    CASE_GET = "case_get"  # GET  api/cases/{case}
    CASE_USER_ACTIONS = "case_user_actions"  # GET  api/cases/{case}/user_actions/_find
    CASE_COMMENTS = "case_comments"  # GET  api/cases/{case}/comments/_find
    CASES_CONFIGURE = "cases_configure"  # GET  api/cases/configure (read only)
    CASE_ALERTS = "case_alerts"  # GET  api/cases/{case}/alerts (technical preview)
    ALERT_CASES = "alert_cases"  # GET  api/cases/alerts/{alert} (technical preview)
    CASE_CREATE = "case_create"  # POST api/cases
    CASES_UPDATE = "cases_update"  # PATCH api/cases
    CASE_COMMENT = "case_comment"  # POST api/cases/{case}/comments (comments, alerts)
    CASE_COMMENT_EDIT = "case_comment_edit"  # PATCH api/cases/{case}/comments (the case team, AR8)
    CASE_FILES = "case_files"  # POST api/cases/{case}/files (multipart; the case team, AR8)
    ALERTS_STATUS = "alerts_status"  # POST api/detection_engine/signals/status
    ALERTS_TAGS = "alerts_tags"  # POST api/detection_engine/signals/tags (the case team, AR8)
    SPACES = "spaces"  # GET  api/spaces/space (argus discover: the spaces)
    FEATURES = "features"  # GET  api/features (argus discover: the Security and Cases feature ids)


@dataclass(frozen=True)
class Target:
    """What a request names besides its endpoint: a case or an alert, never both."""

    case_id: str | None = None
    alert_id: str | None = None


def _case(target: Target) -> str:
    if target.case_id is None or not CASE_ID.fullmatch(target.case_id):
        raise ValueError("the endpoint needs a case id ([A-Za-z0-9_-], at most 64)")
    if target.alert_id is not None:
        raise ValueError("the endpoint names a case only")
    return target.case_id


def _alert(target: Target) -> str:
    if target.alert_id is None or not ALERT_ID.fullmatch(target.alert_id):
        raise ValueError("the endpoint needs an alert id ([A-Za-z0-9_-], at most 128)")
    if target.case_id is not None:
        raise ValueError("the endpoint names an alert only")
    return target.alert_id


def _none(target: Target) -> None:
    if target != Target():
        raise ValueError("the endpoint names no case or alert")


def wire_path(endpoint: KEndpoint, space: str, target: Target = Target()) -> tuple[str, str]:  # noqa: B008
    """(method, path) of ``endpoint`` in ``space``; ValueError for a malformed id or space."""
    if not SPACE.fullmatch(space):
        raise ValueError("a space id is [a-z0-9_-], at most 64")
    api = f"/s/{space}/api"
    match endpoint:
        case KEndpoint.STATUS:
            _none(target)
            return "GET", f"{api}/status"
        case KEndpoint.CASES_FIND:
            _none(target)
            return "GET", f"{api}/cases/_find"
        case KEndpoint.CASE_GET:
            return "GET", f"{api}/cases/{_case(target)}"
        case KEndpoint.CASE_USER_ACTIONS:
            return "GET", f"{api}/cases/{_case(target)}/user_actions/_find"
        case KEndpoint.CASE_COMMENTS:
            return "GET", f"{api}/cases/{_case(target)}/comments/_find"
        case KEndpoint.CASES_CONFIGURE:
            _none(target)
            return "GET", f"{api}/cases/configure"
        case KEndpoint.CASE_ALERTS:
            return "GET", f"{api}/cases/{_case(target)}/alerts"
        case KEndpoint.ALERT_CASES:
            return "GET", f"{api}/cases/alerts/{_alert(target)}"
        case KEndpoint.CASE_CREATE:
            _none(target)
            return "POST", f"{api}/cases"
        case KEndpoint.CASES_UPDATE:
            _none(target)
            return "PATCH", f"{api}/cases"
        case KEndpoint.CASE_COMMENT:
            return "POST", f"{api}/cases/{_case(target)}/comments"
        case KEndpoint.CASE_COMMENT_EDIT:
            return "PATCH", f"{api}/cases/{_case(target)}/comments"
        case KEndpoint.CASE_FILES:
            return "POST", f"{api}/cases/{_case(target)}/files"
        case KEndpoint.ALERTS_STATUS:
            _none(target)
            return "POST", f"{api}/detection_engine/signals/status"
        case KEndpoint.ALERTS_TAGS:
            _none(target)
            return "POST", f"{api}/detection_engine/signals/tags"
        case KEndpoint.SPACES:
            _none(target)
            return "GET", f"{api}/spaces/space"
        case KEndpoint.FEATURES:
            _none(target)
            return "GET", f"{api}/features"
        case _:  # pragma: no cover - mypy proves every member is handled
            assert_never(endpoint)


_SEGMENT = re.compile(r"[A-Za-z0-9_-]{1,128}")


def refusal(method: str, path: str, space: str) -> str | None:
    """Why ARGUS never sends this (method, path), or None. Asked by the validator and again by
    the transport: DELETE and other methods, ``/internal/``, anything outside the space's
    ``/api/``, configuration writes, pushes, any path segment that is not a plain name."""
    if method not in METHODS:
        return f"{method[:10]} is never sent"
    prefix = f"/s/{space}/api/"
    if not SPACE.fullmatch(space) or not path.startswith(prefix):
        return "outside the space's API"
    if "/internal/" in path or path.startswith("/internal") or "internal/" in path:
        return "an internal route"
    rest = path[len(prefix) :]
    segments = rest.split("/")
    if not all(_SEGMENT.fullmatch(s) for s in segments):
        return "a path segment that is not a plain name"
    if "_push" in segments or "connector" in segments or "connectors" in segments:
        return "a push or a connector"
    if method in WRITE_METHODS and "configure" in segments:
        return "a configuration write"
    return None


_PLACEHOLDER = {"case_id": "CASEID0", "alert_id": "ALERTID0"}


@cache
def _endpoint_routes(space: str) -> tuple[tuple[KEndpoint, str, re.Pattern[str]], ...]:
    """(endpoint, method, path pattern) of every route ``wire_path`` builds in ``space``: each
    endpoint tried with no id, a case id and an alert id, the ids turned back into patterns."""
    routes: list[tuple[KEndpoint, str, re.Pattern[str]]] = []
    ids = {"case_id": CASE_ID.pattern, "alert_id": ALERT_ID.pattern}
    for endpoint in KEndpoint:
        for target in (Target(), *(Target(**{k: v}) for k, v in _PLACEHOLDER.items())):
            try:
                method, path = wire_path(endpoint, space, target)
            except ValueError:
                continue
            pattern = re.escape(path)
            for name, value in _PLACEHOLDER.items():
                pattern = pattern.replace(re.escape(value), ids[name])
            routes.append((endpoint, method, re.compile(pattern)))
    return tuple(routes)


def built(method: str, path: str, space: str) -> bool:
    """True if ``wire_path`` builds exactly this (method, path) in ``space``."""
    if not SPACE.fullmatch(space):
        return False
    return any(m == method and p.fullmatch(path) for _, m, p in _endpoint_routes(space))


# The case team's six users (AR8) only create the incident case, comment, upload a file, tag
# alerts and, since D-236, correct what they posted (the lead's PATCH of the case's title and
# description, a user's PATCH of their own comment); nothing else is sent with their keys. Files,
# alert tags and comment edits are theirs alone: no other key of ARGUS sends those routes.
TEAM_ENDPOINTS = frozenset(
    {
        KEndpoint.CASE_CREATE,
        KEndpoint.CASE_COMMENT,
        KEndpoint.CASE_COMMENT_EDIT,
        KEndpoint.CASES_UPDATE,
        KEndpoint.CASE_FILES,
        KEndpoint.ALERTS_TAGS,
    }
)
TEAM_ONLY_ENDPOINTS = frozenset(
    {KEndpoint.CASE_FILES, KEndpoint.ALERTS_TAGS, KEndpoint.CASE_COMMENT_EDIT}
)


def endpoint_of(method: str, path: str, space: str) -> KEndpoint | None:
    """The endpoint whose route this is (the first match), or None."""
    if not SPACE.fullmatch(space):
        return None
    for endpoint, m, pattern in _endpoint_routes(space):
        if m == method and pattern.fullmatch(path):
            return endpoint
    return None
