"""The old addresses: every address ARGUS ever wrote outward (Kibana case links, notices, reports,
bookmarks) leads to the same thing under ``/app``.

A classic page (GET, HEAD) answers 303 to its page in ``/app``, built from fixed paths and a
parsed UUID only; the page it leads to checks access. A classic form (POST) is answered 410 with
a plain page pointing to the same action in ``/app``, and does nothing. Pure functions: the app's
middleware calls them."""

from __future__ import annotations

import re
import uuid
from urllib.parse import parse_qsl, urlencode

from pydantic import TypeAdapter, ValidationError

PAGES = {
    "/classic": "/app",
    "/rules": "/app/rules",
    "/hosts": "/app/hosts",
    "/patterns": "/app/patterns",
    "/proposals": "/app/proposals",
    "/tuning": "/app/tuning",
    "/metrics": "/app/metrics",
    "/gold": "/app/gold",
    "/health": "/app/health",
    "/glossary": "/app/glossary",
}
INBOX_KEYS = ("view", "sort", "rule", "kind", "value")
DASHBOARD_KEYS = ("range", "start", "end", "severity", "state", "verdict", "ai", "rule", "kind",
                  "value")  # fmt: skip
QUERY_MAX = 4096
# The routes take an investigation's id as one path segment and parse it with pydantic's UUID
# validator (hyphenated, 32 hex digits, {braced}, urn:uuid:); the shapes below match the segment
# the way the router does (``[^/]+``) and the id is parsed with that same validator, so no
# spelling the route accepts slips past.
_UUID = TypeAdapter(uuid.UUID)
_SEGMENT = r"([^/]+)"
_INVESTIGATION = re.compile(rf"/investigations/{_SEGMENT}(/report|/alerts/.+)?", re.DOTALL)
_CASE = re.compile(rf"/cases/{_SEGMENT}(/report)?")
_ACTION = re.compile(rf"/investigations/{_SEGMENT}/(?:gold|review|accept|assess)")
ACTIONS = {"/patterns/review": "/app/patterns", "/proposals/confirm": "/app/proposals"}
REFUSED = (
    "The classic pages are gone. Reviewing, confirming and asking the AI investigator are done"
    " in the app, which shows the exact request before it sends anything."
)


def _kept(query: str, keys: tuple[str, ...]) -> str:
    """The query's pairs the app reads (in the order given), re-encoded; nothing else."""
    if len(query) > QUERY_MAX:
        return ""
    pairs = [(k, v) for k, v in parse_qsl(query, keep_blank_values=False) if k in keys]
    return urlencode(pairs)


def _parsed(segment: str) -> uuid.UUID | None:
    """The id as the routes read it (``investigation_id: uuid.UUID``), or None."""
    try:
        return _UUID.validate_python(segment)
    except ValidationError:
        return None


def _with(target: str, query: str) -> str:
    return f"{target}?{query}" if query else target


def redirect_target(path: str, query: str) -> str | None:
    """Where a classic page's address leads in the app, or None for a path that is not one of
    the classic pages the app covers."""
    if path == "/":
        return _with("/app/inbox", _kept(query, INBOX_KEYS)) if query else "/app"
    if path == "/inbox":
        return _with("/app/inbox", _kept(query, INBOX_KEYS))
    if path == "/dashboard":
        return _with("/app/dashboard", _kept(query, DASHBOARD_KEYS))
    if path in PAGES:
        return PAGES[path]
    case = _CASE.fullmatch(path)
    if case is not None:
        case_id = _parsed(case.group(1))
        if case_id is None:
            return None
        return f"/app/incidents/{case_id}?tab=report" if case.group(2) else f"/app/cases/{case_id}"
    found = _INVESTIGATION.fullmatch(path)
    if found is None:
        return None
    inv = _parsed(found.group(1))
    if inv is None:
        return None
    base = f"/app/investigations/{inv}"
    tail = found.group(2)
    if tail is None:
        return base
    return _with(base, "tab=report" if tail == "/report" else "tab=alerts")


def action_target(path: str) -> str | None:
    """Where a classic form's action is done in the app, or None for a path that is not one.
    A path of the form's shape is refused whether or not its id parses (the route would answer
    422 then); the pointer is the investigation when it does, else the app's front page."""
    if path in ACTIONS:
        return ACTIONS[path]
    found = _ACTION.fullmatch(path)
    if found is None:
        return None
    inv = _parsed(found.group(1))
    return "/app" if inv is None else f"/app/investigations/{inv}"
