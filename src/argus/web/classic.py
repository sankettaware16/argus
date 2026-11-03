"""The switch to ``/app``: with ``web.classic`` set to ``fallback``, a classic page's address leads
to the same page of the app, and the classic pages are a read-only fallback.

A classic page (GET, HEAD) answers 303 to its page in ``/app``, built from fixed paths and a
parsed UUID only. The fallback is the browser's choice: ``/classic`` sets a session cookie
(``argus_classic``) and the classic pages answer as they did until the person opens ``/app``; the
cookie grants nothing. A classic form (POST) is refused with a plain page pointing to the same
action in ``/app``. ``/access``, the sign-in, step-up and logout pages and the classic JSON API
stay. Pure functions: the app's middleware and routes call them."""

from __future__ import annotations

import re
import uuid
from urllib.parse import parse_qsl, urlencode

from pydantic import TypeAdapter, ValidationError

COOKIE = "argus_classic"
PAGES = {
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
_ACTION = re.compile(rf"/investigations/{_SEGMENT}/(?:gold|review|accept|assess)")
ACTIONS = {"/patterns/review": "/app/patterns", "/proposals/confirm": "/app/proposals"}
REFUSED = (
    "The classic pages are read-only now. Reviewing, confirming and asking the AI investigator"
    " are done in the new app, which shows the exact request before it sends anything."
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
    if path == "/dashboard":
        return _with("/app/dashboard", _kept(query, DASHBOARD_KEYS))
    if path in PAGES:
        return PAGES[path]
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
