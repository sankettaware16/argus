"""The ``/api/v1`` contract as OpenAPI: built from the routes, served at
``/api/v1/openapi.json`` and committed as ``docs/api/openapi-v1.json`` by
``scripts/export_openapi.py`` (a test keeps the two equal). The app's client is generated
from the committed copy."""

from __future__ import annotations

import json
from typing import Any

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from fastapi.routing import APIRoute

from argus.web.v1.routes import PREFIX

VERSION = "1.0.0"
TITLE = "ARGUS API"
DESCRIPTION = """\
The typed API of ARGUS's web app (Phase 3, Q-A1).

**Signing in** happens only on the server-rendered page `/signin` (and confirming it is you,
before an approval, on `/stepup`): no password ever passes through this API. A session is an
HttpOnly, SameSite=Strict cookie (`__Host-argus_session` under TLS, `argus_session` on the plain
loopback). `GET /api/v1/session` says who is signed in, what they may do and when the session
ends, and gives the CSRF token: send it as `X-CSRF-Token` on every change, and keep it in
memory only.

**Every change** (POST, PUT, PATCH, DELETE) must also come from this site's own page: an
`Origin` header equal to this server's origin (or `Sec-Fetch-Site: same-origin`). Requests that
browsers mark as coming from another site are refused on every `/api/` path.

**Background requests** (polls, refreshes nobody asked for) send `X-Argus-Background: 1`:
they are answered as usual, but never keep a session alive. A session ends after its idle
time without a request of the person's own, and at its absolute end whatever happens.

**Errors** are always `ErrorOut {detail, code}`. On 401 send the person to
`/signin?next=<the app's path>`; on 403 `csrf` read the session again once; on 409 `conflict`
read the thing again; 429 and 503 are said plainly and never retried by the client.

**Words** (DQ23): an *investigation* is one rule, one actor and one IST day; a *case* is one
real problem across days, hosts and rules; an *incident* is a case a person confirmed.
"""
TAGS = [
    {"name": "session", "description": "Who is signed in; signing out."},
    {
        "name": "investigations",
        "description": "The Inbox, an investigation, its alerts, and reviewing it.",
    },
    {"name": "proposals", "description": "ARGUS's proposals waiting for a person."},
    {"name": "patterns", "description": "Alike investigations, decided together."},
    {"name": "browse", "description": "By rule; by host or address."},
    {"name": "system", "description": "Health, cost, metrics, tuning, the gold set."},
    {"name": "dashboard", "description": "The SOC dashboard."},
]
CHANGES = frozenset({"post", "put", "patch", "delete"})


def build(app: FastAPI) -> dict[str, Any]:
    """The spec of the app's ``/api/v1`` routes (its included router's)."""
    routes = [r for r in app.state.v1_router.routes if isinstance(r, APIRoute)
              and r.include_in_schema and r.path.startswith(PREFIX + "/")]  # fmt: skip
    spec = get_openapi(title=TITLE, version=VERSION, description=DESCRIPTION, routes=routes,
                       tags=TAGS)  # fmt: skip
    spec.setdefault("components", {})["securitySchemes"] = {
        "session": {
            "type": "apiKey", "in": "cookie", "name": "argus_session",
            "description": "The session cookie, set by /signin (__Host-argus_session under"
            " TLS); the browser sends it.",
        },
        "csrf": {
            "type": "apiKey", "in": "header", "name": "X-CSRF-Token",
            "description": "The session's CSRF token, from GET /api/v1/session.",
        },
    }  # fmt: skip
    for operations in spec["paths"].values():
        for method, operation in operations.items():
            operation["security"] = (
                [{"session": [], "csrf": []}] if method in CHANGES else [{"session": []}]
            )
            for parameter in operation.get("parameters", []):
                parameter["schema"] = _without_null(parameter["schema"])
    return spec


def _without_null(schema: dict[str, Any]) -> dict[str, Any]:
    """A parameter is left out, never sent as null (a query string cannot say null): its
    ``anyOf`` loses the null branch FastAPI writes for an optional parameter."""
    branches = schema.get("anyOf")
    if not isinstance(branches, list) or {"type": "null"} not in branches:
        return schema
    kept = [b for b in branches if b != {"type": "null"}]
    rest = {k: v for k, v in schema.items() if k != "anyOf"}
    if len(kept) == 1:
        return {**kept[0], **rest}
    return {"anyOf": kept, **rest}


def v1_spec(app: FastAPI) -> dict[str, Any]:
    """The spec, built once per app."""
    cached: dict[str, Any] | None = getattr(app.state, "v1_openapi", None)
    if cached is None:
        cached = app.state.v1_openapi = build(app)
    return cached


def canonical(spec: dict[str, Any]) -> str:
    """The committed form: sorted keys, two-space indents, a final newline."""
    return json.dumps(spec, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
