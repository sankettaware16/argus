"""The Kibana lane's validator: it inspects the **final** request, exactly as the transport would
send it, and refuses anything outside the contract before a byte is sent.

It checks the route (``paths.refusal`` and ``paths.wire_path``), that reads are GETs without a body
and writes POST or PATCH with one, URL parameters from the template's allowlist, and the body: size
cap, plain JSON valid against the strict model, none of the fields ARGUS never sends, and an
attachment's alert indices being the space's own backing indices.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from argus.gateway.errors import TemplateRejectedError
from argus.gateway.kibana import upload
from argus.gateway.kibana.models import OWNER, TEAM_LEAD, TEAM_USERS, AlertAttachment
from argus.gateway.kibana.paths import WRITE_METHODS, KEndpoint, Target, refusal, wire_path
from argus.gateway.kibana.templates import KeyRole, KSpec

MAX_BODY_BYTES = 256 * 1024  # a 30,000-character text, escaped, fits
MAX_PARAM_CHARS = 256
REPEATED_PARAMS = frozenset({"tags", "reporters"})  # Kibana reads a repeated key as a list
NEVER_SENT = frozenset({"assignees", "customFields", "category"})
NEVER_PATCHED = frozenset({"settings", "connector", "owner", "syncAlerts"})
# The case team: only the lead opens a case and touches alerts; only the reporter
# uploads files. Every other team write may be any of the six users'.
TEAM_ONLY: dict[str, frozenset[str]] = {
    "team.create": frozenset({TEAM_LEAD}),
    "team.attach_alerts": frozenset({TEAM_LEAD}),
    "team.alert_tags": frozenset({TEAM_LEAD}),
    "team.edit_case": frozenset({TEAM_LEAD}),
    "team.file": frozenset({"argus-reporter"}),
}
JSON_TYPE = "application/json"
NO_CONNECTOR = {"id": "none", "name": "none", "type": ".none", "fields": None}


@dataclass(frozen=True)
class KFinal:
    """Exactly what the transport would send."""

    spec: KSpec
    method: str
    path: str
    target: Target = field(default_factory=Target)
    url_params: tuple[tuple[str, str], ...] = ()
    body: bytes | None = None
    as_user: str | None = None  # the case team: the user whose key sends it

    @property
    def content_type(self) -> str:
        if self.spec.endpoint is KEndpoint.CASE_FILES and self.body is not None:
            return upload.content_type(self.body)
        return JSON_TYPE


def encode(body: Any) -> bytes:
    return json.dumps(body, allow_nan=False, ensure_ascii=True, separators=(",", ":")).encode()


def request_hash(final: KFinal) -> str:
    """The payload's hash: what an outbox row and an approval are bound to."""
    document = {
        "template": f"{final.spec.name}@{final.spec.version}",
        "method": final.method,
        "path": final.path,
        "params": [list(p) for p in final.url_params],
        "body": None if final.body is None else final.body.decode("latin-1"),
    }
    if final.as_user is not None:  # the author is part of what an approval binds
        document["as"] = final.as_user
    canonical = json.dumps(document, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def reject(code: str, detail: str) -> TemplateRejectedError:
    return TemplateRejectedError(code, detail)


def _walk_keys(node: Any) -> set[str]:
    keys: set[str] = set()
    stack = [node]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            keys.update(str(k) for k in item)
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return keys


def validate(final: KFinal, space: str, alerts_index_prefix: str) -> None:
    """Raise TemplateRejectedError unless ``final`` keeps the contract."""
    spec = final.spec
    why = refusal(final.method, final.path, space)
    if why is not None:
        raise reject("route_refused", why)
    if spec.key is KeyRole.TEAM:
        allowed = TEAM_ONLY.get(spec.name, frozenset(TEAM_USERS))
        if final.as_user not in allowed:
            raise reject("wrong_author", f"{spec.name} is not sent as {str(final.as_user)[:40]}")
    elif final.as_user is not None:
        raise reject("wrong_author", f"{spec.name} is not a case team write")
    try:
        expected = wire_path(spec.endpoint, space, final.target)
    except ValueError as exc:
        raise reject("bad_target", str(exc)) from None
    if expected != (final.method, final.path):
        raise reject("path_mismatch", f"{spec.name} is not sent to that route")
    if spec.write != (final.method in WRITE_METHODS):
        raise reject("method_mismatch", f"{spec.name}: reads are GETs, writes POST or PATCH")
    seen: set[str] = set()
    for name, value in final.url_params:
        if not isinstance(name, str) or not isinstance(value, str):
            raise reject("forbidden_param", "URL parameters are text")
        if name not in spec.url_params:
            raise reject("forbidden_param", f"{name[:40]} is not allowed for {spec.name}")
        if name in seen and name not in REPEATED_PARAMS:
            raise reject("forbidden_param", f"{name} given twice")
        seen.add(name)
        if not value or len(value) > MAX_PARAM_CHARS or not value.isprintable():
            raise reject("forbidden_param", f"{name}: a value of 1-{MAX_PARAM_CHARS} characters")
    if not spec.write:
        if final.body is not None:
            raise reject("bad_shape", f"the read {spec.name} sends no body")
        return
    if final.body is None or spec.body_model is None:
        raise reject("bad_shape", f"the write {spec.name} needs its body")
    if spec.endpoint is KEndpoint.CASE_FILES:
        try:
            upload.decode(final.body)
        except ValueError as exc:
            raise reject("bad_shape", f"the file body is not valid: {str(exc)[:80]}") from None
        return
    if len(final.body) > MAX_BODY_BYTES:
        raise reject("body_too_large", f"{len(final.body)} bytes (limit {MAX_BODY_BYTES})")
    try:
        decoded = json.loads(final.body)
        model = spec.body_model.model_validate_json(final.body)
    except (ValueError, ValidationError, RecursionError):
        raise reject("bad_shape", f"the body is not a valid {spec.name}") from None
    keys = _walk_keys(decoded)
    if keys & NEVER_SENT:
        raise reject("forbidden_field", ", ".join(sorted(keys & NEVER_SENT)))
    if spec.endpoint is KEndpoint.CASES_UPDATE and keys & NEVER_PATCHED:
        raise reject("forbidden_field", "a PATCH never carries " + ", ".join(
            sorted(keys & NEVER_PATCHED)))  # fmt: skip
    if spec.endpoint is KEndpoint.CASE_CREATE and (
        not isinstance(decoded, dict)
        or decoded.get("settings") != {"syncAlerts": False}
        or decoded.get("connector") != NO_CONNECTOR
        or decoded.get("owner") != OWNER
    ):
        raise reject("bad_shape", "a create carries Sync alerts off, no connector, its owner")
    own = re.compile(re.escape(alerts_index_prefix) + r"[0-9]{6}")
    if isinstance(model, AlertAttachment) and not all(own.fullmatch(i) for i in model.index):
        raise reject("index_not_allowed", "an attached alert is not of the space's alert indices")
