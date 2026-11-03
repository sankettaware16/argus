"""Record/replay at the gateway boundary.

A cassette is a JSON file of answers keyed by the request (template and version, method, path,
URL parameters, body without its ``timeout``). Replay is strict: a request the cassette does not
hold raises ``CassetteMissError`` and is never sent. Recordings of real data are written under
``data/`` (never committed) unless sanitized and leak-checked first.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from argus.gateway.errors import GatewayError
from argus.gateway.transport import Transport, WireRequest, WireResponse

FORMAT = 1


class CassetteMissError(GatewayError):
    reason = "cassette_miss"


def cassette_key(request: WireRequest) -> str:
    template = request.opaque_id.split("/", 1)[-1]  # argus-<component>/<template>@<version>
    body: Any = None
    if request.body is not None:
        body = json.loads(request.body)
        if isinstance(body, dict):
            body = {k: v for k, v in body.items() if k != "timeout"}
    canonical = json.dumps(
        [FORMAT, template, request.method, request.path, sorted(request.params), body],
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass
class CassetteTransport:
    path: Path
    mode: Literal["replay", "record"] = "replay"
    inner: Transport | None = None
    entries: dict[str, dict[str, Any]] = field(default_factory=dict)
    changed: bool = False

    def __post_init__(self) -> None:
        if self.mode == "record" and self.inner is None:
            raise ValueError("recording needs a transport to record from")
        if self.path.is_file():
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if data.get("format") != FORMAT:
                raise ValueError(
                    f"{self.path}: cassette format {data.get('format')} is not {FORMAT}"
                )
            self.entries = data["entries"]
        elif self.mode == "replay":
            raise FileNotFoundError(f"no cassette {self.path}")

    async def send(self, request: WireRequest) -> WireResponse:
        key = cassette_key(request)
        if self.mode == "replay":
            entry = self.entries.get(key)
            if entry is None:
                template = request.opaque_id.split("/", 1)[-1]
                raise CassetteMissError(f"{template}: no recorded answer for this request")
            return WireResponse(entry["status"], entry["body"].encode(), entry["elapsed_ms"])
        assert self.inner is not None
        response = await self.inner.send(request)
        self.entries[key] = {
            "template": request.opaque_id.split("/", 1)[-1],
            "path": request.path,
            "status": response.status,
            "body": response.body.decode("utf-8", "replace"),
            "elapsed_ms": round(response.elapsed_ms, 1),
        }
        self.changed = True
        return response

    def save(self) -> None:
        """Write the recording atomically (mode 0600); replay never writes."""
        if self.mode != "record" or not self.changed:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        payload = json.dumps({"format": FORMAT, "entries": self.entries}, indent=1, sort_keys=True)
        descriptor, name = tempfile.mkstemp(prefix=".cassette-", dir=self.path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(payload)
            os.replace(name, self.path)
        except BaseException:
            Path(name).unlink(missing_ok=True)
            raise
        self.changed = False
