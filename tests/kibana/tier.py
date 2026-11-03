"""The local Kibana tier as tests see it (Q-D1, docs/runbooks/kibana-tier.md).

``Tier`` is one pytest session's view: its mode (live when the tier answers, else replay), a
run id that makes every object it creates unique (``t-<run>-…`` users, ``run:<run>`` tags,
``argus-tier-run-<run>-…`` rules), and recorded clients. Each test talks to Kibana and
Elasticsearch only through ``tier.kibana(principal)`` and ``tier.es(principal)``, whose
exchanges go to the test's strict cassette (tests/kibana/cassette.py). Waiting (polls) and
clean-up use ``tier.admin_*``, which is never recorded and exists only live.

Principals are labels, never credentials: ``elastic``; ``user:<seeded name>``; ``key:<seeded
key>``; ``run-user:<suffix>`` and ``run-key:<suffix>`` for objects a test made itself (it
registers the password or the encoded key); ``none`` (no credential); ``wrong:<name>`` (a wrong
password). Secrets come from the tier's own directory (KIBANA_TIER_DIR), are registered
as secrets of the cassette and never reach it.
"""

from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import secrets
import sys
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx

from tests.conftest import hide_in_reports
from tests.kibana.cassette import Exchange, Recorder

REPO_ROOT = Path(__file__).resolve().parents[2]
MODE_VARIABLE = "KIBANA_TIER"  # auto (default), live or replay
RECORD_VARIABLE = "KIBANA_TIER_RECORD"  # 1: rewrite a live run's cassettes; new: missing ones
XSRF = "argus-tier-test"


def _load(name: str, path: Path) -> ModuleType:
    module = sys.modules.get(name)
    if module is None:
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec is not None
        assert spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return module


tier_script = _load("argus_kibana_tier", REPO_ROOT / "scripts" / "kibana_tier.py")
seed = _load("argus_kibana_seed", REPO_ROOT / "scripts" / "kibana_seed.py")
SPACE = seed.SPACE
S = f"/s/{SPACE}"  # every Kibana path of the space starts with this
ALERTS_ALIAS = seed.ALERTS_ALIAS
# The seed's fixed UUIDs: kept verbatim in cassettes (tests compare answers with them).
CONSTANTS = frozenset(
    [seed.argus_uid(name) for name in seed.usernames()]
    + [str(seed.uuid.uuid5(seed.UID_NAMESPACE, "seed-case"))]
)


def new_run_id(now: datetime | None = None) -> str:
    """Unique per pytest session and easy to spot: kt<yymmddHHMMSS><4 hex>."""
    moment = (now or datetime.now(UTC)).strftime("%y%m%d%H%M%S")
    return f"kt{moment}{secrets.token_hex(2)}"


def record_requested(environ: Mapping[str, str] = os.environ) -> bool | str:
    """KIBANA_TIER_RECORD: 1 rewrites every cassette of a live run, new writes missing ones,
    unset compares (a missing cassette fails)."""
    value = (environ.get(RECORD_VARIABLE) or "").strip().lower()
    if value not in ("", "0", "1", "new"):
        raise ValueError(f"{RECORD_VARIABLE}={value!r}: use 1 or new")
    return {"": False, "0": False, "1": True}.get(value, "new")


def mode_requested(environ: Mapping[str, str] = os.environ) -> str:
    tier_script.refuse_old_names(environ)
    value = (environ.get(MODE_VARIABLE) or "auto").strip().lower()
    if value not in ("auto", "live", "replay"):
        raise ValueError(f"{MODE_VARIABLE}={value!r}: use auto, live or replay")
    return value


def tier_problem(settings: Any) -> str | None:
    """Why the tier cannot be used live, or None when it answers (2 s per check)."""
    if not settings.paths.secrets.is_file() or not settings.paths.ca_crt.is_file():
        return f"no tier files in {settings.paths.root} (run scripts/kibana_tier.py init)"
    data = tier_script.load_secrets(settings.paths)
    try:
        kibana = tier_script.kibana_admin(settings, data, timeout=2)
        es = tier_script.es_admin(settings, data, timeout=2)
        try:
            if not tier_script.kibana_available(kibana):
                return "Kibana is not available yet"
            version = es.request("GET", "/")["version"]["number"]
            if version != tier_script.VERSION:
                return f"Elasticsearch is {version}, not {tier_script.VERSION}"
            if not data.get("api_keys"):
                return "the tier is not seeded (scripts/kibana_tier.py seed)"
        finally:
            kibana.close()
            es.close()
    except (httpx.HTTPError, tier_script.TierError, OSError, KeyError, ValueError) as exc:
        return f"the tier does not answer ({type(exc).__name__})"
    return None


@dataclass(frozen=True)
class Reply:
    status: int
    body: Any

    def __getitem__(self, key: str) -> Any:
        return self.body[key]


@dataclass
class Client:
    """Calls one target as one principal; every exchange goes to the test's recorder."""

    tier: Tier
    target: str  # "kibana" or "es"
    principal: str

    def call(
        self,
        method: str,
        path: str,
        body: Any = None,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        xsrf: bool = True,
        keep: Callable[[Any], Any] | None = None,
        ndjson: str | None = None,
        timeout: float | None = None,
    ) -> Reply:
        """Send (live) or replay one request. ``keep`` reduces the answer to what the test
        uses before it is recorded (volatile parts of big answers stay out of the cassette)."""
        sent_params = tuple((str(k), str(v)) for k, v in (params or {}).items())
        noted: dict[str, str] = dict(headers or {})
        if self.target == "kibana" and not xsrf and "kbn-xsrf" not in noted:
            noted["kbn-xsrf"] = "(absent)"
        recorded_body = body if ndjson is None else ndjson
        request = Exchange(
            self.target,
            self.principal,
            method,
            path,
            sent_params,
            recorded_body,
            tuple(sorted(noted.items())),
            0,
            None,
        )
        recorder = self.tier.recorder
        if recorder is None:
            raise RuntimeError("no test is recording: use the kt fixture")
        if self.tier.mode == "replay":
            status, replayed = recorder.answer(request)
            return Reply(status, replayed)
        response = self.tier.send(
            self.target,
            self.principal,
            method,
            path,
            body,
            params=sent_params,
            headers=headers,
            xsrf=xsrf,
            ndjson=ndjson,
            timeout=timeout,
        )
        try:
            answer: Any = response.json() if response.content else None
        except ValueError:
            answer = response.text
        if keep is not None and 200 <= response.status_code < 300:
            # through JSON, so that the test sees the same types live and in replay
            answer = json.loads(json.dumps(keep(answer)))
        recorder.add(
            Exchange(
                request.target,
                request.principal,
                method,
                path,
                sent_params,
                recorded_body,
                request.headers,
                response.status_code,
                answer,
            )
        )
        return Reply(response.status_code, answer)

    def get(self, path: str, **kw: Any) -> Reply:
        return self.call("GET", path, **kw)

    def post(self, path: str, body: Any = None, **kw: Any) -> Reply:
        return self.call("POST", path, body, **kw)

    def put(self, path: str, body: Any = None, **kw: Any) -> Reply:
        return self.call("PUT", path, body, **kw)

    def patch(self, path: str, body: Any = None, **kw: Any) -> Reply:
        return self.call("PATCH", path, body, **kw)

    def delete(self, path: str, body: Any = None, **kw: Any) -> Reply:
        return self.call("DELETE", path, body, **kw)


@dataclass
class Tier:
    mode: str  # "live" or "replay"
    run: str
    record: bool | str = False
    settings: Any = None
    data: dict[str, Any] = field(default_factory=dict, repr=False)  # secrets.json (live)
    recorder: Recorder | None = None  # the current test's
    run_credentials: dict[str, str] = field(default_factory=dict, repr=False)  # -> authorization
    cleanups: list[Callable[[], None]] = field(default_factory=list)
    made_rules: list[str] = field(default_factory=list)  # deleted at the end (live)
    lock: Any = None  # live: the session's shared hold on the tier (tier_script.TierLock)
    _clients: dict[str, httpx.Client] = field(default_factory=dict)

    @contextlib.contextmanager
    def exclusive(self, wait: float = 0.0) -> Iterator[None]:
        """The tier alone, for a test that stops it, takes the security index away or loads it
        hard (docs/runbooks/kibana-tier.md, "Exclusive use"): no other live session runs
        meanwhile, and none starts. Raises tier_script.TierBusy while another holds it."""
        if not self.live or self.lock is None:
            raise RuntimeError("exclusive use needs the live tier")
        with self.lock.exclusively(wait):
            yield

    # ----------------------------------------------------------------------- per test

    def hide(self, value: str) -> None:
        """A secret of this run: never in a cassette, masked in every test report."""
        if self.recorder is not None:
            self.recorder.secret(value)
        hide_in_reports(value)

    def start(self, name: str) -> Recorder:
        self.recorder = Recorder(name, self.run, self.mode, record=self.record, constants=CONSTANTS)
        for value in self.known_secrets():
            self.recorder.secret(value)
        return self.recorder

    def known_secrets(self) -> Iterator[str]:
        yield from self.data.get("passwords", {}).values()
        yield from self.data.get("encryption_keys", {}).values()
        for key in self.data.get("api_keys", {}).values():
            yield key["encoded"]
        for authorization in self.run_credentials.values():
            yield authorization.split(" ", 1)[-1]

    @property
    def live(self) -> bool:
        return self.mode == "live"

    def kibana(self, principal: str) -> Client:
        return Client(self, "kibana", principal)

    def es(self, principal: str) -> Client:
        return Client(self, "es", principal)

    def name(self, suffix: str) -> str:
        """A per-run name: t-<run>-<suffix>."""
        return f"t-{self.run}-{suffix}"

    def password(self) -> str:
        value = secrets.token_urlsafe(18)  # 24 characters, never recorded
        self.hide(value)
        return value

    def add_run_user(self, suffix: str, password: str, *, label: str | None = None) -> str:
        """Let ``run-user:<suffix>`` (or ``label``) sign requests as t-<run>-<suffix> with
        ``password``."""
        principal = label or f"run-user:{suffix}"
        self.run_credentials[principal] = tier_script.basic(self.name(suffix), password)
        self.hide(password)
        self.hide(self.run_credentials[principal].split(" ", 1)[1])
        return principal

    def add_run_key(self, suffix: str, encoded: str) -> str:
        self.run_credentials[f"run-key:{suffix}"] = f"ApiKey {encoded}"
        self.hide(encoded)
        return f"run-key:{suffix}"

    # ----------------------------------------------------------------------- live only

    def authorization(self, principal: str) -> str | None:
        if principal == "none":
            return None
        basic: Callable[[str, str], str] = tier_script.basic
        if principal == "elastic":
            return basic("elastic", str(self.data["passwords"]["elastic"]))
        kind, _, name = principal.partition(":")
        if kind == "user":
            return basic(name, str(self.data["passwords"][name]))
        if kind == "key":
            return "ApiKey " + str(self.data["api_keys"][name]["encoded"])
        if kind == "wrong":
            return basic(name, "not-the-password-" + self.run)
        return self.run_credentials[principal]

    def _client(self, target: str) -> httpx.Client:
        if target not in self._clients:
            base = self.settings.kibana_url if target == "kibana" else self.settings.es_url
            self._clients[target] = httpx.Client(
                base_url=base,
                verify=tier_script.tls_context(self.settings.paths.ca_crt),
                trust_env=False,
                follow_redirects=False,
                timeout=60,
            )
        return self._clients[target]

    def send(
        self,
        target: str,
        principal: str,
        method: str,
        path: str,
        body: Any = None,
        *,
        params: tuple[tuple[str, str], ...] = (),
        headers: Mapping[str, str] | None = None,
        xsrf: bool = True,
        ndjson: str | None = None,
        timeout: float | None = None,
    ) -> httpx.Response:
        if not self.live:
            raise RuntimeError("the tier is not live: nothing is sent in replay")
        sent: dict[str, str] = {}
        authorization = self.authorization(principal)
        if authorization is not None:
            sent["Authorization"] = authorization
        if target == "kibana" and xsrf:
            sent["kbn-xsrf"] = XSRF
        sent.update(headers or {})
        content = None
        if ndjson is not None:
            content = ndjson.encode()
            sent["Content-Type"] = "application/x-ndjson"
        elif body is not None:
            content = json.dumps(body).encode()
            sent["Content-Type"] = "application/json"
        return self._client(target).request(
            method,
            path,
            params=list(params),
            content=content,
            headers=sent,
            timeout=timeout if timeout is not None else httpx.USE_CLIENT_DEFAULT,
        )

    def admin(self, target: str) -> Any:
        """An unrecorded client as elastic (live only): waits and clean-up."""
        if not self.live:
            raise RuntimeError("no admin client in replay")
        factory = tier_script.kibana_admin if target == "kibana" else tier_script.es_admin
        return factory(self.settings, self.data, timeout=60)

    def wait(self, what: str, check: Callable[[], bool], *, seconds: float = 120) -> None:
        """Live: poll ``check`` (unrecorded) until it is true; replay: nothing to wait for."""
        if not self.live:
            return
        deadline = time.monotonic() + seconds
        while not check():
            if time.monotonic() > deadline:
                raise AssertionError(f"{what}: not after {seconds:.0f} s")
            time.sleep(0.5)

    def on_finish(self, action: Callable[[], None]) -> None:
        """Clean-up at the end of the session (live only; failures only reported)."""
        if self.live:
            self.cleanups.append(action)

    def close(self) -> list[str]:
        problems = []
        for action in reversed(self.cleanups):
            try:
                action()
            except Exception as exc:  # clean-up must not hide the tests' results
                problems.append(f"{type(exc).__name__}: {exc}")
        for client in self._clients.values():
            client.close()
        return problems
