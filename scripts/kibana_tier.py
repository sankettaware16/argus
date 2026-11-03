#!/usr/bin/env python3
"""The local Kibana 8.19.12 Basic tier (Q-D1, docs/runbooks/kibana-tier.md).

Elasticsearch and Kibana as on the SIEM (security on, Basic licence, HTTPS with a CA, the site's
space: the checkout's config/site.yaml, or KIBANA_TIER_SPACE and KIBANA_TIER_PREFIX; see
scripts/kibana_seed.py), on 127.0.0.1 only: Elasticsearch at :59210, Kibana at :55610. This
script is the only way to make, start, seed, stop or reset it:

    uv run python scripts/kibana_tier.py init       # the CA, certificates, passwords (idempotent)
    scripts/heavy.sh --label kibana-tier uv run python scripts/kibana_tier.py up --hold &
                                                    # start, wait, keep the heavy slot till `down`
    uv run python scripts/kibana_tier.py seed       # idempotent, one at a time: space, roles,
                                                    # users, keys, rule
    uv run python scripts/kibana_tier.py status     # what runs, what is seeded, memory now
    uv run python scripts/kibana_tier.py stats --seconds 120   # peak memory while you work
    uv run python scripts/kibana_tier.py down       # stop (keeps the data); waits for no one:
                                                    # refused while live test sessions run
    uv run python scripts/kibana_tier.py reset --yes   # stop, remove its containers and volumes

Every docker command names the tier's two services (kibana-es, kibana), containers or volumes,
and only those, word for word (an allowlist): the compose project "argus" also holds
production's database (db), which no command here may touch, and `docker compose down` is never
run. Live test sessions hold the tier's lock (TierLock) shared; exclusive use, `down` and
`reset` need it alone. The tier's CA, certificates and
secrets live outside every checkout, in KIBANA_TIER_DIR (default
~/.local/share/argus-kibana-tier, mode 0700), so every worktree starts the same containers and
tests in any worktree find them. Nothing here contacts the SIEM: the URLs must be loopback.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import fcntl
import ipaddress
import json
import os
import re
import secrets
import shutil
import signal
import ssl
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

ROOT = Path(__file__).resolve().parent.parent
COMPOSE_FILE = ROOT / "docker-compose.yml"
PROJECT = "argus"
PROFILE = "kibana"
SERVICES = ("kibana-es", "kibana")  # start order
CONTAINERS = {"kibana-es": "argus-kibana-es", "kibana": "argus-kibana"}
VOLUMES = ("argus_argus-kibana-esdata", "argus_argus-kibana-data")
# Never named by any command here (a unit test checks every command the script builds).
PROTECTED = frozenset(
    {"db", "es-local", "argus-db", "argus-es-local", "argus_argus-pgdata", "argus_argus-esdata"}
)
VERSION = "8.19.12"
DEFAULT_KIBANA_URL = "https://127.0.0.1:55610"
DEFAULT_ES_URL = "https://127.0.0.1:59210"
DEFAULT_DIR = Path.home() / ".local" / "share" / "argus-kibana-tier"
# A certificate is re-issued by `init` when it ends within this many days.
RENEW_BEFORE = timedelta(days=30)
CA_DAYS = 3650
LEAF_DAYS = 825
PASSWORD_MIN = 10  # ARGUS refuses shorter ELK passwords (plan §3 rule 8)


# --------------------------------------------------------------------------- settings


def _loopback_url(url: str, variable: str) -> str:
    """``https://<loopback host>[:<port>]`` and nothing more: no credentials, path, query or
    fragment, whose parsing could differ between this check and the HTTP client."""
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise SystemExit(f"{variable}={url!r}: the tier is reached over https only")
    try:
        loopback = ipaddress.ip_address(parts.hostname).is_loopback
    except ValueError:
        loopback = parts.hostname == "localhost"
    if not loopback:
        raise SystemExit(f"{variable}={url!r}: the tier runs on this machine (127.0.0.1) only")
    try:
        parts.port  # noqa: B018 - raises ValueError when out of range
    except ValueError:
        raise SystemExit(f"{variable}={url!r}: not a port") from None
    if "@" in parts.netloc or url.rstrip("/") != f"https://{parts.netloc}":
        raise SystemExit(f"{variable}={url!r}: give https://<loopback host>:<port> only")
    return url.rstrip("/")


# The variables the tooling and tests read. None starts with ARGUS_: ARGUS refuses every
# ARGUS_* variable that is not one of its settings, so one set for the tests would stop every
# test (and command) that loads the configuration.
LOCATION_VARIABLES = ("KIBANA_TIER_URL", "KIBANA_TIER_ES_URL", "KIBANA_TIER_DIR")
RENAMED = {
    "ARGUS_KIBANA_TIER": "KIBANA_TIER",
    "ARGUS_KIBANA_RECORD": "KIBANA_TIER_RECORD",
    "ARGUS_KIBANA_TIER_URL": "KIBANA_TIER_URL",
    "ARGUS_KIBANA_TIER_ES_URL": "KIBANA_TIER_ES_URL",
    "ARGUS_KIBANA_TIER_DIR": "KIBANA_TIER_DIR",
}


def refuse_old_names(environ: Mapping[str, str]) -> None:
    for old, new in RENAMED.items():
        if old in environ:
            raise SystemExit(
                f"{old} is now {new} (ARGUS refuses ARGUS_ variables that are not settings)"
            )


@dataclass(frozen=True)
class Paths:
    """Where the tier's files are; see the module docstring."""

    root: Path

    @property
    def secrets(self) -> Path:
        return self.root / "secrets.json"

    @property
    def ca_crt(self) -> Path:
        return self.root / "ca" / "ca.crt"

    @property
    def ca_key(self) -> Path:
        return self.root / "ca" / "ca.key"

    @property
    def es_dir(self) -> Path:  # mounted read-only at config/tier in kibana-es
        return self.root / "es"

    @property
    def kibana_dir(self) -> Path:
        return self.root / "kibana"

    @property
    def kibana_yml(self) -> Path:  # mounted at config/kibana.yml in kibana
        return self.kibana_dir / "kibana.yml"

    @property
    def kibana_tls(self) -> Path:  # mounted read-only at config/tier in kibana
        return self.kibana_dir / "tls"


@dataclass(frozen=True)
class Settings:
    """The tier as tests and this script see it (the variables of the runbook)."""

    kibana_url: str
    es_url: str
    paths: Paths

    @classmethod
    def from_env(cls, environ: Mapping[str, str] = os.environ) -> Settings:
        refuse_old_names(environ)
        directory = environ.get("KIBANA_TIER_DIR") or str(DEFAULT_DIR)
        return cls(
            kibana_url=_loopback_url(
                environ.get("KIBANA_TIER_URL") or DEFAULT_KIBANA_URL, "KIBANA_TIER_URL"
            ),
            es_url=_loopback_url(
                environ.get("KIBANA_TIER_ES_URL") or DEFAULT_ES_URL,
                "KIBANA_TIER_ES_URL",
            ),
            paths=Paths(Path(directory).expanduser().resolve()),
        )


# --------------------------------------------------------------------------- secrets


def _password() -> str:
    return secrets.token_urlsafe(24)  # 32 characters


def _key() -> str:
    return secrets.token_hex(32)  # 64 characters; Kibana needs at least 32


def _write_private(path: Path, text: str) -> None:
    """Write ``text`` atomically, readable by this user only (uid 1000 in both containers)."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(name, 0o600)
        os.replace(name, path)
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise


def load_secrets(paths: Paths) -> dict[str, Any]:
    if not paths.secrets.is_file():
        raise SystemExit(f"no {paths.secrets}: run `uv run python scripts/kibana_tier.py init`")
    data: dict[str, Any] = json.loads(paths.secrets.read_text(encoding="utf-8"))
    return data


def save_secrets(paths: Paths, data: Mapping[str, Any]) -> None:
    _write_private(paths.secrets, json.dumps(data, indent=1, sort_keys=True) + "\n")


def ensure_secrets(paths: Paths, usernames: Sequence[str]) -> dict[str, Any]:
    """The tier's passwords and keys, made once and kept; new seeded users get a password."""
    data: dict[str, Any] = (
        json.loads(paths.secrets.read_text(encoding="utf-8")) if paths.secrets.is_file() else {}
    )
    changed = not data
    for name in ("elastic", "kibana_system"):
        if not data.get("passwords", {}).get(name):
            data.setdefault("passwords", {})[name] = _password()
            changed = True
    for name in usernames:
        if not data.get("passwords", {}).get(name):
            data.setdefault("passwords", {})[name] = _password()
            changed = True
    for name in ("encrypted_saved_objects", "security", "reporting"):
        if not data.get("encryption_keys", {}).get(name):
            data.setdefault("encryption_keys", {})[name] = _key()
            changed = True
    data.setdefault("api_keys", {})
    if changed:
        save_secrets(paths, data)
    return data


# --------------------------------------------------------------------------- certificates


def _openssl(*args: str) -> None:
    subprocess.run(["openssl", *args], check=True, capture_output=True)  # noqa: S603, S607


def certificate_end(path: Path) -> datetime | None:
    """When the PEM certificate at ``path`` expires, or None if there is none."""
    if not path.is_file():
        return None
    try:
        decoded = ssl._ssl._test_decode_cert(str(path))  # type: ignore[attr-defined]
    except (ssl.SSLError, OSError):
        return None
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(decoded["notAfter"]), UTC)


def _fresh(path: Path, now: datetime) -> bool:
    end = certificate_end(path)
    return end is not None and end - now > RENEW_BEFORE


def make_ca(paths: Paths) -> None:
    paths.ca_crt.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _openssl(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-sha256",
        "-keyout",
        str(paths.ca_key),
        "-out",
        str(paths.ca_crt),
        "-days",
        str(CA_DAYS),
        "-subj",
        "/O=ARGUS/CN=ARGUS local Kibana tier CA",
        "-addext",
        "basicConstraints=critical,CA:TRUE,pathlen:0",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-addext",
        "subjectKeyIdentifier=hash",
    )
    os.chmod(paths.ca_key, 0o600)


def make_leaf(paths: Paths, name: str, dns: Sequence[str], out_dir: Path) -> None:
    """A server certificate for ``name`` signed by the tier's CA, valid for ``dns`` and
    127.0.0.1, written to ``out_dir``/<name>.crt and .key (0600)."""
    out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    key, crt = out_dir / f"{name}.key", out_dir / f"{name}.crt"
    with tempfile.TemporaryDirectory() as work:
        csr, ext = Path(work) / "leaf.csr", Path(work) / "leaf.ext"
        sans = ",".join([*(f"DNS:{d}" for d in dns), "IP:127.0.0.1"])
        ext.write_text(
            f"subjectAltName={sans}\n"
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n"
            "subjectKeyIdentifier=hash\n"
            "authorityKeyIdentifier=keyid,issuer\n",
            encoding="utf-8",
        )
        _openssl(
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-sha256",
            "-keyout",
            str(key),
            "-out",
            str(csr),
            "-subj",
            f"/O=ARGUS/CN={dns[0]}",
        )
        _openssl(
            "x509",
            "-req",
            "-sha256",
            "-in",
            str(csr),
            "-CA",
            str(paths.ca_crt),
            "-CAkey",
            str(paths.ca_key),
            "-set_serial",
            str(secrets.randbits(63)),
            "-days",
            str(LEAF_DAYS),
            "-extfile",
            str(ext),
            "-out",
            str(crt),
        )
    os.chmod(key, 0o600)
    os.chmod(crt, 0o644)


def ensure_certificates(paths: Paths, *, now: datetime, force: bool = False) -> list[str]:
    """The CA and both server certificates; re-issued when missing or ending within 30 days.
    Returns what was made."""
    made: list[str] = []
    if force or not _fresh(paths.ca_crt, now) or not paths.ca_key.is_file():
        make_ca(paths)
        made.append("ca")
        force = True  # leaves of an old CA would not verify
    leaves = {
        "es": (["kibana-es", "argus-kibana-es", "localhost"], paths.es_dir),
        "kibana": (["kibana", "argus-kibana", "localhost"], paths.kibana_tls),
    }
    for name, (dns, out_dir) in leaves.items():
        if force or not _fresh(out_dir / f"{name}.crt", now):
            make_leaf(paths, name, dns, out_dir)
            made.append(name)
        shutil.copyfile(paths.ca_crt, out_dir / "ca.crt")
    for directory in (paths.ca_crt.parent, paths.es_dir, paths.kibana_dir, paths.kibana_tls):
        os.chmod(directory, 0o700)  # only this user (uid 1000 in both containers)
    return made


# --------------------------------------------------------------------------- kibana.yml


def kibana_yml(settings: Settings, data: Mapping[str, Any]) -> str:
    """Kibana's configuration: HTTPS with the tier's CA (as DQ2 (a) expects on the SIEM), no
    basePath, the rate limiter and HTTP authentication at their defaults (§12 #5), no calls
    home. Values are written as JSON strings, which are YAML double-quoted scalars; they must
    be printable ASCII (the tier's are: token_urlsafe and hex), so no parser can read them
    differently."""
    keys = data["encryption_keys"]

    def q(value: str) -> str:
        if not (value.isascii() and value.isprintable()):
            raise ValueError("kibana.yml values must be printable ASCII")
        return json.dumps(value)

    lines = [
        "# Written by scripts/kibana_tier.py init: do not edit (it holds secrets; mode 0600).",
        'server.host: "0.0.0.0"',
        'server.name: "argus-kibana"',
        'server.shutdownTimeout: "5s"',
        f"server.publicBaseUrl: {q(settings.kibana_url)}",
        "server.ssl.enabled: true",
        'server.ssl.certificate: "/usr/share/kibana/config/tier/kibana.crt"',
        'server.ssl.key: "/usr/share/kibana/config/tier/kibana.key"',
        'elasticsearch.hosts: ["https://kibana-es:9200"]',
        'elasticsearch.username: "kibana_system"',
        f"elasticsearch.password: {q(data['passwords']['kibana_system'])}",
        'elasticsearch.ssl.certificateAuthorities: ["/usr/share/kibana/config/tier/ca.crt"]',
        'elasticsearch.ssl.verificationMode: "full"',
        f"xpack.encryptedSavedObjects.encryptionKey: {q(keys['encrypted_saved_objects'])}",
        f"xpack.security.encryptionKey: {q(keys['security'])}",
        f"xpack.reporting.encryptionKey: {q(keys['reporting'])}",
        "telemetry.optIn: false",
        "telemetry.allowChangingOptInStatus: false",
        "newsfeed.enabled: false",
        "xpack.fleet.isAirGapped: true",
        "",
    ]
    return "\n".join(lines)


def write_configuration(settings: Settings, data: Mapping[str, Any]) -> None:
    paths = settings.paths
    _write_private(paths.es_dir / "elastic-password", data["passwords"]["elastic"])
    _write_private(paths.kibana_yml, kibana_yml(settings, data))


# --------------------------------------------------------------------------- docker


def compose_settings() -> dict[str, str]:
    """Compose settings the script sets itself. Compose also reads COMPOSE_* from the
    checkout's .env (every tier command reads it: db's required variables), and a value in the
    process environment wins over it (Compose v5.3): left unset, a .env's
    COMPOSE_REMOVE_ORPHANS=true made the tier's own `up` remove other checkouts' containers."""
    return {
        "COMPOSE_REMOVE_ORPHANS": "false",
        "COMPOSE_PROFILES": PROFILE,
        "COMPOSE_FILE": str(COMPOSE_FILE),
        "COMPOSE_PROJECT_NAME": PROJECT,
    }


def docker_env(settings: Settings) -> dict[str, str]:
    """The environment of every docker command: no DOCKER_* or COMPOSE_* variable of the
    caller's (another daemon, client configuration, env file, profile, file or project), the
    default context, and the compose settings above."""
    env = {k: v for k, v in os.environ.items() if not k.startswith(("DOCKER_", "COMPOSE_"))}
    env["DOCKER_CONTEXT"] = "default"  # the CLI default here is Docker Desktop, never used
    env.update(compose_settings())
    env["KIBANA_TIER_DIR"] = str(settings.paths.root)
    return env


def compose_command(*args: str) -> list[str]:
    """``docker compose`` for the tier: its project, its profile, the repository's file."""
    return [
        "docker",
        "compose",
        "--project-name",
        PROJECT,
        "--file",
        str(COMPOSE_FILE),
        "--profile",
        PROFILE,
        *args,
    ]


def commands_for(action: str) -> list[list[str]]:
    """Every docker command an action runs, built here so a test can check them all."""
    if action == "start-es":
        return [compose_command("up", "--detach", "--no-recreate", "kibana-es")]
    if action == "start-kibana":
        return [compose_command("up", "--detach", "--no-recreate", "--no-deps", "kibana")]
    if action == "stop":
        return [compose_command("stop", "kibana", "kibana-es")]
    if action == "remove":
        return [
            compose_command("rm", "--stop", "--force", "kibana", "kibana-es"),
            ["docker", "volume", "rm", "--force", *VOLUMES],
        ]
    if action == "ps":
        return [
            [
                "docker",
                "ps",
                "--all",
                "--filter",
                "label=com.docker.compose.project=argus",
                "--format",
                "{{.Names}}\t{{.State}}\t{{.Status}}",
            ]
        ]
    if action == "hash":
        return [compose_command("config", "--hash", ",".join(SERVICES))]
    if action == "labels":
        return [
            [
                "docker",
                "inspect",
                "--format",
                '{{.Name}} {{index .Config.Labels "com.docker.compose.config-hash"}}',
                *CONTAINERS.values(),
            ]
        ]
    if action == "running":
        return [["docker", "inspect", "--format", "{{.State.Running}}", *CONTAINERS.values()]]
    if action == "ids":  # one each, so that one missing container hides nothing of the other
        return [["docker", "inspect", "--format", "{{.Id}}", name] for name in CONTAINERS.values()]
    if action == "process-check":  # the secrets go to its stdin, never into this command
        return [
            ["docker", "exec", "--interactive", name, "bash", "-c", PROCESS_CHECK]
            for name in CONTAINERS.values()
        ]
    if action == "stats":
        return [
            [
                "docker",
                "stats",
                "--no-stream",
                "--format",
                "{{.Name}}\t{{.MemUsage}}",
                *CONTAINERS.values(),
            ]
        ]
    raise ValueError(action)


# Every action of commands_for: check_command allows their commands and nothing else.
ACTIONS = (
    "start-es",
    "start-kibana",
    "stop",
    "remove",
    "ps",
    "stats",
    "running",
    "hash",
    "labels",
    "ids",
    "process-check",
)


def allowed_commands() -> list[list[str]]:
    return [command for action in ACTIONS for command in commands_for(action)]


# compose verbs that act on every service of the project when no service is named
COMPOSE_ALL_BY_DEFAULT = frozenset(
    {"up", "start", "stop", "restart", "rm", "kill", "pause", "unpause", "create", "pull"}
)
COMPOSE_GLOBAL_OPTIONS = frozenset({"--project-name", "--file", "--profile"})  # take a value


def check_command(command: Sequence[str]) -> None:
    """Allow exactly the commands of ``ACTIONS``, word for word, and refuse everything else.
    The checks before that only give the clearer reason for what matters most: a command
    naming production's services or volumes, `docker compose down`, `--remove-orphans`, a
    compose verb that would act on every service, a volume removal beyond the tier's."""
    words = set(command)
    if words & PROTECTED:
        raise RuntimeError(f"refused: {' '.join(command)} names a protected service or volume")
    argv = list(command)  # a tuple compares unequal to every list below
    if argv[:2] == ["docker", "compose"]:
        if "down" in words:
            raise RuntimeError("refused: `docker compose down` stops every service, db included")
        if "--remove-orphans" in words:
            raise RuntimeError("refused: --remove-orphans removes other checkouts' containers")
        rest = argv[2:]
        while rest and rest[0] in COMPOSE_GLOBAL_OPTIONS:
            rest = rest[2:]
        if rest and rest[0] in COMPOSE_ALL_BY_DEFAULT:
            services = {w for w in rest[1:] if not w.startswith("-")}
            if not services or not services <= set(SERVICES):
                raise RuntimeError(
                    f"refused: `docker compose {rest[0]}` must name the tier's services only"
                )
    if argv[:3] == ["docker", "volume", "rm"]:
        volumes = {w for w in argv[3:] if not w.startswith("-")}
        if not volumes or not volumes <= set(VOLUMES):
            raise RuntimeError("refused: only the tier's own volumes may be removed")
    if argv not in allowed_commands():
        raise RuntimeError(f"refused: {' '.join(command)} is not one of the tier's own commands")


def run(
    command: Sequence[str], settings: Settings, *, capture: bool = False, stdin: str | None = None
) -> str:
    check_command(command)
    result = subprocess.run(  # noqa: S603 - fixed argv, checked above
        list(command),
        env=docker_env(settings),
        check=True,
        text=True,
        capture_output=capture,
        input=stdin,
    )
    return result.stdout if capture else ""


# --------------------------------------------------------------------------- HTTP


class TierError(RuntimeError):
    pass


class TierBusy(TierError):
    """Another session holds the tier (or the seed) in a way that excludes this one."""


TIER_LOCK = "tier.lock"  # live test sessions: shared; exclusive use, `down`, `reset`: alone
SEED_LOCK = "seed.lock"  # one seed at a time


class TierLock:
    """An flock on a file in the tier's directory, which every worktree shares: live test
    sessions hold ``tier.lock`` shared for their whole run; whatever would break them (a test
    that stops the tier or takes the security index away, `down`, `reset`) needs it alone.
    flock ends with its holder, so a crashed session never leaves the tier locked."""

    def __init__(self, paths: Paths, name: str = TIER_LOCK) -> None:
        self.path = paths.root / name
        self.fd: int | None = None

    def _flock(self, operation: int, wait: float, what: str) -> None:
        assert self.fd is not None
        deadline = time.monotonic() + wait
        while True:
            try:
                fcntl.flock(self.fd, operation | fcntl.LOCK_NB)
                return
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TierBusy(what) from None
                time.sleep(0.5)

    def acquire(self, *, exclusive: bool, wait: float = 0.0) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            self._flock(
                fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH,
                wait,
                f"{self.path.name}: "
                + (
                    "another session uses the tier (live test sessions share it; whatever stops "
                    "it or breaks it needs it alone)"
                    if exclusive
                    else "the tier is held alone (an exclusive test, `down` or `reset`)"
                ),
            )
        except BaseException:
            self.release()
            raise

    def release(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    @contextlib.contextmanager
    def exclusively(self, wait: float = 0.0) -> Iterator[None]:
        """This (shared) holder alone for a while, then shared again. Linux converts a lock by
        dropping it first, so a refused upgrade takes the shared lock back before it raises."""
        try:
            self._flock(fcntl.LOCK_EX, wait, "another live session uses the tier")
        except TierBusy:
            self._flock(fcntl.LOCK_SH, 60.0, "the tier is held alone")
            raise
        try:
            yield
        finally:
            self._flock(fcntl.LOCK_SH, 60.0, "the tier is held alone")


@contextlib.contextmanager
def tier_lock(
    paths: Paths, *, exclusive: bool, wait: float = 0.0, name: str = TIER_LOCK
) -> Iterator[TierLock]:
    lock = TierLock(paths, name)
    lock.acquire(exclusive=exclusive, wait=wait)
    try:
        yield lock
    finally:
        lock.release()


def tls_context(ca_file: Path) -> ssl.SSLContext:
    """Verify the tier against its own CA only: CERT_REQUIRED, hostname checked, TLS >= 1.2."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile=str(ca_file))
    return context


def basic(username: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()


@dataclass
class Http:
    """A small client for the tier: one base URL, one credential, the tier's CA. ``as_user``
    and ``as_key`` give the same connection pool with another credential."""

    base_url: str
    authorization: str = field(repr=False)  # a credential: never in a report
    ca_file: Path
    timeout: float = 30.0
    client: httpx.Client | None = field(default=None, repr=False)
    last_status: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        if self.client is None:
            self.client = httpx.Client(
                base_url=self.base_url,
                verify=tls_context(self.ca_file),
                trust_env=False,
                follow_redirects=False,
                timeout=self.timeout,
            )

    def as_user(self, username: str, password: str) -> Http:
        return Http(
            self.base_url, basic(username, password), self.ca_file, self.timeout, self.client
        )

    def as_key(self, encoded: str) -> Http:
        return Http(self.base_url, f"ApiKey {encoded}", self.ca_file, self.timeout, self.client)

    def close(self) -> None:
        assert self.client is not None
        self.client.close()

    def send(
        self,
        method: str,
        path: str,
        body: Any = None,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        content: bytes | None = None,
    ) -> httpx.Response:
        assert self.client is not None
        sent = {"Authorization": self.authorization, "kbn-xsrf": "argus-tier"}
        sent.update(headers or {})
        response = self.client.request(
            method,
            path,
            json=body if content is None else None,
            content=content,
            params=params,
            headers=sent,
        )
        self.last_status = response.status_code
        return response

    def request(
        self,
        method: str,
        path: str,
        body: Any = None,
        *,
        params: Mapping[str, Any] | None = None,
        ok: Sequence[int] = (200,),
        headers: Mapping[str, str] | None = None,
    ) -> Any:
        response = self.send(method, path, body, params=params, headers=headers)
        if response.status_code not in ok:
            raise TierError(f"{method} {path}: HTTP {response.status_code} {response.text[:600]}")
        if not response.content:
            return None
        try:
            return response.json()
        except ValueError:
            return response.text

    def bulk(self, ndjson: str, **params: str) -> Any:
        response = self.send(
            "POST",
            "/_bulk",
            params=params,
            headers={"Content-Type": "application/x-ndjson"},
            content=ndjson.encode(),
        )
        if response.status_code != 200:
            raise TierError(f"POST /_bulk: HTTP {response.status_code} {response.text[:600]}")
        return response.json()


def es_admin(settings: Settings, data: Mapping[str, Any], timeout: float = 30.0) -> Http:
    return Http(
        settings.es_url,
        basic("elastic", data["passwords"]["elastic"]),
        settings.paths.ca_crt,
        timeout,
    )


def kibana_admin(settings: Settings, data: Mapping[str, Any], timeout: float = 60.0) -> Http:
    return Http(
        settings.kibana_url,
        basic("elastic", data["passwords"]["elastic"]),
        settings.paths.ca_crt,
        timeout,
    )


def wait_for(what: str, check: Callable[[], bool], *, seconds: float, every: float = 2.0) -> float:
    """Call ``check`` until it is true; the seconds it took. Raises TierError at the deadline."""
    started = time.monotonic()
    while True:
        try:
            if check():
                return time.monotonic() - started
        except (httpx.HTTPError, TierError, ssl.SSLError, OSError):
            pass
        if time.monotonic() - started > seconds:
            raise TierError(f"{what}: not ready after {seconds:.0f} s")
        time.sleep(every)


def es_ready(es: Http) -> bool:
    health = es.request("GET", "/_cluster/health", params={"wait_for_status": "yellow"})
    return bool(health.get("status") in ("green", "yellow"))


def kibana_available(kibana: Http) -> bool:
    status = kibana.request("GET", "/api/status")
    return bool(status["status"]["overall"]["level"] == "available")


# --------------------------------------------------------------------------- commands


def cmd_init(settings: Settings, args: argparse.Namespace) -> int:
    from_seed = _seed_module()
    paths = settings.paths
    paths.root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(paths.root, 0o700)
    data = ensure_secrets(paths, from_seed.usernames())
    made = ensure_certificates(paths, now=datetime.now(UTC), force=args.new_ca)
    write_configuration(settings, data)
    print(f"tier files in {paths.root}; certificates made: {', '.join(made) or 'none (fresh)'}")
    return 0


def cmd_up(settings: Settings, args: argparse.Namespace) -> int:
    if not os.environ.get("HEAVY_SLOT_HELD"):
        raise SystemExit(
            "the tier runs inside a heavy-task slot (D-110): scripts/heavy.sh --label "
            "kibana-tier uv run python scripts/kibana_tier.py up --hold (or plain `up` inside "
            "a job that holds a slot for the tier's whole life)"
        )
    cmd_init(settings, argparse.Namespace(new_ca=False))
    data = load_secrets(settings.paths)
    started = time.monotonic()
    args.hold = getattr(args, "hold", False)
    for command in commands_for("start-es"):
        run(command, settings)
    es = es_admin(settings, data, timeout=10)
    try:
        took = wait_for("Elasticsearch", lambda: es_ready(es), seconds=args.timeout)
        print(f"Elasticsearch {VERSION} ready after {took:.0f} s")
        es.request(
            "POST",
            "/_security/user/kibana_system/_password",
            {"password": data["passwords"]["kibana_system"]},
        )
    finally:
        es.close()
    for command in commands_for("start-kibana"):
        run(command, settings)
    kibana = kibana_admin(settings, data, timeout=10)
    try:
        took = wait_for("Kibana", lambda: kibana_available(kibana), seconds=args.timeout)
    finally:
        kibana.close()
    print(f"Kibana {VERSION} available after {took:.0f} s ({time.monotonic() - started:.0f} s)")
    warn_if_drifted(settings)
    if args.hold:
        return hold(settings)
    return 0


def tier_state(settings: Settings) -> str:
    """The tier's containers now: "running" (both), "partial" (one), "stopped" (neither, or
    removed) or "unknown" (docker did not say)."""
    try:
        states = run(commands_for("running")[0], settings, capture=True).split()
    except subprocess.CalledProcessError as exc:
        if "no such object" not in (exc.stderr or "").lower():  # docker 29: "error: no such"
            return "unknown"  # the daemon or the CLI failed: says nothing about the tier
        states = (exc.stdout or "").split()  # the containers that are still there
    running = states.count("true")
    if running == len(CONTAINERS):
        return "running"
    return "partial" if running else "stopped"


HOLD_UNKNOWN_LIMIT = 3  # docker failing this many times in a row ends the hold (with a stop)


def held_alone(paths: Paths) -> bool:
    """Whether someone holds the tier's lock alone: an exclusive test (which may stop one
    container on purpose), `down` or `reset` (which stop them one by one)."""
    try:
        with tier_lock(paths, exclusive=False):
            return False
    except TierBusy:
        return True


def hold(settings: Settings, *, every: float = 10.0) -> int:
    """Stay in the foreground while the tier runs, so the heavy-task slot this command was
    started in (scripts/heavy.sh) counts the tier for as long as it lives (D-110 lists the
    tier among the heavy jobs). Ends when the tier is stopped (`down`, `reset`): 0. When one
    container stops alone (an OOM kill: the tier has no restart policy) or docker keeps
    failing, it stops the rest of the tier first: 1; half a tier is left alone while someone
    holds the tier's lock alone (an exclusive test, `down`, `reset`). Interrupted (Ctrl-C,
    SIGTERM, a closed terminal's SIGHUP, the slot's scope ending), it stops the tier first:
    130. Only a SIGKILL can end it without a stop."""

    def interrupted(signum: int, frame: object) -> None:
        raise KeyboardInterrupt

    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGHUP)}
    print("holding the heavy-task slot while the tier runs (stop it with `down`)", flush=True)
    try:
        unknown = 0
        while True:
            state = tier_state(settings)
            unknown = unknown + 1 if state == "unknown" else 0
            waiting = state == "partial" and held_alone(settings.paths)
            if state == "running" or waiting or 0 < unknown < HOLD_UNKNOWN_LIMIT:
                time.sleep(every)
                continue
            if state == "stopped":
                print("the tier has stopped: the slot is free", flush=True)
                return 0
            why = "one of its containers stopped" if state == "partial" else "docker fails"
            print(f"{why}: stopping the rest of the tier", flush=True)
            for command in commands_for("stop"):
                run(command, settings)
            return 1
    except KeyboardInterrupt:
        for command in commands_for("stop"):
            run(command, settings)
        print("interrupted: the tier is stopped", flush=True)
        return 130
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def _alone(settings: Settings, args: argparse.Namespace) -> TierLock | None:
    """The tier alone for `down` or `reset`, so they never pull it from under another worktree's
    live test session (None, and why, when one holds it). ``--force`` skips the check."""
    lock = TierLock(settings.paths)
    if getattr(args, "force", False):
        return lock
    try:
        lock.acquire(exclusive=True)
    except TierBusy:
        print(
            "a live test session (another worktree's?) is using the tier: wait for it, or add "
            "--force to stop the tier from under it"
        )
        return None
    return lock


def cmd_down(settings: Settings, args: argparse.Namespace) -> int:
    lock = _alone(settings, args)
    if lock is None:
        return 3
    try:
        for command in commands_for("stop"):
            run(command, settings)
    finally:
        lock.release()
    return 0


def cmd_reset(settings: Settings, args: argparse.Namespace) -> int:
    if not args.yes:
        print("reset removes the tier's containers and volumes (kibana-es, kibana); add --yes")
        return 2
    lock = _alone(settings, args)
    if lock is None:
        return 3
    try:
        for command in commands_for("remove"):
            run(command, settings)
    finally:
        lock.release()
    if settings.paths.secrets.is_file():
        data = load_secrets(settings.paths)
        data["api_keys"] = {}  # they lived in the removed volume
        save_secrets(settings.paths, data)
    print("the tier's containers and volumes are removed; `up` then `seed` start it clean")
    return 0


MEMORY_UNITS = {
    "B": 1 / 1024 / 1024,
    "kB": 1000 / 1024 / 1024,
    "KiB": 1 / 1024,
    "MB": 1000 * 1000 / 1024 / 1024,
    "MiB": 1.0,
    "GB": 1000**3 / 1024 / 1024,
    "GiB": 1024.0,
}
MEMORY_USAGE = re.compile(r"\s*(\d+(?:\.\d+)?)\s*([A-Za-z]+)\s*")


def memory_mib(text: str) -> float:
    """docker stats' "123.4MiB / 1.5GiB" usage part, in MiB."""
    match = MEMORY_USAGE.fullmatch(text.split("/", 1)[0])
    if match is None or match[2] not in MEMORY_UNITS:
        raise ValueError(f"not a memory usage: {text!r}")
    return float(match[1]) * MEMORY_UNITS[match[2]]


def sample_memory(settings: Settings) -> dict[str, float]:
    """Each running tier container's memory now (docker stats: page cache left out), MiB."""
    try:
        out = run(commands_for("stats")[0], settings, capture=True)
    except subprocess.CalledProcessError:
        return {}  # a container is not there (yet)
    sample: dict[str, float] = {}
    for line in out.splitlines():
        name, usage = line.split("\t", 1)
        with contextlib.suppress(ValueError):
            sample[name] = memory_mib(usage)
    return sample


CGROUP_ROOT = Path("/sys/fs/cgroup")


def container_ids(settings: Settings) -> dict[str, str]:
    """Each existing tier container's full id (through run(), like every docker command)."""
    ids: dict[str, str] = {}
    for name, command in zip(CONTAINERS.values(), commands_for("ids"), strict=True):
        try:
            ids[name] = run(command, settings, capture=True).strip()
        except subprocess.CalledProcessError:
            continue  # not there
    return ids


def _scope(container_id: str, cgroup_root: Path = CGROUP_ROOT) -> Path:
    if not re.fullmatch(r"[0-9a-f]{12,64}", container_id):
        raise ValueError(f"not a container id: {container_id!r}")
    return cgroup_root / "system.slice" / f"docker-{container_id}.scope"


def cgroup_memory(settings: Settings) -> dict[str, dict[str, float]]:
    """The kernel's view of each container since it started: memory.peak (page cache
    included: an upper bound) and anonymous memory now, in MiB, and its OOM kills."""
    found: dict[str, dict[str, float]] = {}
    for name, container_id in container_ids(settings).items():
        try:
            scope = _scope(container_id)
            stat = dict(line.split() for line in (scope / "memory.stat").read_text().splitlines())
            events = dict(
                line.split() for line in (scope / "memory.events").read_text().splitlines()
            )
            found[name] = {
                "peak_mib": round(int((scope / "memory.peak").read_text()) / 1024 / 1024, 1),
                "anon_mib": round(int(stat["anon"]) / 1024 / 1024, 1),
                "oom_kill": int(events.get("oom_kill", 0)),
            }
        except (OSError, ValueError, KeyError):
            continue
    return found


# Run inside each tier container as its own user (from the host, Elasticsearch's processes run
# with gid 0 and cannot be read): which processes hold one of the secrets read from stdin, one
# a line, in their environment or command line. It prints process ids only, never a value.
PROCESS_CHECK = r"""pats=$(cat)
if [ -z "$pats" ]; then echo "no secrets given" >&2; exit 2; fi
for d in /proc/[0-9]*; do
  p=${d#/proc/}
  [ "$p" = "$$" ] && continue
  if ! tr '\0' '\n' < "$d/environ" > /dev/null 2>&1; then
    [ -d "$d" ] && echo "unreadable $p"
    continue
  fi
  echo "seen $p"
  if tr '\0' '\n' < "$d/environ" 2>/dev/null | grep -qF -f <(printf '%s\n' "$pats"); then
    echo "found $p environment"
  fi
  if tr '\0' '\n' < "$d/cmdline" 2>/dev/null | grep -qF -f <(printf '%s\n' "$pats"); then
    echo "found $p command line"
  fi
done
exit 0
"""


def parse_process_check(
    name: str, text: str
) -> tuple[int, list[tuple[str, int]], list[tuple[str, int, str]]]:
    """PROCESS_CHECK's output: processes read, (container, pid) unreadable, findings."""
    seen = 0
    unreadable: list[tuple[str, int]] = []
    found: list[tuple[str, int, str]] = []
    for line in text.splitlines():
        word, _, rest = line.partition(" ")
        if word == "seen":
            seen += 1
        elif word == "unreadable":
            unreadable.append((name, int(rest)))
        elif word == "found":
            pid, _, where = rest.partition(" ")
            found.append((name, int(pid), where))
    return seen, unreadable, found


def secrets_in_containers(
    settings: Settings, values: Sequence[str]
) -> tuple[int, list[tuple[str, int]], list[tuple[str, int, str]]]:
    """Whether any process of the tier's containers holds one of ``values`` in its environment
    or command line (secrets reach the containers only as files): processes read, processes
    unreadable, findings. A container that is not running is left out."""
    secrets_text = "".join(f"{v}\n" for v in values if v)
    if not secrets_text:
        raise ValueError("no secrets to look for")
    seen = 0
    unreadable: list[tuple[str, int]] = []
    found: list[tuple[str, int, str]] = []
    for name, command in zip(CONTAINERS.values(), commands_for("process-check"), strict=True):
        try:
            out = run(command, settings, capture=True, stdin=secrets_text)
        except subprocess.CalledProcessError:
            continue
        one = parse_process_check(name, out)
        seen += one[0]
        unreadable += one[1]
        found += one[2]
    return seen, unreadable, found


def tier_secret_values(data: Mapping[str, Any]) -> list[str]:
    """Every secret the tier's directory holds (passwords, encryption keys, minted keys)."""
    values = [*data.get("passwords", {}).values(), *data.get("encryption_keys", {}).values()]
    for key in data.get("api_keys", {}).values():
        encoded = str(key.get("encoded", ""))
        values.append(encoded)
        with contextlib.suppress(ValueError):  # its id:key, decoded
            values.append(base64.b64decode(encoded).decode().split(":", 1)[1])
    return [str(v) for v in values if v]


# The day-1 go/no-go: the tier beside production within the plan's 3.5 GB (§5), read in decimal
# units, the stricter way: 3,338 MiB.
BUDGET_MIB = 3_500_000_000 / 1024 / 1024


def host_available_mib() -> float:
    for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) / 1024
    return float("nan")


def cmd_stats(settings: Settings, args: argparse.Namespace) -> int:
    """Sample until the time is up (or the stop file appears); the peaks. Exit 0 within the
    budget, 1 over it, 2 when no sample held both containers (nothing measured: no go)."""
    peak: dict[str, float] = {}
    peak_total = 0.0
    lowest_available = float("inf")
    deadline = time.monotonic() + args.seconds
    samples = 0
    complete = 0  # samples of both containers: only these say what the tier needs
    while True:
        sample = sample_memory(settings)
        samples += 1
        for name, mib in sample.items():
            peak[name] = max(peak.get(name, 0.0), mib)
        if set(CONTAINERS.values()) <= set(sample):
            complete += 1
        peak_total = max(peak_total, sum(sample.values()))
        lowest_available = min(lowest_available, host_available_mib())
        if time.monotonic() >= deadline or (args.until and Path(args.until).exists()):
            break
        time.sleep(args.interval)
    result = {
        "samples": samples,
        "samples_of_both": complete,
        "peak_mib": {k: round(v, 1) for k, v in sorted(peak.items())},
        "peak_total_mib": round(peak_total, 1),
        # the kernel's own view since each container started: its peak (page cache
        # included), anonymous memory now, OOM kills
        "cgroup": dict(sorted(cgroup_memory(settings).items())),
        "host_lowest_available_mib": round(lowest_available, 1),
        "budget_mib": round(BUDGET_MIB, 1),
    }
    print(json.dumps(result, indent=1))
    if peak_total > BUDGET_MIB:
        return 1
    if not complete:
        print("nothing measured: no sample held both of the tier's containers", file=sys.stderr)
        return 2
    return 0


def drifted(settings: Settings) -> list[str]:
    """The tier's containers made from another version of their compose services: `up` keeps
    them (--no-recreate, so other worktrees never restart a running tier), so a change to the
    services takes effect only after `reset --yes`."""
    try:
        wanted = dict(
            line.split(None, 1)
            for line in run(commands_for("hash")[0], settings, capture=True).splitlines()
        )
        made = dict(
            line.lstrip("/").split(None, 1)
            for line in run(commands_for("labels")[0], settings, capture=True).splitlines()
        )
    except (subprocess.CalledProcessError, ValueError):
        return []  # no containers (yet): nothing has drifted
    return [
        service
        for service, container in CONTAINERS.items()
        if container in made and made[container].strip() != wanted.get(service, "").strip()
    ]


def warn_if_drifted(settings: Settings) -> None:
    services = drifted(settings)
    if services:
        print(
            f"warning: {', '.join(services)} run(s) an older definition from docker-compose.yml; "
            "`reset --yes` (then `up`, `seed`) applies the current one",
            flush=True,
        )


def cmd_status(settings: Settings, args: argparse.Namespace) -> int:
    print(run(commands_for("ps")[0], settings, capture=True).strip())
    warn_if_drifted(settings)
    if not settings.paths.secrets.is_file():
        print("not initialised (no secrets): run init")
        return 1
    data = load_secrets(settings.paths)
    es = es_admin(settings, data, timeout=5)
    kibana = kibana_admin(settings, data, timeout=5)
    try:
        info = es.request("GET", "/")
        lic = es.request("GET", "/_license")["license"]
        status = kibana.request("GET", "/api/status")
        print(
            f"Elasticsearch {info['version']['number']} licence {lic['type']} ({lic['status']}); "
            f"Kibana {status['version']['number']} {status['status']['overall']['level']}"
        )
        print(json.dumps(_seed_module().summary(es, kibana), indent=1))
    except (httpx.HTTPError, TierError, OSError) as exc:
        print(f"the tier does not answer: {exc}")
        return 1
    finally:
        es.close()
        kibana.close()
    print("memory now (MiB):", json.dumps(sample_memory(settings)))
    seen, unreadable, found = secrets_in_containers(settings, tier_secret_values(data))
    print(
        f"secrets in the environment or command line of the tier's {seen} processes: "
        + (", ".join(f"{name} pid {pid} ({where})" for name, pid, where in found) or "none")
        + (f"; {len(unreadable)} could not be read" if unreadable else "")
    )
    return 1 if found or unreadable or not seen else 0


def cmd_seed(settings: Settings, args: argparse.Namespace) -> int:
    """Seed the tier, one seed at a time: a second waits up to ``--wait`` seconds (two at once
    both minted `argus`'s keys)."""
    seed = _seed_module()
    try:
        lock = TierLock(settings.paths, SEED_LOCK)
        lock.acquire(exclusive=True, wait=args.wait)
    except TierBusy:
        print(f"another seed is running (waited {args.wait:.0f} s): run `status` when it ends")
        return 3
    try:
        data = ensure_secrets(settings.paths, seed.usernames())
        es = es_admin(settings, data, timeout=60)
        kibana = kibana_admin(settings, data, timeout=120)
        started = time.monotonic()
        try:
            report = seed.seed(
                data, es, kibana, log=print, save=lambda: save_secrets(settings.paths, data)
            )
        finally:
            es.close()
            kibana.close()
    finally:
        lock.release()
    report["seconds"] = round(time.monotonic() - started, 1)
    report["changed"] = seed_changes(report)
    print(json.dumps(report, indent=1))
    if args.expect_kept and report["changed"]:
        print(f"the seed changed {', '.join(report['changed'])}: expected none", file=sys.stderr)
        return 4
    return 0


SEED_CHANGES = frozenset({"created", "updated", "minted", "re-minted"})


def seed_changes(report: Mapping[str, Any], prefix: str = "") -> list[str]:
    """What a seed's report says it changed (an idempotent second run changes nothing)."""
    changed: list[str] = []
    for key, value in report.items():
        if isinstance(value, Mapping):
            changed += seed_changes(value, f"{prefix}{key}.")
        elif value in SEED_CHANGES or key == "surplus keys invalidated":
            changed.append(f"{prefix}{key}")
    return changed


# Test runs name what they make after their run id (tests/kibana/tier.py): kt<yymmddHHMMSS>...
RUN_NAME = re.compile(r"kt(\d{12})[0-9a-f]{4}")


def run_started(name: str) -> datetime | None:
    """When the test run that made ``name`` started, from the run id in it; None if none."""
    match = RUN_NAME.search(name)
    if match is None:
        return None
    try:
        return datetime.strptime(match[1], "%y%m%d%H%M%S").replace(tzinfo=UTC)
    except ValueError:
        return None


def stale(name: str, *, now: datetime, older_than: timedelta) -> bool:
    started = run_started(name)
    return started is not None and now - started > older_than


def cmd_clean(settings: Settings, args: argparse.Namespace) -> int:
    """Remove what crashed test runs left (rules, cases, keys, users, roles named after a run
    older than ``--hours``), leaving the seed and every recent run alone."""
    data = load_secrets(settings.paths)
    es = es_admin(settings, data)
    kibana = kibana_admin(settings, data)
    now = datetime.now(UTC)
    older = timedelta(hours=args.hours)
    space = f"/s/{_seed_module().SPACE}"
    removed = {"rules": 0, "cases": 0, "users": 0, "roles": 0}
    try:
        page = 1
        while True:
            found = kibana.request(
                "GET",
                f"{space}/api/detection_engine/rules/_find",
                params={"page": page, "per_page": 100},
            )
            for rule in found["data"]:
                if rule["rule_id"].startswith("argus-tier-run-") and stale(
                    rule["rule_id"], now=now, older_than=older
                ):
                    kibana.request(
                        "DELETE",
                        f"{space}/api/detection_engine/rules",
                        params={"rule_id": rule["rule_id"]},
                        ok=(200, 404),
                    )
                    removed["rules"] += 1
            if page * 100 >= found["total"]:
                break
            page += 1
        doomed: list[str] = []
        page = 1
        while True:
            found = kibana.request(
                "GET", f"{space}/api/cases/_find", params={"page": page, "perPage": 100}
            )
            for case in found["cases"]:
                if any(
                    t.startswith("run:kt") and stale(t, now=now, older_than=older)
                    for t in case["tags"]
                ):
                    doomed.append(case["id"])
            if page * 100 >= found["total"] or page >= 100:
                break
            page += 1
        for start in range(0, len(doomed), 100):
            kibana.request(
                "DELETE",
                f"{space}/api/cases",
                params={"ids": json.dumps(doomed[start : start + 100])},
                ok=(204,),
            )
        removed["cases"] = len(doomed)
        for name in es.request("GET", "/_security/user"):
            if name.startswith("t-kt") and stale(name, now=now, older_than=older):
                es.request("DELETE", "/_security/api_key", {"username": name}, ok=(200, 404))
                es.request("DELETE", f"/_security/user/{name}", ok=(200, 404))
                removed["users"] += 1
        for name in es.request("GET", "/_security/role"):
            if name.startswith("t-kt") and stale(name, now=now, older_than=older):
                es.request("DELETE", f"/_security/role/{name}", ok=(200, 404))
                removed["roles"] += 1
    finally:
        es.close()
        kibana.close()
    print(json.dumps(removed))
    return 0


def cmd_env(settings: Settings, args: argparse.Namespace) -> int:
    """The variables tests read (no secrets: those stay in the tier directory)."""
    print(f"KIBANA_TIER_URL={settings.kibana_url}")
    print(f"KIBANA_TIER_ES_URL={settings.es_url}")
    print(f"KIBANA_TIER_DIR={settings.paths.root}")
    return 0


def _seed_module() -> Any:
    """The seed definitions (scripts/kibana_seed.py), loaded beside this file."""
    import importlib.util

    module = sys.modules.get("argus_kibana_seed")
    if module is None:
        spec = importlib.util.spec_from_file_location(
            "argus_kibana_seed", Path(__file__).with_name("kibana_seed.py")
        )
        assert spec is not None
        assert spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    return module


def _activate_checkout_site() -> None:
    """The checkout's site is the tier's (its space and role names, scripts/kibana_seed.py):
    config/argus.yaml with config/site.yaml beside it, read without .env (no secret is needed)."""
    from argus.config.settings import ConfigError, load_settings

    try:
        load_settings(ROOT / "config" / "argus.yaml", env_file=None)
    except ConfigError as exc:
        raise SystemExit(f"kibana_tier: the checkout's config cannot be read: {exc}") from exc


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("init", help="make the CA, certificates and secrets (idempotent)")
    p.add_argument("--new-ca", action="store_true", help="re-issue the CA and certificates")
    p = sub.add_parser("up", help="start the tier and wait until Kibana is available")
    p.add_argument("--timeout", type=float, default=600)
    p.add_argument(
        "--hold",
        action="store_true",
        help="then stay in the foreground until the tier stops (keeps the heavy-task slot)",
    )
    p = sub.add_parser("seed", help="seed the space, roles, users, keys, rule and alerts")
    p.add_argument("--wait", type=float, default=600, help="seconds to wait for another seed")
    p.add_argument(
        "--expect-kept", action="store_true", help="exit 4 if anything had to change (the gate)"
    )
    sub.add_parser("status", help="containers, versions, licence, seed, memory")
    p = sub.add_parser("stats", help="sample memory and print the peak")
    p.add_argument("--seconds", type=float, default=60)
    p.add_argument("--interval", type=float, default=2)
    p.add_argument("--until", help="stop early once this file exists")
    p = sub.add_parser("down", help="stop the tier (keeps its data)")
    p.add_argument("--force", action="store_true", help="even while live test sessions use it")
    p = sub.add_parser("reset", help="remove the tier's containers and volumes")
    p.add_argument("--yes", action="store_true")
    p.add_argument("--force", action="store_true", help="even while live test sessions use it")
    sub.add_parser("env", help="print the variables tests read")
    p = sub.add_parser("clean", help="remove what crashed test runs left behind")
    p.add_argument("--hours", type=float, default=6, help="only runs older than this")
    args = parser.parse_args(argv)
    _activate_checkout_site()
    settings = Settings.from_env()
    handlers: dict[str, Callable[[Settings, argparse.Namespace], int]] = {
        "init": cmd_init,
        "up": cmd_up,
        "seed": cmd_seed,
        "status": cmd_status,
        "stats": cmd_stats,
        "down": cmd_down,
        "reset": cmd_reset,
        "env": cmd_env,
        "clean": cmd_clean,
    }
    return handlers[args.command](settings, args)


if __name__ == "__main__":
    sys.exit(main())
