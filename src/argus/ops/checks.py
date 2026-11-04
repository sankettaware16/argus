"""``argus doctor``'s platform checks: certificates and keys that expire, where the write keys
are, the local model's tunnel, the service units, the backups, the frontend's toolchain and build,
the threat-intel feeds' freshness and the probe readings. Read-only and local: no request reaches
the SIEM; the only connection made is a TLS handshake with the local model's tunnel on this
machine's loopback. Each check is a plain function over explicit paths (what the tests call); the
registered checks at the end give them the real ones."""

from __future__ import annotations

import glob
import io
import os
import pwd
import subprocess
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, datetime, time, timedelta
from pathlib import Path

import yaml
from dotenv.parser import parse_stream
from sqlalchemy import text

from argus.config.settings import ConfigError, Settings
from argus.db.engine import create_engine
from argus.db.errors import DB_ERRORS, short_db_error
from argus.doctor import CheckResult, register_check
from argus.ops import backup, certs, custody, frontend, units
from argus.ops.units import REPO, UNITS_DIR
from argus.reference import store as reference_store
from argus.web import spa

# deploy/local-llm/setup-argus-side.sh: TUNNEL_PORT and CERT_FILE (a test keeps them equal)
LOCAL_LLM_PORT = 18443
LOCAL_LLM_CERT = Path("data/tls/local-llm.crt")
# The keys that can change Kibana or the alerts: the case writer, the Kibana lane's cases and alert
# writers and the case team's users. Each belongs to the writer's own credential, nowhere else.
WRITE_KEYS = {
    "siem.writer_api_key": "ARGUS_SIEM__WRITER_API_KEY",
    "kibana.cases_writer_api_key": "ARGUS_KIBANA__CASES_WRITER_API_KEY",
    "kibana.alert_writer_api_key": "ARGUS_KIBANA__ALERT_WRITER_API_KEY",
    # the case team's users: the same rule, one key each
    "case_team.lead_api_key": "ARGUS_CASE_TEAM__LEAD_API_KEY",
    "case_team.evidence_api_key": "ARGUS_CASE_TEAM__EVIDENCE_API_KEY",
    "case_team.intel_api_key": "ARGUS_CASE_TEAM__INTEL_API_KEY",
    "case_team.responder_api_key": "ARGUS_CASE_TEAM__RESPONDER_API_KEY",
    "case_team.hunter_api_key": "ARGUS_CASE_TEAM__HUNTER_API_KEY",
    "case_team.reporter_api_key": "ARGUS_CASE_TEAM__REPORTER_API_KEY",
    "case_team.visualiser_api_key": "ARGUS_CASE_TEAM__VISUALISER_API_KEY",  # optional
}
PROBES_STALE = timedelta(minutes=15)
NOTICES_LATE = timedelta(hours=1)  # the timer runs every 10 minutes: an hour without a pass is late
PROC = Path("/proc")


def _now() -> datetime:
    return datetime.now(UTC)


def certificate_result(name: str, path: Path, now: datetime, renew: str) -> CheckResult:
    """A certificate's expiry: WARN within 30 days, FAIL once expired or unreadable."""
    try:
        info = certs.read_cert(path)
    except ValueError as exc:
        return CheckResult(name, False, str(exc))
    left = certs.expiry(info.not_after, now)
    until = f"{info.not_after:%Y-%m-%d}"
    if left.state == "expired":
        return CheckResult(name, False, f"{info.subject} expired on {until}: {renew}")
    if left.state == "soon":
        return CheckResult(
            name, True, f"{info.subject} expires {until} (in {left.days} days): {renew}", warn=True
        )
    return CheckResult(name, True, f"{info.subject}, valid until {until} ({left.days} days)")


def web_certificate(
    settings: Settings, repo: Path = REPO, system_unit: Path | None = None
) -> tuple[Path | None, str, int]:
    """The certificate the web serves, where that was found and the web's port:
    ``web.tls_cert``; else, under custody, the system unit's; else the user unit's
    environment (its template rendered for this installation) when this checkout is the
    one the unit runs (the production web)."""
    if settings.web.tls_cert is not None:
        return settings.web.tls_cert, "web.tls_cert", settings.web.port
    if system_unit is None and custody.marker() is not None:
        system_unit = custody.SYSTEM_UNITS / "argus-web.service"
    if system_unit is not None and system_unit.is_file():
        environment = units.unit_environment(system_unit)
        cert, port = environment.get("ARGUS_WEB__TLS_CERT"), environment.get("ARGUS_WEB__PORT", "")
        if cert is not None and Path(cert).is_absolute():
            number = int(port) if port.isdigit() else settings.web.port
            return Path(cert), f"{system_unit.name} (custody)", number
    template = repo / "deploy" / "systemd" / "argus-web.service"
    if not template.is_file():
        return None, "", settings.web.port
    try:
        unit = units.render(template.read_text(encoding="utf-8"), _unit_params(settings))
    except units.UnitsError:
        return None, "", settings.web.port
    folder = units.working_directory_of(unit)
    environment = units.environment_of(unit)
    cert = environment.get("ARGUS_WEB__TLS_CERT")
    if cert is None or folder is None or folder.resolve() != repo.resolve():
        return None, "", settings.web.port
    port = environment.get("ARGUS_WEB__PORT", "")
    path = Path(cert)
    return (
        path if path.is_absolute() else folder / path,
        "argus-web.service",
        int(port) if port.isdigit() else settings.web.port,
    )


def _unit_params(settings: Settings) -> units.UnitParams:
    """This installation's rendering parameters; a uv that cannot be found renders as ``uv``
    (the installed copy then differs, and doctor says so)."""
    try:
        return units.params_of(settings.units)
    except units.UnitsError:
        return units.params_of(settings.units, uv="uv")


async def web_certificate_checks(
    settings: Settings, now: datetime, repo: Path = REPO, wait_s: float = 3.0
) -> list[CheckResult]:
    """Its expiry, and the alarm when it is no longer the pinned one: browsers then
    warn, and a person must never type a password past a certificate warning. The
    certificate the web serves on this machine is compared too, when the web is up."""
    path, source, port = web_certificate(settings, repo)
    if path is None:
        return [CheckResult("web certificate", True, "no TLS here (the web is on the loopback)")]
    renew = "renew it and pin the new one (web.tls_pin_sha256)"
    results = [certificate_result("web certificate", path, now, renew)]
    try:
        info = certs.read_cert(path)
    except ValueError:
        return results  # said above
    served = await certs.served_cert("127.0.0.1", port, wait_s)
    if served is not None and certs.fingerprint(served) != info.sha256:
        results.append(
            CheckResult(
                "web certificate served",
                False,
                f"the web on port {port} serves {certs.fingerprint(served)[:16]}..., not"
                f" {path} ({info.sha256[:16]}...): restart argus-web, or find out why",
            )
        )
    pin = settings.web.tls_pin_sha256
    if pin is None:
        results.append(
            CheckResult(
                "web certificate pin",
                True,
                f"not pinned: set web.tls_pin_sha256: {info.sha256} (from {source}), so a"
                " changed certificate raises an alarm",
                warn=True,
            )
        )
    elif pin != info.sha256:
        results.append(
            CheckResult(
                "web certificate pin",
                False,
                f"the certificate CHANGED: pinned {pin[:16]}..., {path} holds"
                f" {info.sha256[:16]}...; browsers will warn. If you replaced it, pin the new"
                " one; if not, find out why",
            )
        )
    else:
        results.append(CheckResult("web certificate pin", True, f"unchanged ({pin[:16]}...)"))
    return results


def key_expiry_results(settings: Settings, now: datetime) -> list[CheckResult]:
    """Every configured key's recorded expiry: WARN 30 days ahead and when none is recorded,
    FAIL once expired. No request: the expiry is what the key's creation recorded."""
    siem, kibana = settings.siem, settings.kibana
    keys = (
        ("SIEM key expiry", siem.api_key, siem.api_key_expires, "siem.api_key_expires"),
        (
            "writer key expiry",
            siem.writer_api_key,
            siem.writer_api_key_expires,
            "siem.writer_api_key_expires",
        ),
        (
            "Kibana reader key expiry",
            kibana.reader_api_key,
            kibana.reader_api_key_expires,
            "kibana.reader_api_key_expires",
        ),
        (
            "Kibana cases writer key expiry",
            kibana.cases_writer_api_key,
            kibana.cases_writer_api_key_expires,
            "kibana.cases_writer_api_key_expires",
        ),
        (
            "Kibana alert writer key expiry",
            kibana.alert_writer_api_key,
            kibana.alert_writer_api_key_expires,
            "kibana.alert_writer_api_key_expires",
        ),
    )
    results = []
    for name, key, expires, setting in keys:
        if key is None or not key.get_secret_value():
            continue
        if expires is None:
            results.append(
                CheckResult(
                    name,
                    True,
                    f"its expiry is not recorded: set {setting} (the expiration the key was"
                    " created with)",
                    warn=True,
                )
            )
            continue
        left = certs.expiry(datetime.combine(expires, time(0), UTC), now)
        if left.state == "expired":
            results.append(CheckResult(name, False, f"expired on {expires}: mint a new one"))
        elif left.state == "soon":
            results.append(
                CheckResult(
                    name, True, f"expires {expires} (in {left.days} days): rotate it", warn=True
                )
            )
        else:
            results.append(CheckResult(name, True, f"valid until {expires} ({left.days} days)"))
    return results


def _dotenv_sets(path: Path, variable: str, secret: str = "") -> bool:
    """Whether an env file gives ``variable`` a non-empty value as ARGUS would read it
    (python-dotenv's parser: quoted names, ``export``, the name in any case), or holds the
    secret's value anywhere (under any name). The value is never read out."""
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    if secret and secret in raw:
        return True
    wanted = variable.upper()
    for binding in parse_stream(io.StringIO(raw)):
        key = binding.key
        if key is not None and key.strip().upper() == wanted and (binding.value or "").strip():
            return True
    # every line is also read plainly: python-dotenv skips a line it cannot parse
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("export "):
            stripped = stripped[len("export ") :].lstrip()
        name, sep, value = stripped.partition("=")
        if sep and name.strip().strip("'\"").upper() == wanted and value.strip().strip("'\""):
            return True
    return False


def _unit_files(folders: Iterable[Path]) -> list[Path]:
    """ARGUS's unit files in ``folders``, with their drop-ins (``argus-x.service.d/*.conf``,
    and those for many units: ``argus-.service.d``, ``service.d``, ``timer.d``)."""
    found: list[Path] = []
    for folder in folders:
        if not folder.is_dir():
            continue
        for entry in sorted(folder.iterdir()):
            if entry.name.startswith("argus-") and entry.is_file():
                found.append(entry)
            elif entry.is_dir() and units.is_argus_drop_in_dir(entry.name):
                found += sorted(p for p in entry.glob("*.conf") if p.is_file())
    return found


def _unit_name(unit: Path) -> str | None:
    """The one unit a file configures: its own name, or its drop-in folder's
    (``x.service.d``); None for a drop-in that applies to many (``argus-.service.d``)."""
    name = unit.parent.name.removesuffix(".d") if unit.suffix == ".conf" else unit.name
    stem, _, kind = name.rpartition(".")
    return None if not stem or stem.endswith("-") or not kind else name


def _specifiers(unit: Path) -> dict[str, str]:
    """systemd's specifiers as a user manager expands them (systemd.unit(5)), those a path can
    use; the unit-name ones only where the file configures one unit."""
    home = Path.home()
    state = os.environ.get("XDG_STATE_HOME") or str(home / ".local" / "state")
    uid = os.getuid()
    try:
        user = pwd.getpwuid(uid).pw_name
    except KeyError:
        user = str(uid)
    values = {
        "h": str(home),
        "E": os.environ.get("XDG_CONFIG_HOME") or str(home / ".config"),
        "t": os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{uid}",
        "S": state,
        "C": os.environ.get("XDG_CACHE_HOME") or str(home / ".cache"),
        "L": str(Path(state) / "log"),
        "U": str(uid),
        "u": user,
        "%": "%",
    }
    name = _unit_name(unit)
    if name is not None:
        stem = name.rpartition(".")[0]
        prefix, at, instance = stem.partition("@")
        values |= {"n": name, "N": stem, "p": prefix, "i": instance if at else ""}
    return values


def _expand(value: str, specifiers: dict[str, str]) -> str | None:
    """``value`` with its specifiers expanded; None when one of them is not known here."""
    out: list[str] = []
    chars = iter(value)
    for char in chars:
        if char != "%":
            out.append(char)
            continue
        code = next(chars, "")
        if code not in specifiers:
            return None
        out.append(specifiers[code])
    return "".join(out)


def _environment_files(unit: Path, body: str, shared: Path) -> tuple[list[Path], list[str]]:
    """The files a unit loads with EnvironmentFile= (a leading - only makes one optional;
    specifiers and wildcards expanded as systemd expands them), except the shared .env, which is
    checked on its own; and, as written, the paths doctor cannot resolve."""
    files: list[Path] = []
    unknown: list[str] = []
    specifiers = _specifiers(unit)
    for line in body.splitlines():
        key, sep, value = line.strip().partition("=")
        if not sep or key.strip() != "EnvironmentFile":
            continue
        written = value.strip()
        if len(written) > 1 and written[0] == written[-1] and written[0] in "'\"":
            written = written[1:-1]
        expanded = _expand(written.lstrip("-"), specifiers)
        if expanded is None:
            unknown.append(written)
            continue
        if not expanded.startswith("/"):
            continue  # systemd refuses a relative path: nothing is loaded
        matches = sorted(glob.glob(expanded)) if glob.has_magic(expanded) else [expanded]
        for match in matches:
            path = Path(match)
            if path.is_file() and path.resolve() != shared.resolve():
                files.append(path)
    return files, unknown


def _yaml_sets(path: Path, section: str, field: str, secret: str) -> bool:
    """Whether a YAML config sets ``section.field``, or holds the secret's value anywhere."""
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
        data = yaml.safe_load(raw)
    except (OSError, yaml.YAMLError):
        return False
    if secret and secret in raw:
        return True
    part = data.get(section) if isinstance(data, dict) else None
    return isinstance(part, dict) and part.get(field) not in (None, "")


def _environ_holds(environ: bytes, variable: bytes, secret: bytes) -> bool:
    """Whether a process environment sets ``variable`` to something (the name in any case, as
    ARGUS reads it), or holds the secret's value under any name."""
    for entry in environ.split(b"\0"):
        name, sep, value = entry.partition(b"=")
        if (sep and value and name.upper() == variable) or (secret and secret in entry):
            return True
    return False


def write_key_problems(
    settings: Settings,
    *,
    env_file: Path,
    config_file: Path | None,
    unit_dirs: Iterable[Path],
    proc: Path | None = None,
    me: int | None = None,
    environ_now: dict[str, str] | None = None,
) -> list[str]:
    """Where a write key is that it must not be: the shared ``.env`` every
    ARGUS process loads, the YAML file, a unit file or drop-in and the files it loads, or the
    environment of any process of this user. Names are matched as ARGUS reads them (in any
    case), and the key's value is looked for under any name. Until the writer is given its
    own credential there is no right place, so any is wrong. Names places and processes, never
    a value."""
    problems: list[str] = []
    me = os.getpid() if me is None else me
    proc = PROC if proc is None else proc
    for setting, variable in WRITE_KEYS.items():
        section, _, field = setting.partition(".")
        value = getattr(getattr(settings, section), field)
        secret = value.get_secret_value() if value is not None else ""
        if _dotenv_sets(env_file, variable, secret):
            problems.append(f"{setting} is in {env_file}, which every ARGUS process loads")
        for yaml_file in _yaml_files(config_file):
            if _yaml_sets(yaml_file, section, field, secret):
                problems.append(f"{setting} is in {yaml_file} (secrets never go in YAML)")
        for unit in _unit_files(unit_dirs):
            body = unit.read_text(encoding="utf-8", errors="replace")
            if variable.lower() in body.lower() or (secret and secret in body):
                problems.append(f"{setting} is in the unit file {unit}")
            loaded, unknown = _environment_files(unit, body, env_file)
            problems += [
                f"{setting} is in {extra}, which {unit.name} loads"
                for extra in loaded
                if _dotenv_sets(extra, variable, secret)
            ]
            problems += [
                f"cannot tell whether {unit.name} loads {setting}: doctor cannot resolve"
                f" EnvironmentFile={path}"
                for path in unknown
            ]
        holders = []
        for entry in sorted(proc.glob("[0-9]*"), key=lambda p: int(p.name)):
            if not entry.name.isdigit() or int(entry.name) == me:
                continue  # this process: its environment now, below
            try:
                environ = (entry / "environ").read_bytes()
            except OSError:  # another user's process, or gone
                continue
            if _environ_holds(environ, variable.encode(), secret.encode()):
                try:
                    command = (entry / "comm").read_text(encoding="utf-8").strip()[:40]
                except OSError:
                    command = "?"
                holders.append(f"{command} (pid {entry.name})")
        mine = environ_now if environ_now is not None else dict(os.environ)
        named = any(name.upper() == variable and held for name, held in mine.items())
        if named or (secret and any(secret in held for held in mine.values())):
            holders.append("this doctor")
        if holders:
            problems.append(f"{setting} is in the environment of {', '.join(holders[:10])}")
    return problems


def write_key_result(problems: list[str], configured: bool) -> CheckResult:
    if problems:
        return CheckResult(
            "write keys",
            False,
            "; ".join(problems)
            + ": a write key belongs only to the writer's own credential (Q-A5); remove it",
        )
    if configured:
        return CheckResult("write keys", True, "configured, and in no shared place")
    return CheckResult("write keys", True, "none anywhere (writes are off, D-109)")


async def tunnel_result(
    cert: Path, port: int = LOCAL_LLM_PORT, host: str = "127.0.0.1", wait_s: float = 3.0
) -> CheckResult:
    """The local model's tunnel: up, and serving the certificate the import stored."""
    stored = _stored_fingerprint(cert)
    if stored is None:
        return CheckResult("local model tunnel", True, "the local model is not set up (D-108)")
    if isinstance(stored, ValueError):
        return CheckResult("local model tunnel", False, str(stored))
    expected = stored
    der = await certs.served_cert(host, port, wait_s)
    if der is None:
        return CheckResult(
            "local model tunnel",
            True,
            f"down: nothing answers on {host}:{port} (the model machine is off, or its tunnel is"
            " not up); ARGUS uses the free providers meanwhile",
            warn=True,
        )
    served = certs.fingerprint(der)
    if served != expected:
        return CheckResult(
            "local model tunnel",
            False,
            f"{host}:{port} serves another certificate ({served[:16]}..., stored"
            f" {expected[:16]}...): a newer hand-over not imported, or not the model machine",
        )
    return CheckResult("local model tunnel", True, f"up on {host}:{port}, the stored certificate")


def _stored_fingerprint(cert: Path) -> str | ValueError | None:
    """The stored certificate's fingerprint; None if there is none; the error if unreadable."""
    if not cert.is_file():
        return None
    try:
        return certs.read_cert(cert).sha256
    except ValueError as exc:
        return exc


def unit_results(
    repo_dir: Path = UNITS_DIR,
    installed_dir: Path | None = None,
    other_dirs: Sequence[Path] | None = None,
    moved: frozenset[str] | set[str] = frozenset(),
    params: units.UnitParams | None = None,
    run: Sequence[str] | None = None,
) -> list[CheckResult]:
    """The installed units against their templates rendered with ``params`` (this installation's;
    by default this checkout's), their roles for an installation that runs ``run``, and every
    drop-in that changes one (in the unit directory and ``other_dirs``: by default systemd's other
    folders when the unit directory is the user's own, none for a folder given). Units installed
    for another checkout (a worktree beside production) are named, not compared: they are that
    checkout's to check."""
    if other_dirs is None:
        other_dirs = units.control_dirs() if installed_dir is None else ()
    installed = units.user_unit_dir() if installed_dir is None else installed_dir
    changed = units.drop_ins([installed, *other_dirs])
    flagged = [
        CheckResult(
            f"unit {drop.applies_to}",
            False,
            f"a drop-in changes it: {drop.path} (deploy/systemd holds whole units only; remove"
            f" the drop-in, or change the template in deploy/systemd and {units.INSTALL})",
        )
        for drop in changed
    ]
    if params is not None:
        elsewhere = units.installed_root(installed)
        if elsewhere is not None and elsewhere.resolve() != params.root.resolve():
            summary = (
                f"installed for another checkout ({elsewhere}), not this one ({params.root}):"
                " not compared here (units.root names the checkout the units run)"
            )
            return [
                CheckResult("service units", not flagged, summary, warn=not flagged),
                *flagged,
            ]
    states, unlisted, stray = units.unit_states(repo_dir, installed_dir, moved, params, run)
    running = sum(
        1
        for s in states
        if s.role is units.Role.RUN
        and s.identical
        and s.enabled
        and not any(d.changes(s.name) for d in changed)
    )
    # A new installation whose services were installed but not started yet (`argus init`
    # without --start) is waiting for a person, not broken: once one runs, the rest must too.
    waiting = not any(s.enabled for s in states if s.role is units.Role.RUN)
    for state in states:
        found = units.problems(state)
        if found is not None:
            detail, warning = found
            if waiting and found == units.NOT_ENABLED:
                detail, warning = "installed, not started yet (`argus init --start`)", True
            flagged.append(CheckResult(f"unit {state.name}", warning, detail, warn=warning))
    for name in unlisted:
        flagged.append(
            CheckResult(f"unit {name}", False, "in deploy/systemd but not in the unit manifest")
        )
    for name in stray:
        flagged.append(
            CheckResult(f"unit {name}", True, "installed, but not in the repository", warn=True)
        )
    chosen = sum(1 for s in states if s.role is units.Role.RUN)
    summary = (
        f"{len(states)} in deploy/systemd; {running} of the {chosen} this installation runs"
        " running as installed and byte-identical to their rendered templates"
    )
    if chosen == 0:
        summary += "; none runs yet (units.run is empty: `argus init --start` starts them)"
    elif waiting:
        summary += "; none started yet: `argus init --start` starts them"
    ok = not any(not r.ok for r in flagged)
    results = [CheckResult("service units", ok, summary, warn=ok and waiting and chosen > 0)]
    return results + flagged


# What a running service holds in memory is the code it started with, but it re-reads files from
# the tree it runs from (the web re-reads the built page and the templates, a late import takes
# the new module, a new ``argus.yaml`` is read by any ``load_settings``): a checkout that changed
# under a running service is a mixed old/new process until it restarts.
CODE_ROOTS = ("src/argus", "config")
_NOT_CODE = {"__pycache__", ".pytest_cache", ".mypy_cache"}


def code_changed_at(repo: Path = REPO, roots: Sequence[str] = CODE_ROOTS) -> datetime | None:
    """When the newest file of the tree the services run from was written (checkout, merge or
    edit); None when none can be read."""
    newest = 0.0
    stack = [repo / root for root in roots]
    while stack:
        folder = stack.pop()
        try:
            entries = list(os.scandir(folder))
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    if entry.name not in _NOT_CODE:
                        stack.append(Path(entry.path))
                elif entry.is_file(follow_symlinks=False):
                    newest = max(newest, entry.stat(follow_symlinks=False).st_mtime)
            except OSError:
                continue
    return datetime.fromtimestamp(newest, UTC) if newest else None


def service_start_times(
    names: Sequence[str],
    run: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> Mapping[str, datetime] | str:
    """When each of the user units in ``names`` that is active entered that state (a restart
    moves it), from ``systemctl --user show``; a text saying why it could not be asked."""
    try:
        done = (run or subprocess.run)(
            ["systemctl", "--user", "show", *names, "--timestamp=unix",
             "--property=Id,ActiveState,ActiveEnterTimestamp"],
            capture_output=True, text=True, timeout=10, check=False,
        )  # fmt: skip
    except (OSError, subprocess.SubprocessError) as exc:
        return f"systemctl could not be run ({type(exc).__name__})"
    if done.returncode != 0:
        return "the user service manager did not answer"
    started: dict[str, datetime] = {}
    for block in done.stdout.strip().split("\n\n"):
        fields = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
        stamp = fields.get("ActiveEnterTimestamp", "")
        if fields.get("ActiveState") == "active" and stamp.startswith("@") and "Id" in fields:
            try:
                started[fields["Id"]] = datetime.fromtimestamp(int(stamp[1:]), UTC)
            except (ValueError, OverflowError, OSError):
                continue
    return started


def deployed_code_result(
    started: Mapping[str, datetime] | str, changed: datetime | None
) -> CheckResult:
    """A warning for each service that started before the tree it runs from last changed: restart
    it (deploy order: restart the services, then ``argus db upgrade``)."""
    name = "services run the deployed code"
    if isinstance(started, str):
        return CheckResult(name, True, f"not checked: {started}")
    if changed is None:
        return CheckResult(name, True, "not checked: the code tree could not be read")
    if not started:
        return CheckResult(name, True, "no ARGUS service is running under this user")
    from argus import site

    def shown(moment: datetime) -> str:
        local = moment.astimezone(site.zone())
        return f"{local:%Y-%m-%d %H:%M} {site.zone_label(local)}"

    stale = sorted(unit for unit, at in started.items() if at < changed)
    if stale:
        who = ", ".join(f"{u.removesuffix('.service')} (since {shown(started[u])})" for u in stale)
        return CheckResult(
            name,
            True,
            f"the code changed at {shown(changed)}, after {who} started: they hold the old"
            " modules but read the new files; restart them (`systemctl --user restart`),"
            " then `argus db upgrade`",
            warn=True,
        )
    return CheckResult(
        name, True, f"{len(started)} running services started after the code last changed"
    )


def backup_results(base: Path, now: datetime) -> list[CheckResult]:
    found = backup.status(base)
    nightly, drill = found.newest_nightly, found.last_drill
    if found.newest_any is None:
        return [
            CheckResult(
                "backups",
                True,
                f"no dump in {base} yet: the nightly dump starts when argus-backup.timer is"
                " enabled (a production step)",
                warn=True,
            )
        ]
    results = []
    if nightly is None:
        newest = found.newest_any
        results.append(
            CheckResult(
                "backups",
                True,
                f"no nightly dump yet (newest: {newest.kind}, {newest.created_at:%Y-%m-%d %H:%M}"
                " UTC): enable argus-backup.timer (a production step)",
                warn=True,
            )
        )
    elif now - nightly.created_at > backup.NIGHTLY_STALE:
        hours = int((now - nightly.created_at).total_seconds() // 3600)
        results.append(
            CheckResult(
                "backups",
                False,
                f"the newest nightly dump is {hours} h old ({nightly.created_at:%Y-%m-%d %H:%M}"
                " UTC): argus-backup.service did not run or failed",
            )
        )
    else:
        results.append(
            CheckResult(
                "backups",
                True,
                f"nightly dump {nightly.created_at:%Y-%m-%d %H:%M} UTC, revision"
                f" {nightly.revision or 'none'}, {len(nightly.fingerprints.tables)} tables",
            )
        )
    if drill is None:
        results.append(
            CheckResult(
                "restore drill",
                True,
                "never run: argus-backup-drill.timer (weekly) or `argus backup drill`",
                warn=True,
            )
        )
        return results
    at = _parse(drill.get("at"))
    if drill.get("passed") is not True:
        results.append(
            CheckResult(
                "restore drill",
                False,
                f"the last drill ({drill.get('at', '?')}) found the restore DIFFERENT from the"
                f" dump {drill.get('dump', '?')}: `argus backup list`, then a new dump and drill",
            )
        )
    elif at is None or now - at > backup.DRILL_STALE:
        results.append(
            CheckResult(
                "restore drill",
                True,
                f"the last drill passed, but it is from {drill.get('at', '?')}: weekly is due",
                warn=True,
            )
        )
    else:
        results.append(
            CheckResult(
                "restore drill", True, f"{at:%Y-%m-%d %H:%M} UTC: {drill.get('dump')} identical"
            )
        )
    return results


def _parse(value: object) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def toolchain_result(directory: Path | None = None) -> CheckResult:
    chain = frontend.toolchain(directory)
    where = directory or frontend.node_dir()
    if chain.node is None:
        return CheckResult(
            "node toolchain",
            True,
            f"{chain.problem}: the frontend cannot be built on this machine",
            warn=True,
        )
    if chain.problem is not None:
        return CheckResult("node toolchain", False, chain.problem)
    return CheckResult("node toolchain", True, f"Node {chain.node}, npm {chain.npm} ({where})")


def build_result(frontend_dir: Path, build_dir: Path) -> CheckResult:
    """Whether the committed build is the build of the current ``frontend/``."""
    if not (frontend_dir / "package.json").is_file():
        return CheckResult("frontend build", True, "no frontend yet (Q-B1)")
    made = frontend.read_manifest(build_dir)
    if made is None:
        return CheckResult(
            "frontend build",
            False,
            f"no build in {build_dir}: run scripts/frontend_gate.sh and commit the build (DQ25)",
        )
    now = frontend.sources_sha256(frontend_dir)
    if made["sources_sha256"] != now:
        return CheckResult(
            "frontend build",
            False,
            f"stale: built from sources {made['sources_sha256'][:12]}, frontend/ is now"
            f" {now[:12]}: rebuild (scripts/frontend_gate.sh) and commit it",
        )
    return CheckResult(
        "frontend build",
        True,
        f"built {str(made.get('built_at', '?'))[:16]} with Node {made.get('node', '?')} from the"
        " current sources",
    )


def served_result(served: Path, package: Path) -> CheckResult:
    """Whether /app has a page to serve from ``served`` (``web.spa_dir``, else the package's
    build): an index.html that names its build, and, for another folder (a deploy copy), the
    package's build copied whole: the same manifest."""
    index = spa.Build(served).index()
    if index is None:
        return CheckResult(
            "frontend served", False, f"no index.html in {served}: /app answers 503 (web.spa_dir)"
        )
    if index.build is None:
        return CheckResult("frontend served", False, f"index.html in {served} names no build")
    if served.resolve() != package.resolve():
        copied = frontend.read_manifest(served)
        if copied is None or copied != frontend.read_manifest(package):
            return CheckResult(
                "frontend served",
                False,
                f"{served} is not a copy of the package's build: copy it again (web.spa_dir)",
            )
    return CheckResult("frontend served", True, f"/app serves build {index.build} from {served}")


async def stored_results(settings: Settings, now: datetime) -> list[CheckResult]:
    """The threat-intel sources' freshness and the probe readings, read as the runtime role."""
    try:
        engine = create_engine(settings.database)
    except ConfigError as exc:
        return [CheckResult("threat intel", False, f"not checked: {exc}")]
    try:
        async with engine.connect() as conn:
            fresh = await reference_store.freshness(conn)
            probes = (
                await conn.execute(
                    text("SELECT count(*) FILTER (WHERE at > :day), max(at) FROM siem_probes"),
                    {"day": now - timedelta(days=1)},
                )
            ).one()
    except DB_ERRORS as exc:
        return [CheckResult("threat intel", False, f"not checked: {short_db_error(exc)}")]
    finally:
        await engine.dispose()
    results = []
    if not fresh:
        results.append(
            CheckResult("threat intel", True, "no source in site.ti_sources: threat intel is off")
        )
    for source in fresh:
        name = f"threat intel {source.source}"
        if source.newest is None:
            results.append(
                CheckResult(
                    name, True, "never synced: its 'no match' answers are unknown", warn=True
                )
            )
        elif source.stale(now):
            days = (now - source.newest).days
            results.append(
                CheckResult(
                    name,
                    True,
                    f"stale: the newest indicator is {days} days old ({source.newest:%Y-%m-%d});"
                    " its 'no match' answers are unknown until it is synced (plan §13)",
                    warn=True,
                )
            )
        else:
            results.append(
                CheckResult(name, True, f"fresh: newest indicator {source.newest:%Y-%m-%d %H:%M}")
            )
    day, newest = int(probes[0] or 0), probes[1]
    keyed = settings.siem.api_key is not None and bool(settings.siem.api_key.get_secret_value())
    if newest is None:
        results.append(
            CheckResult(
                "probe readings",
                True,
                "none stored yet" + ("" if keyed else " (no SIEM key here)"),
                warn=keyed,
            )
        )
    elif keyed and now - newest > PROBES_STALE:
        results.append(
            CheckResult(
                "probe readings",
                True,
                f"the newest is from {newest:%Y-%m-%d %H:%M} UTC: is the collector running?",
                warn=True,
            )
        )
    else:
        results.append(
            CheckResult(
                "probe readings",
                True,
                f"{day} in the last 24 h, newest {newest:%Y-%m-%d %H:%M} UTC (kept for Q-A3)",
            )
        )
    return results


def shared_result(path: Path | None = None) -> CheckResult:
    """The shared-infrastructure list loads (a missing, invalid or empty list would switch
    the content-delivery and cloud rule off)."""
    from argus.cases import membership

    name = "shared infrastructure"
    path = membership.SHARED_PATH if path is None else path
    try:
        loaded = membership.load_shared(path)
    except ConfigError as exc:
        return CheckResult(name, False, str(exc)[:300])
    return CheckResult(
        name, True, f"{len(loaded.networks)} networks, {len(loaded.domains)} domain suffixes"
    )


async def watch_results(settings: Settings, now: datetime) -> list[CheckResult]:
    """The still-active watch ran lately. Off is a state; otherwise its audit row
    (``watch.run``) must be less than 36 hours old, else the daily run is not happening and
    "not checked within 24 hours" depends on a run that does not take place."""
    from argus.cases import watch, watchrun

    name = "still-active watch"
    if settings.cases.watch == "off":
        return [CheckResult(name, True, "off (cases.watch)")]
    try:
        engine = create_engine(settings.database)
    except ConfigError as exc:
        return [CheckResult(name, False, f"not checked: {exc}")]
    try:
        async with engine.connect() as conn:
            last = await watchrun.last_run(conn)
    except DB_ERRORS as exc:
        return [CheckResult(name, False, f"not checked: {short_db_error(exc)}")]
    finally:
        await engine.dispose()
    words = watch.last_run_words(last, now)
    late = last is None or now - last > watch.RUN_LATE
    detail = f"cases.watch is {settings.cases.watch}; {words}"
    if late:
        detail += ": schedule `argus case watch run` once a day (docs/runbooks/case-watch.md)"
    return [CheckResult(name, True, detail, warn=late)]


async def notices_results(settings: Settings, now: datetime) -> list[CheckResult]:
    """Notices are off (a state, by choice), or switched on with a coherent relay
    and at least one recipient, and a pass has run in the last hour. WARN when switched on with
    no recipient (nothing is sent), links that point to the loopback, or sends that failed;
    FAIL when switched on with an incomplete relay."""
    from argus.notices import run as notices_run

    name = "notices"
    n = settings.notices
    if not n.enabled:
        detail = "off (notices.enabled): nothing is e-mailed, by your choice"
        if n.password is not None and n.user is None:
            return [
                CheckResult(
                    name, True, detail + "; a relay password is set without a user", warn=True
                )
            ]
        return [CheckResult(name, True, detail)]
    cfg = notices_run.config_of(settings)
    if cfg.relay is None or cfg.sender is None:
        return [
            CheckResult(
                name,
                False,
                "switched on, but the relay is incomplete (notices.relay_host, notices.relay_from)",
            )
        ]
    if not cfg.recipients:
        return [
            CheckResult(
                name,
                True,
                "switched on, but no recipient is named (notices.recipients): nothing is sent",
                warn=True,
            )
        ]
    login = "with a login" if n.user is not None else "without a login"
    tls = "STARTTLS" if n.relay_starttls else "no TLS"
    detail = (
        f"on: {len(cfg.recipients)} recipient(s) through {n.relay_host}:{n.relay_port}"
        f" ({tls}, {login})"
    )
    warn = False
    if n.password is not None and n.user is None:
        detail += "; a relay password is set without a user"
        warn = True
    if settings.cases.watch == "off":
        detail += (
            "; the still-active watch is off (cases.watch): a case that keeps beaconing is told"
            " only when an investigation joins it"
        )
        warn = True
    from urllib.parse import urlsplit

    if urlsplit(cfg.base).hostname in ("127.0.0.1", "localhost"):
        detail += f"; links point to {cfg.base}: set notices.web_url or web.public_url"
        warn = True
    try:
        engine = create_engine(settings.database)
    except ConfigError as exc:
        return [CheckResult(name, False, f"not checked: {exc}")]
    try:
        async with engine.connect() as conn:
            last = await notices_run.last_run(conn)
            failed = await notices_run.failures_last_hour(conn, now)
    except DB_ERRORS as exc:
        return [CheckResult(name, False, f"not checked: {short_db_error(exc)}")]
    finally:
        await engine.dispose()
    if last is None or now - last > NOTICES_LATE:
        detail += "; no pass in the last hour: is argus-notices.timer enabled?"
        warn = True
    if failed:
        detail += f"; the relay failed {failed} message(s) in the last hour"
        warn = True
    return [CheckResult(name, True, detail, warn=warn)]


# Each registered on its own: a check that breaks shows as one crashed line, never hiding the
# others.


@register_check
async def web_certificate_check(settings: Settings) -> list[CheckResult]:
    return await web_certificate_checks(settings, _now())


@register_check
async def local_model_check(settings: Settings) -> list[CheckResult]:
    cert = REPO / LOCAL_LLM_CERT
    results = []
    if cert.is_file():
        renew = "a new hand-over (D-108)"
        results.append(certificate_result("local model certificate", cert, _now(), renew))
    results.append(await tunnel_result(cert))
    return results


@register_check
async def key_check(settings: Settings) -> list[CheckResult]:
    return key_expiry_results(settings, _now())


@register_check
async def write_key_check(settings: Settings) -> list[CheckResult]:
    configured = False
    for setting in WRITE_KEYS:
        section, _, field = setting.partition(".")
        value = getattr(getattr(settings, section), field)
        configured |= value is not None and bool(value.get_secret_value())
    problems = write_key_problems(
        settings,
        env_file=settings.env_file or Path(".env"),
        config_file=_config_file(settings),
        unit_dirs=(UNITS_DIR, units.user_unit_dir(), *units.control_dirs()),
    )
    return [write_key_result(problems, configured)]


@register_check
async def unit_check(settings: Settings) -> list[CheckResult]:
    return unit_results(
        moved=custody.moved_units(), params=_unit_params(settings), run=settings.units.run
    )


@register_check
async def deployed_code_check(settings: Settings) -> list[CheckResult]:
    import asyncio

    running = [
        name for name, (role, _) in units.roles_for(settings.units.run).items()
        if role is units.Role.RUN and name.endswith(".service")
    ]  # fmt: skip
    started = await asyncio.to_thread(service_start_times, running)
    changed = await asyncio.to_thread(code_changed_at)
    return [deployed_code_result(started, changed)]


@register_check
async def custody_check(settings: Settings) -> list[CheckResult]:
    enabled = units.enabled_units(units.user_unit_dir())
    return custody.custody_results(settings, user_units=enabled)


@register_check
async def backup_check(settings: Settings) -> list[CheckResult]:
    return backup_results(settings.backup.dir, _now())


@register_check
async def frontend_check(settings: Settings) -> list[CheckResult]:
    served = settings.web.spa_dir if settings.web.spa_dir is not None else frontend.BUILD_DIR
    return [
        toolchain_result(),
        build_result(frontend.FRONTEND_DIR, frontend.BUILD_DIR),
        served_result(served, frontend.BUILD_DIR),
    ]


@register_check
async def stored_check(settings: Settings) -> list[CheckResult]:
    return await stored_results(settings, _now())


@register_check
async def watch_check(settings: Settings) -> list[CheckResult]:
    return [shared_result(), *await watch_results(settings, _now())]


@register_check
async def notices_check(settings: Settings) -> list[CheckResult]:
    return await notices_results(settings, _now())


def _yaml_files(config_file: Path | None) -> list[Path]:
    """The config file and the YAML files read beside it (local.yaml, site.yaml)."""
    if config_file is None:
        return []
    from argus.config.settings import LOCAL_FILE, SITE_FILE

    beside = [config_file.parent / name for name in (LOCAL_FILE, SITE_FILE)]
    return [config_file, *(path for path in beside if path != config_file and path.is_file())]


def _config_file(settings: Settings) -> Path | None:
    """The YAML file these settings were loaded from (``argus doctor --config``), or the one
    load_settings would read when they were built otherwise."""
    from argus.config.settings import resolve_config_path

    path = settings.config_file or resolve_config_path(None)
    return path if path.is_file() else None
