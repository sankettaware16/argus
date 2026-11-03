"""Credential custody (Q-A5, plan §7.9): ARGUS's services as their own system users, each
with only its own secrets, from root-owned files by ``LoadCredential=``.

The layout ``deploy/custody/install.sh`` makes (as root; it is the user's production step):

* system users ``argus-svc`` (collector, worker, assessments, soak samples, Kibana read-back),
  ``argus-web`` and ``argus-writer``, each in its own group and in the group ``argus``;
* ``/etc/argus/credentials/<name>``: one root-owned file (mode 0600) per secret, in a folder
  anyone may list (names are public, contents are not). No service can read one: systemd reads
  each as root and gives a unit only the ones its ``LoadCredential=`` lines name, in
  ``$CREDENTIALS_DIRECTORY``, readable by that unit's user alone;
* ``/etc/argus/argus.env``: the non-secret settings the shared ``.env`` held (root:argus 0640);
  the SIEM CA, the web's certificate and the asset map beside it. Like the credentials, once
  there they are not replaced from the checkout without a review: they decide where each service
  connects and which CA it trusts, and any process of the operator's account can change the
  checkout (review F2);
* ``/opt/argus/releases/<tag>-<commit>``: a read-only copy of an approved tag (root-owned, no
  write bit anywhere) with its own virtualenv; ``/opt/argus/current`` points at one;
* system units from ``deploy/custody/units`` and ``/usr/local/sbin/argus-owner``, the root
  wrapper for the owner's commands (and for commands run inside a service's account).

This module holds that layout (the script, the units and the tests are checked against it),
the import the script runs (``python -m argus.ops.custody import``) and ``argus doctor``'s
custody check. Nothing here prints a secret: only names, places and modes.
"""

from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
import pwd
import stat
import sys
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from argus.config.errors import ConfigError
from argus.config.settings import CUSTODY_SECRETS, CustodyRole, Settings, secret_settings
from argus.config.sources import CREDENTIAL_SETTING, dotenv_layer
from argus.doctor import CheckResult
from argus.ops.units import REPO, Role

ETC = Path("/etc/argus")
CREDENTIALS = ETC / "credentials"
ENV_FILE = ETC / "argus.env"
MARKER = ETC / "custody.json"
OPT = Path("/opt/argus")
RELEASES = OPT / "releases"
CURRENT = OPT / "current"
BACKUPS = Path("/var/lib/argus-backups")
SYSTEM_UNITS = Path("/etc/systemd/system")
OWNER_WRAPPER = Path("/usr/local/sbin/argus-owner")
SOURCE_UNITS = REPO / "deploy" / "custody" / "units"
GROUP = "argus"
# Groups whose members can read any root-owned file (a container or a VM with the host's
# disk mounted): an operator account in one holds every credential anyway.
ROOT_EQUIVALENT_GROUPS = ("docker", "libvirt", "lxd", "incus-admin", "disk")


@dataclass(frozen=True)
class Account:
    role: CustodyRole
    user: str  # root for the owner: its commands need docker for the backups
    credentials: tuple[str, ...]  # what its units load, in this order
    optional: tuple[str, ...] = ()
    """Loaded by ``argus-owner`` only when present. A unit file loads none of them (a missing
    file fails ``LoadCredential=`` and the unit with it): the unit of the step that uses a key
    names it once it exists."""


# the case team's six users' keys (AR8, D-159), the writer's alone
TEAM_KEYS = tuple(
    f"case_team.{user}_api_key"
    for user in ("lead", "evidence", "intel", "responder", "hunter", "reporter")
)
# the seventh user's key (AR10, D-250) is optional for the case team itself (its step is skipped
# without it), so no unit file names it until the key exists (a missing LoadCredential= file fails
# the unit); the writer's account loads it when present
OPTIONAL_TEAM_KEYS = ("case_team.visualiser_api_key",)

ACCOUNTS: dict[str, Account] = {
    # the notices' relay password (Q-H4) is optional: a campus relay may need no login, and a
    # unit names it only at the production step that gives it one
    # the outside threat-intel keys (AR3, D-165) are optional too: a source without a key is
    # off, and a unit names a key only at the production step that gives it one
    "svc": Account(
        "svc",
        "argus-svc",
        (
            "database.password",
            "siem.api_key",
            "llm-api-keys.env",
            "notices.password",
            "outside.virustotal_api_key",
            "outside.shodan_api_key",
            "outside.censys_api_key",
        ),
        optional=(
            "notices.password",
            "outside.virustotal_api_key",
            "outside.shodan_api_key",
            "outside.censys_api_key",
        ),
    ),
    "web": Account("web", "argus-web", ("database.api_password", "web-tls.key")),
    # the Kibana keys (Q-D2) are made at their own production steps: the writer is off until
    # its canary, and the svc units get the Kibana reader key at Q-D3's first live read
    "writer": Account(
        "writer",
        "argus-writer",
        (
            "database.writer_password",
            "approval-signing.key",
            "siem.api_key",
            "siem.writer_api_key",
            "kibana.reader_api_key",
            "kibana.cases_writer_api_key",
            "kibana.alert_writer_api_key",
            *TEAM_KEYS,
            *OPTIONAL_TEAM_KEYS,
        ),
        # minted at later canaries (R17's write-back, Q-D5's alert writer): the cases canary
        # and the cases schedule start without them (Q-D4 review: the unit would not start).
        # The case team's six keys (AR8, D-159) wait for its own canary the same way.
        optional=(
            "siem.writer_api_key",
            "kibana.alert_writer_api_key",
            *TEAM_KEYS,
            *OPTIONAL_TEAM_KEYS,
        ),
    ),
    "owner": Account(
        "owner",
        "root",
        (
            "database.owner_password",
            "database.password",
            "database.api_password",
            "database.writer_password",
            "siem.api_key",
            "kibana.reader_api_key",
        ),
        optional=(
            "database.api_password",
            "database.writer_password",
            "siem.api_key",
            "kibana.reader_api_key",
        ),
    ),
}
SERVICE_USERS = tuple(a.user for a in ACCOUNTS.values() if a.user != "root")

# Credentials that are files a setting (or the LLM gateway) names by path, and where the
# import takes them from in the operator's checkout. An absent LLM keys file becomes an empty
# credential (no provider has a key), so the svc units still start.
FILE_CREDENTIALS: dict[str, Path] = {
    "llm-api-keys.env": Path("reference/llm_api_keys.env"),
    "web-tls.key": Path("data/tls/argus.key"),
    # the approval signing key (Q-C3, `argus approvals keygen`): normally made in place at the
    # first closure; copied from the checkout only when a development key is there
    "approval-signing.key": Path("data/approval-signing.key"),
}
EMPTY_ALLOWED = frozenset({"llm-api-keys.env"})
# Needed before the switch-over; the writer key only at its canary (D-109).
REQUIRED = frozenset(
    {
        "database.password",
        "database.owner_password",
        "database.api_password",
        "siem.api_key",
        "web-tls.key",
        "llm-api-keys.env",
    }
)

# Public or private-but-not-secret files the services read, copied from the checkout.
DATA_FILES: dict[str, tuple[Path, int, bool]] = {
    # destination under /etc/argus: (source in the checkout, mode, group argus)
    "certs/siem-ca.crt": (Path("data/certs/siem-ca.crt"), 0o644, False),
    "tls/argus.crt": (Path("data/tls/argus.crt"), 0o644, False),
    "tls/local-llm.crt": (Path("data/tls/local-llm.crt"), 0o644, False),
    "data/asset_map.yaml": (Path("data/assets/asset_map.yaml"), 0o640, True),
}
# Settings argus.env always sets: the custody paths, whatever the shared .env said.
CUSTODY_ENV: dict[str, str] = {
    "ARGUS_SIEM__CA_FILE": str(ETC / "certs" / "siem-ca.crt"),
    "ARGUS_ASSETS__MAP_PATH": str(ETC / "data" / "asset_map.yaml"),
    "ARGUS_BACKUP__DIR": str(BACKUPS),
}

# Settings each unit sets itself (Environment=): argus.env never carries them, since systemd
# lets an EnvironmentFile= override Environment= (a test keeps this equal to the units).
UNIT_SET = frozenset(
    {
        "ARGUS_CUSTODY__ROLE",
        "ARGUS_WEB__HOST",
        "ARGUS_WEB__TLS_CERT",
        "ARGUS_WEB__TLS_KEY",
        "ARGUS_WEB__DATABASE_ROLE",
        "ARGUS_WEB__PUBLIC_URL",
        "ARGUS_WEB__APPROVAL_KEY_FILE",
        "ARGUS_SOAK__DIR",
    }
)

# The system units and the account each service runs as (timers run none); roles as in
# argus.ops.units.MANIFEST, for the system manager.
UNITS: dict[str, tuple[str | None, Role]] = {
    "argus-collector.service": ("svc", Role.RUN),
    "argus-worker.service": ("svc", Role.RUN),
    "argus-assess.service": ("svc", Role.RUN),
    "argus-soak-sample.service": ("svc", Role.TRIGGERED),
    "argus-soak-sample.timer": (None, Role.RUN),
    "argus-kibana-sync.service": ("svc", Role.RUN),
    "argus-case-team.service": ("writer", Role.TRIGGERED),
    "argus-case-team.timer": (None, Role.RUN),
    "argus-web.service": ("web", Role.RUN),
    "argus-writer.service": ("writer", Role.OFF),
    "argus-backup.service": ("owner", Role.TRIGGERED),
    "argus-backup.timer": (None, Role.SOON),
    "argus-backup-drill.service": ("owner", Role.TRIGGERED),
    "argus-backup-drill.timer": (None, Role.SOON),
    "argus-purge.service": ("owner", Role.TRIGGERED),
    "argus-purge.timer": (None, Role.OFF),
    "argus-notices.service": ("svc", Role.TRIGGERED),
    "argus-notices.timer": (None, Role.OFF),
    "argus-report-daily.service": ("svc", Role.TRIGGERED),
    "argus-report-daily.timer": (None, Role.OFF),
    "argus-report-weekly.service": ("svc", Role.TRIGGERED),
    "argus-report-weekly.timer": (None, Role.OFF),
    "argus-soak-phase3.service": ("svc", Role.TRIGGERED),
    "argus-soak-phase3.timer": (None, Role.OFF),
}


# Credentials one unit loads besides its account's (Q-D3): the Kibana read-back alone of the
# svc units gets the Kibana reader key, so the collector's units never depend on a key that is
# made only at its production step (Q-D2's open risk) and never hold it.
UNIT_EXTRA_CREDENTIALS: dict[str, tuple[str, ...]] = {
    "argus-kibana-sync.service": ("kibana.reader_api_key",),
}


# A unit that loads a different set of its account's credentials (D-214): the case team needs
# the six team keys (optional for the writer until AR8's canary) and not the cases writer key.
UNIT_CREDENTIALS: dict[str, tuple[str, ...]] = {
    "argus-case-team.service": (
        "database.writer_password",
        "approval-signing.key",
        "siem.api_key",
        "kibana.reader_api_key",
        *TEAM_KEYS,
    ),
}


def unit_credentials(unit: str) -> tuple[str, ...]:
    """What a unit file loads, in order: its own list (``UNIT_CREDENTIALS``), else its account's
    credentials but the optional ones, then its own extras."""
    if unit in UNIT_CREDENTIALS:
        return UNIT_CREDENTIALS[unit]
    role = UNITS[unit][0]
    own = () if role is None else _required(ACCOUNTS[role])
    return (*own, *UNIT_EXTRA_CREDENTIALS.get(unit, ()))


def _required(account: Account) -> tuple[str, ...]:
    """The account's credentials a unit cannot start without."""
    return tuple(name for name in account.credentials if name not in account.optional)


def all_credentials() -> list[str]:
    """Every credential name, each once, in account order."""
    names: list[str] = []
    for account in ACCOUNTS.values():
        names += [name for name in account.credentials if name not in names]
    return names


def holders(name: str) -> list[str]:
    return [role for role, account in ACCOUNTS.items() if name in account.credentials]


# --------------------------------------------------------------------------- the import


@dataclass
class Report:
    lines: list[str] = field(default_factory=list)
    pending: int = 0  # changes a run would make (or made), and differences kept
    missing: list[str] = field(default_factory=list)  # required, and nowhere to take it from
    kept: list[str] = field(default_factory=list)  # argus.env and files kept over the checkout's
    # (destination, installed bytes, the checkout's bytes) of each difference shown
    proposals: list[tuple[str, bytes, bytes]] = field(default_factory=list)

    def add(self, line: str, *, change: bool = False) -> None:
        self.lines.append(line)
        self.pending += change

    def digest(self) -> str | None:
        """What --accept-settings must name to take exactly the differences shown: any change
        to either side (installed or the checkout's) gives another digest."""
        if not self.proposals:
            return None
        hashed = hashlib.sha256()
        for name, have, new in sorted(self.proposals):
            hashed.update(name.encode() + b"\0")
            hashed.update(hashlib.sha256(have).digest() + hashlib.sha256(new).digest())
        return hashed.hexdigest()[:16]


def _write(path: Path, data: bytes, mode: int) -> None:
    """``path`` replaced at once by a file holding ``data`` with ``mode`` (never another). A
    missing folder is made writable by its owner alone, whatever the umask (install.sh makes
    them first, each with its own mode)."""
    missing, folder = [], path.parent
    while not folder.exists():
        missing.append(folder)
        folder = folder.parent
    for folder in reversed(missing):
        folder.mkdir(mode=0o755)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise


def _read(path: Path) -> bytes | None:
    """A regular file's bytes (a symlink is not followed), or None when there is none."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError(f"{path} is not a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            return handle.read()
    finally:
        os.close(descriptor)


class SourceError(Exception):
    """A file of the checkout the import refuses to read (it runs as root)."""


def _source(checkout: Path, relative: Path) -> bytes | None:
    """A file of the operator's checkout, read as root: refused when it, or a folder on the way,
    leads out of the checkout (a planted link to a root-only file), or is not a regular file;
    None when there is none."""
    path = checkout / relative
    try:
        real = path.resolve(strict=True)
    except FileNotFoundError:
        return None
    except (OSError, RuntimeError) as exc:
        raise SourceError(f"{relative}: cannot be resolved ({exc})") from None
    if not real.is_relative_to(checkout.resolve()):
        raise SourceError(f"{relative} leads out of the checkout: not read")
    if path.is_symlink():
        raise SourceError(f"{relative} is a symbolic link: not read")
    try:
        return _read(path)
    except (OSError, ValueError) as exc:
        raise SourceError(f"{relative}: not read ({exc})") from None


def _quote(value: str) -> str | None:
    """``value`` as systemd's EnvironmentFile= reads it back unchanged (single quotes take
    everything literally), or None for one it cannot hold so (a quote or a line break)."""
    if "'" in value or any(ord(c) < 0x20 or c == "\x7f" for c in value):
        return None
    return f"'{value}'"


def _setting_text(value: object) -> str:
    return value if isinstance(value, str) else json.dumps(value)


def split_env(env_file: Path) -> tuple[dict[str, str], dict[str, str], list[str]]:
    """The shared ``.env`` read exactly as ARGUS reads it: its secrets by credential name, its
    other ARGUS settings as variables for argus.env, and the problems (names only). Raises
    ConfigError for a file ARGUS itself would refuse."""
    layer = dotenv_layer(env_file, Settings)
    if layer is None:
        return {}, {}, []
    secrets = set(secret_settings())
    found: dict[str, str] = {}
    plain: dict[str, str] = {}
    for section, values in layer.data.items():
        if not isinstance(values, dict):
            plain[f"ARGUS_{section.upper()}"] = _setting_text(values)
            continue
        for key, value in values.items():
            setting = f"{section}.{key}"
            if setting in secrets:
                text = value.get_secret_value() if hasattr(value, "get_secret_value") else value
                if text:
                    found[setting] = str(text)
            else:
                plain[f"ARGUS_{section.upper()}__{key.upper()}"] = _setting_text(value)
    return found, plain, list(layer.problems)


def env_file_text(plain: Mapping[str, str], report: Report) -> bytes:
    lines = [
        "# ARGUS settings for the custody layout (Q-A5): written by deploy/custody/install.sh",
        "# from the shared .env (its non-secret ARGUS_ settings) and the custody paths. No",
        "# secret here: each is a credential in /etc/argus/credentials.",
    ]
    values = {**plain, **CUSTODY_ENV}
    for name in sorted(values):
        if name.upper() in UNIT_SET:
            report.add(f"argus.env: {name} left out (the units set it)")
            continue
        quoted = _quote(values[name])
        if quoted is None:
            report.add(f"argus.env: {name} left out (a quote or a line break): set it by hand")
            continue
        lines.append(f"{name}={quoted}")
    return ("\n".join(lines) + "\n").encode()


def _printable(value: str) -> str:
    return "".join(c if c.isprintable() else f"\\x{ord(c):02x}" for c in value)


def _env_values(data: bytes) -> dict[str, str]:
    """argus.env's NAME=VALUE lines (the value as written, quotes included)."""
    values = {}
    for line in data.decode("utf-8", errors="replace").splitlines():
        name, sep, value = line.strip().partition("=")
        if sep and name and not name.startswith("#"):
            values[name.strip()] = value.strip()
    return values


def _shown(name: str, value: str) -> str:
    secrets = {f"ARGUS_{s.replace('.', '__').upper()}" for s in secret_settings()}
    return "(a secret: not shown)" if name.upper() in secrets else _printable(value)


def _env_changes(have: bytes, new: bytes) -> list[str]:
    old, now = _env_values(have), _env_values(new)
    lines = []
    for name in sorted(old.keys() | now.keys()):
        label = _printable(name)
        if name not in now:
            lines.append(f"argus.env: {label} removed (was {_shown(name, old[name])})")
        elif name not in old:
            lines.append(f"argus.env: {label} added {_shown(name, now[name])}")
        elif old[name] != now[name]:
            lines.append(
                f"argus.env: {label} {_shown(name, old[name])} -> {_shown(name, now[name])}"
            )
    return lines or ["argus.env: only its comments or layout differ"]


def _sha256(data: bytes) -> str:
    return f"sha256 {hashlib.sha256(data).hexdigest()}"


def _take_trusted(
    report: Report,
    etc: Path,
    items: Sequence[tuple[str, bytes, int]],
    *,
    check: bool,
    accept: str | None,
) -> None:
    """argus.env and the files the services trust: written when missing (shown: settings by
    name and value, files by sha256), a mode put back, and a difference from the installed one
    shown and kept unless ``accept`` is the digest of exactly the differences shown."""
    differing = []
    for destination, data, mode in items:
        target = etc / destination
        have = _read(target)
        if have == data:
            if stat.S_IMODE(target.stat().st_mode) == mode:
                report.add(f"{destination}: in place")
            else:
                if not check:
                    _write(target, data, mode)
                report.add(f"{destination}: mode {mode:04o} {'to put' if check else 'put'} back",
                           change=True)  # fmt: skip
        elif have is None:
            if destination == "argus.env":
                for name, value in _env_values(data).items():
                    report.add(f"argus.env: {name} = {_shown(name, value)}")
            if not check:
                _write(target, data, mode)
            verb = ("to write" if check else "written") if destination == "argus.env" else (
                "to copy" if check else "copied")  # fmt: skip
            sha = "" if destination == "argus.env" else f" ({_sha256(data)})"
            report.add(f"{destination}: {verb}{sha}", change=True)
        else:
            differing.append((destination, have, data, mode))
    if not differing:
        if accept is not None:
            report.add("--accept-settings: no difference to take")
        return
    differing.sort()
    report.proposals = [(name, have, new) for name, have, new, _ in differing]
    digest = report.digest()
    take = accept is not None and accept == digest
    for destination, have, new, mode in differing:
        if destination == "argus.env":
            for line in _env_changes(have, new):
                report.add(line)
        else:
            report.add(f"{destination}: installed {_sha256(have)}, the checkout's {_sha256(new)}")
        if take:
            if not check:
                _write(etc / destination, new, mode)
            report.add(f"{destination}: {'to replace' if check else 'replaced'} (accepted)",
                       change=True)  # fmt: skip
        else:
            report.kept.append(destination)
            report.add(f"{destination}: differs from the checkout's: kept", change=True)
    if not take:
        if accept is not None:
            report.add(
                f"--accept-settings {_printable(accept)}: nothing taken (the differences shown"
                f" have the digest {digest}: review them again)"
            )
        report.add(
            f"to take the checkout's {', '.join(report.kept)} after you reviewed the differences"
            f" above (they decide where the services connect and what they trust): run again"
            f" with --accept-settings {digest}"
        )


def import_checkout(checkout: Path, etc: Path, *, check: bool, accept: str | None = None) -> Report:
    """Take the shared layout's secrets and files from ``checkout`` into ``etc`` (the
    custody ``/etc/argus``, or a fake root's). A credential already there is never replaced (it
    is the one that counts once custody is installed: rotate it by hand); a missing one is
    created, mode 0600. argus.env and the data files are written when missing; a difference
    from the installed ones is shown and kept unless ``accept`` is its digest (review F2).
    ``check``: change nothing, say what a run would do. Ownership is the caller's (install.sh
    chowns)."""
    report = Report()
    try:
        _source(checkout, Path(".env"))  # its path checked as every other source's
        secrets, plain, problems = split_env(checkout / ".env")
    except (ConfigError, SourceError) as exc:
        report.add(f".env: not read ({exc}); fix it, then run again")
        report.missing.append(".env")
        return report
    for problem in problems:
        report.add(f".env: {problem}")
    sources: dict[str, bytes | None] = {n: s.encode() for n, s in secrets.items()}
    for name, relative in FILE_CREDENTIALS.items():
        try:
            sources[name] = _source(checkout, relative)
        except SourceError as exc:
            report.add(f"credential {name}: {exc}")
            sources[name] = None
            continue
        if sources[name] is None and name in EMPTY_ALLOWED:
            sources[name] = b""
    folder = etc / "credentials"
    for name in all_credentials():
        target = folder / name
        have, new = _read(target), sources.get(name)
        if have is not None:
            if new is not None and have != new:
                report.add(
                    f"credential {name}: kept (it differs from the checkout's; the credential"
                    " counts now: replace it by hand to rotate)"
                )
            else:
                report.add(f"credential {name}: in place")
        elif new is not None:
            if not check:
                _write(target, new, 0o600)
            report.add(f"credential {name}: {'to create' if check else 'created'}", change=True)
        elif name in REQUIRED:
            report.missing.append(name)
            report.add(f"credential {name}: MISSING (not in the checkout's .env or files)")
        else:
            report.add(f"credential {name}: none yet (added at its own production step)")
    trusted: list[tuple[str, bytes, int]] = []
    for destination, (source, mode, _grouped) in DATA_FILES.items():
        try:
            data = _source(checkout, source)
        except SourceError as exc:
            report.add(f"{destination}: {exc}")
            continue
        if data is None:
            report.add(f"{destination}: not in the checkout ({source})")
            continue
        trusted.append((destination, data, mode))
    if secrets:
        report.add(
            f".env still holds {', '.join(sorted(secrets))}: remove them once the services run"
            " under custody (docker compose reads ARGUS_DATABASE__OWNER_PASSWORD only to make"
            " a new database)"
        )
    trusted.append(("argus.env", env_file_text(plain, report), 0o640))
    _take_trusted(report, etc, trusted, check=check, accept=accept)
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m argus.ops.custody",
        description="The custody layout's import (deploy/custody/install.sh runs it as root).",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    take = commands.add_parser("import", help="secrets and files from a checkout into /etc/argus")
    take.add_argument("--checkout", type=Path, required=True)
    take.add_argument("--etc", type=Path, default=ETC)
    take.add_argument("--check", action="store_true")
    take.add_argument("--accept-settings", metavar="DIGEST", default=None)
    commands.add_parser("names", help="every credential name, one a line")
    args = parser.parse_args(argv)
    if args.command == "names":
        sys.stdout.write("\n".join(all_credentials()) + "\n")
        return 0
    umask = os.umask(0o077)
    try:
        report = import_checkout(
            args.checkout, args.etc, check=args.check, accept=args.accept_settings
        )
    except Exception as exc:  # install.sh stops on this code, never reads it as "pending"
        sys.stderr.write(f"import failed: {type(exc).__name__}: {exc}\n")
        return 4
    finally:
        os.umask(umask)
    sys.stdout.write("".join(f"   {line}\n" for line in report.lines))
    if report.missing:
        return 3
    return 1 if (args.check and report.pending) or report.kept else 0


# --------------------------------------------------------------------------- doctor


def marker(etc: Path = ETC) -> dict[str, str] | None:
    """What install.sh recorded (tag, commit, release), or None: not installed."""
    try:
        data = json.loads((etc / MARKER.name).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        return {}
    return {k: str(v) for k, v in data.items()} if isinstance(data, dict) else {}


def moved_units(etc: Path = ETC) -> set[str]:
    """The user units custody replaced by system units (none while it is not installed)."""
    return set(UNITS) if marker(etc) is not None else set()


def _file_problem(path: Path, *, want_uid: int, mode: int, empty_ok: bool) -> str | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return "missing"
    except OSError as exc:
        return f"cannot be checked ({exc.strerror})"
    if stat.S_ISLNK(info.st_mode):
        return "is a symbolic link (a credential is a file of its own)"
    if not stat.S_ISREG(info.st_mode):
        return "is not a regular file"
    if info.st_uid != want_uid or (want_uid == 0 and info.st_gid != 0):
        return "is not owned by root"
    if stat.S_IMODE(info.st_mode) & ~mode:
        return f"has mode {stat.S_IMODE(info.st_mode):04o} (wanted {mode:04o} at most)"
    if info.st_size == 0 and not empty_ok:
        return "is empty"
    return None


def credential_results(etc: Path = ETC, *, want_uid: int = 0) -> list[CheckResult]:
    """Every credential file: there (when required), root's, mode 0600 at most, not empty, not
    a link; the folder root's and writable by root alone; no file the layout does not name."""
    folder = etc / "credentials"
    results = []
    try:
        info = folder.lstat()
    except OSError:
        return [CheckResult("custody credentials", False, f"{folder} is missing")]
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != want_uid or info.st_mode & 0o022:
        results.append(
            CheckResult(
                "custody credentials",
                False,
                f"{folder} must be root's folder, writable by root only",
            )
        )
    known = all_credentials()
    for name in known:
        problem = _file_problem(
            folder / name, want_uid=want_uid, mode=0o600, empty_ok=name in EMPTY_ALLOWED
        )
        if problem == "missing" and name not in REQUIRED:
            continue
        if problem is not None:
            results.append(CheckResult(f"credential {name}", False, problem))
    try:
        present = sorted(p.name for p in folder.iterdir())
    except OSError:
        present = []
    for name in present:
        if name not in known:
            results.append(
                CheckResult(
                    f"credential {name}",
                    False,
                    "not a credential of the layout: remove it, or name it in argus.ops.custody",
                )
            )
    count = sum(1 for name in known if (folder / name).exists())
    summary = f"{count} of {len(known)} in {folder}, each loaded only by the units that need it"
    ok = not results
    return [CheckResult("custody credentials", ok, summary), *results]


# How a unit can be given a credential: the layout uses LoadCredential= alone.
_CREDENTIAL_KEYS = (
    "LoadCredential",
    "LoadCredentialEncrypted",
    "SetCredential",
    "SetCredentialEncrypted",
    "ImportCredential",
)
# Folders where systemd reads drop-ins that change a system unit (systemd.unit(5)).
SYSTEM_DROP_IN_DIRS = (
    Path("/etc/systemd/system.control"),
    Path("/run/systemd/system.control"),
    Path("/run/systemd/system"),
    Path("/usr/local/lib/systemd/system"),
    Path("/usr/lib/systemd/system"),
)


def _credential_problems(body: str, role: str | None, unit: str | None = None) -> list[str]:
    """What is wrong with how a unit gets its credentials: each must be LoadCredential=NAME:
    /etc/argus/credentials/NAME of a credential its account may hold."""
    problems = []
    for line in body.splitlines():
        key, sep, value = line.strip().partition("=")
        key = key.strip()
        if not sep or key not in _CREDENTIAL_KEYS:
            continue
        name, _, source = value.strip().partition(":")
        if key != "LoadCredential":
            problems.append(
                f"gets {name or 'a credential'} by {key}= (the layout uses LoadCredential=)"
            )
            continue
        extra = UNIT_EXTRA_CREDENTIALS.get(unit or "", ())
        if role is None or (name not in ACCOUNTS[role].credentials and name not in extra):
            problems.append(f"loads {name}, which its account ({role}) must not hold")
        if source != f"{CREDENTIALS}/{name}":
            problems.append(f"loads {name} from {source or 'nowhere'}, not {CREDENTIALS}/{name}")
    return problems


def unit_results(
    source: Path,
    installed: Path,
    *,
    user_units: Iterable[str] = (),
    other_dirs: Sequence[Path] | None = None,
) -> list[CheckResult]:
    """The system units against the release's deploy/custody/units (byte for byte), enabled as
    their role says, no drop-in (in the unit folder and ``other_dirs``: by default systemd's
    other folders when it is /etc/systemd/system, none for a folder given), each credential
    loaded from its own file by a unit whose account may hold it, and no service running twice
    (its user unit still enabled)."""
    if other_dirs is None:
        other_dirs = SYSTEM_DROP_IN_DIRS if installed == SYSTEM_UNITS else ()
    results = []
    wants = {
        entry.name
        for folder in installed.glob("*.wants")
        if folder.is_dir()
        for entry in folder.iterdir()
    }
    for name, (role, unit_role) in UNITS.items():
        src, dst = source / name, installed / name
        if not src.is_file():
            results.append(CheckResult(f"system unit {name}", False, f"missing from {source}"))
            continue
        if not dst.is_file():
            results.append(CheckResult(f"system unit {name}", False, "not installed"))
            continue
        body = dst.read_text(encoding="utf-8", errors="replace")
        if dst.read_bytes() != src.read_bytes():
            results.append(
                CheckResult(f"system unit {name}", False, "differs from the release's copy")
            )
        for problem in _credential_problems(body, role, name):
            results.append(CheckResult(f"system unit {name}", False, problem))
        enabled = name in wants
        if unit_role is Role.RUN and not enabled:
            results.append(CheckResult(f"system unit {name}", False, "installed but not enabled"))
        if unit_role is Role.OFF and enabled:
            results.append(
                CheckResult(f"system unit {name}", False, "enabled before its production step")
            )
        if unit_role is Role.SOON and not enabled:
            results.append(
                CheckResult(
                    f"system unit {name}", True, "not enabled yet: a production step", warn=True
                )
            )
        if name in user_units and enabled:
            results.append(
                CheckResult(
                    f"system unit {name}",
                    False,
                    "its user unit is enabled too: the service would run twice (disable the"
                    " user unit: systemctl --user disable --now " + name + ")",
                )
            )
    folders = [
        folder
        for base in (installed, *other_dirs)
        for folder in [*sorted(base.glob("argus-*.d")), base / "service.d", base / "timer.d"]
    ]
    for folder in folders:
        for conf in sorted(folder.glob("*.conf")) if folder.is_dir() else []:
            results.append(
                CheckResult(
                    f"system unit {folder.name.removesuffix('.d')}",
                    False,
                    f"a drop-in changes it: {conf} (deploy/custody/units holds whole units)",
                )
            )
    return results


def release_results(etc: Path = ETC, opt: Path = OPT, *, want_uid: int = 0) -> list[CheckResult]:
    """The deploy copy: current points at the release the marker names, root's, no write bit."""
    recorded = marker(etc) or {}
    release = opt / "releases" / recorded.get("release", "?")
    current = opt / "current"
    try:
        target = current.resolve(strict=True)
    except OSError:
        return [CheckResult("deploy copy", False, f"{current} does not point at a release")]
    if target != release.resolve():
        return [CheckResult("deploy copy", False, f"{current} is {target}, not {release}")]
    writable: list[str] = []
    foreign: list[str] = []
    walked = os.walk(target)
    for top, dirs, files in walked:
        here = [os.path.join(top, name) for name in files + dirs]
        for entry in [top, *here] if top == str(target) else here:
            info = os.lstat(entry)
            if stat.S_ISLNK(info.st_mode):
                continue
            if info.st_mode & 0o222:
                writable.append(entry)
            if info.st_uid != want_uid:
                foreign.append(entry)
    if writable or foreign:
        bad = (writable + foreign)[:3]
        return [
            CheckResult(
                "deploy copy",
                False,
                f"{len(writable)} writable and {len(foreign)} not root's in {target}, e.g."
                f" {', '.join(bad)}",
            )
        ]
    tag, commit = recorded.get("tag", "?"), recorded.get("commit", "?")[:12]
    return [CheckResult("deploy copy", True, f"{target} ({tag}, {commit}): root's, read-only")]


def account_results(
    *,
    uid: int | None = None,
    home: Path | None = None,
    env_file: Path | None = None,
) -> list[CheckResult]:
    """Warnings about the operator's account, which custody cannot fix: groups that read any
    root-owned file, a home others may enter, and secrets still in the shared .env."""
    uid = os.getuid() if uid is None else uid
    results = []
    try:
        user = pwd.getpwuid(uid)
        names = {g.gr_name for g in grp.getgrall() if user.pw_name in g.gr_mem}
        names |= {grp.getgrgid(user.pw_gid).gr_name}
    except KeyError:
        names = set()
    risky = sorted(names & set(ROOT_EQUIVALENT_GROUPS))
    if risky and uid != 0:
        results.append(
            CheckResult(
                "custody operator",
                True,
                f"this account is in {', '.join(risky)}: through it any process of this account"
                " (build tools, AI agents) can read every root-owned credential. Custody holds"
                " once it leaves them (sudo for docker): docs/runbooks/custody.md",
                warn=True,
            )
        )
    home = Path.home() if home is None else home
    try:
        if home.stat().st_mode & 0o001:
            results.append(
                CheckResult(
                    "custody operator",
                    True,
                    f"{home} may be entered by every account (mode o+x): chmod o-x {home}",
                    warn=True,
                )
            )
    except OSError:
        pass
    if env_file is not None and env_file.is_file():
        try:
            secrets, _, _ = split_env(env_file)
        except ConfigError:
            secrets = {}
        if secrets:
            results.append(
                CheckResult(
                    "custody operator",
                    True,
                    f"{env_file} still holds {', '.join(sorted(secrets))}: the credentials hold"
                    " them now; remove them from it (docker compose needs only"
                    " ARGUS_DATABASE__OWNER_PASSWORD, at a first start)",
                    warn=True,
                )
            )
    return results


def custody_results(
    settings: Settings,
    *,
    etc: Path = ETC,
    opt: Path = OPT,
    units_dir: Path = SYSTEM_UNITS,
    user_units: Iterable[str] = (),
    want_uid: int = 0,
) -> list[CheckResult]:
    recorded = marker(etc)
    if recorded is None:
        return [
            CheckResult(
                "custody",
                True,
                "not installed: every service is a user unit of this account with its secrets"
                " in .env (Q-A5's production step: deploy/custody/install.sh,"
                " docs/runbooks/custody.md)",
                warn=True,
            )
        ]
    if not recorded:
        return [CheckResult("custody", False, f"{etc / MARKER.name} cannot be read")]
    release = opt / "releases" / recorded.get("release", "?")
    results = credential_results(etc, want_uid=want_uid)
    results += release_results(etc, opt, want_uid=want_uid)
    results += unit_results(release / "deploy" / "custody" / "units", units_dir,
                            user_units=user_units)  # fmt: skip
    results += account_results(env_file=settings.env_file)
    ok = all(r.ok for r in results)
    head = CheckResult(
        "custody",
        ok,
        f"installed ({recorded.get('tag', '?')}): services run as {', '.join(SERVICE_USERS)}",
    )
    return [head, *results]


def credential_name_problems(names: Iterable[str]) -> list[str]:
    """Names the layout gives that the settings would refuse or never read (for the tests)."""
    secrets = set(secret_settings())
    out = []
    for name in names:
        if CREDENTIAL_SETTING.fullmatch(name) and name not in secrets:
            out.append(f"{name} looks like a setting but is no secret setting")
        if not CREDENTIAL_SETTING.fullmatch(name) and name not in FILE_CREDENTIALS:
            out.append(f"{name} is neither a secret setting nor a file credential")
    for role, account in ACCOUNTS.items():
        extras = {n for unit, (r, _) in UNITS.items() if r == role
                  for n in UNIT_EXTRA_CREDENTIALS.get(unit, ())}  # fmt: skip
        loaded = {*account.credentials, *extras}
        dotted = {n for n in loaded if CREDENTIAL_SETTING.fullmatch(n)}
        if dotted != CUSTODY_SECRETS[role]:
            allowed = sorted(CUSTODY_SECRETS[role])
            out.append(f"{role} loads {sorted(dotted)}, the settings allow {allowed}")
    return out


if __name__ == "__main__":
    sys.exit(main())
