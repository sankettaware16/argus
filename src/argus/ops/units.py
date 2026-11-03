"""ARGUS's systemd user units (Q-A2, D-295). The files in ``deploy/systemd/`` are templates: each
installation renders them with the checkout the units run, the uv that starts ARGUS and the web's
environment (``units`` in the settings), ``argus units install`` writes the rendered text, and
``argus doctor`` checks that what is installed equals it byte for byte and runs only what is meant
to run. Nothing here starts, stops or enables a unit; reading the unit directory is all doctor
does."""

from __future__ import annotations

import difflib
import os
import re
import shlex
import shutil
import tempfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from argus.config.settings import UnitsSettings

REPO = Path(__file__).resolve().parents[3]
UNITS_DIR = REPO / "deploy" / "systemd"
INSTALL = "argus units install"


class Role(StrEnum):
    RUN = "run"  # installed and enabled: this installation runs it
    TRIGGERED = "triggered"  # started by its timer, never enabled itself
    CHOICE = "choice"  # runs when this installation lists it (units.run); either way no fault
    SOON = "soon"  # enabled at the next checkpoint (a production step); a warning until then
    OFF = "off"  # enabled only at its own production step; enabled before it, a failure


# Every unit file in deploy/systemd, and what it is for. A unit this installation runs is listed in
# ``units.run`` (config/local.yaml): enabling an OFF unit is a production step with the user
# (D-109), and the step adds it there.
MANIFEST: dict[str, tuple[Role, str]] = {
    "argus-collector.service": (Role.RUN, "the collector (R5)"),
    "argus-worker.service": (Role.RUN, "the context worker (R8)"),
    "argus-web.service": (Role.RUN, "the web (R7, D-104)"),
    "argus-assess.service": (Role.RUN, "the assessments (Phase 2)"),
    "argus-soak-sample.timer": (Role.CHOICE, "the soak samples (D-092)"),
    "argus-soak-sample.service": (Role.TRIGGERED, "started by argus-soak-sample.timer"),
    "argus-backup.timer": (Role.SOON, "the nightly dump (Q-A2)"),
    "argus-backup.service": (Role.TRIGGERED, "started by argus-backup.timer"),
    "argus-backup-drill.timer": (Role.SOON, "the weekly restore drill (Q-A2)"),
    "argus-backup-drill.service": (Role.TRIGGERED, "started by argus-backup-drill.timer"),
    "argus-purge.timer": (Role.OFF, "the retention purge (Q-A4): its schedule is the user's"),
    "argus-purge.service": (Role.TRIGGERED, "started by argus-purge.timer"),
    "argus-notices.timer": (Role.OFF, "notices (Q-H4): the user approves the relay and recipients"),
    "argus-notices.service": (Role.TRIGGERED, "started by argus-notices.timer"),
    "argus-report-daily.timer": (
        Role.OFF,
        "the daily report (Q-H3): on after the user has read two",
    ),
    "argus-report-daily.service": (Role.TRIGGERED, "started by argus-report-daily.timer"),
    "argus-report-weekly.timer": (
        Role.OFF,
        "the weekly report (Q-H3): on after the user has read two",
    ),
    "argus-report-weekly.service": (Role.TRIGGERED, "started by argus-report-weekly.timer"),
    "argus-kibana-sync.service": (Role.CHOICE, "Kibana read-back and Verdict: comments (D-214)"),
    "argus-case-team.timer": (Role.CHOICE, "the case team's posts to Kibana (AR8, D-214)"),
    "argus-case-team.service": (Role.TRIGGERED, "started by argus-case-team.timer"),
    "argus-writer.service": (Role.OFF, "Kibana writes (Q-D4, Q-D5): each class's canary"),
    "argus-soak-phase3.timer": (Role.OFF, "the soak gate, daily (P4-A1): on when the lead says"),
    "argus-soak-phase3.service": (Role.TRIGGERED, "started by argus-soak-phase3.timer"),
}
# What an installation runs when ``units.run`` is left out: ARGUS's four services.
CORE = tuple(name for name, (role, _) in MANIFEST.items() if role is Role.RUN)


def roles_for(run: Iterable[str] | None = None) -> dict[str, tuple[Role, str]]:
    """Each unit's role for an installation that runs ``run`` (``units.run``; None: ``CORE``): a
    listed unit runs; a service or timer that may run but is not listed is the installation's
    choice; the production steps (SOON, OFF) and the triggered services keep theirs."""
    chosen = set(CORE if run is None else run)
    roles: dict[str, tuple[Role, str]] = {}
    for name, (role, why) in MANIFEST.items():
        if name in chosen:
            roles[name] = (Role.RUN, why)
        elif role is Role.RUN:
            roles[name] = (Role.CHOICE, why)
        else:
            roles[name] = (role, why)
    return roles


# --------------------------------------------------------------------------- rendering

PLACEHOLDER = re.compile(r"@([A-Z][A-Z_]*)@")
_REQUIRED = ("ROOT", "UV")
_OPTIONAL = "WEB_"  # the web's environment (units.web): a line without its value is left out


class UnitsError(Exception):
    """A unit cannot be rendered or installed (the message says why)."""


@dataclass(frozen=True)
class UnitParams:
    """What the templates are rendered with: the checkout, the uv, and the optional values
    (``WEB_HOST`` ...), each dropping its line when it is not given."""

    root: Path
    uv: str
    values: Mapping[str, str] = field(default_factory=dict)


def default_uv() -> str:
    """The uv running this command (``uv run`` names itself in ``UV``), else the one on PATH."""
    named = os.environ.get("UV", "")
    if named and Path(named).is_absolute() and Path(named).is_file():
        return named
    found = shutil.which("uv")
    if found is None:
        raise UnitsError("uv is not on PATH: set units.uv (config/local.yaml) to its full path")
    return str(Path(found).absolute())


def params_of(units: UnitsSettings | None = None, *, uv: str | None = None) -> UnitParams:
    """The rendering parameters of an installation's ``units`` settings."""
    if units is None:
        return UnitParams(REPO, uv or default_uv())
    chosen = str(units.uv) if units.uv is not None else (uv or default_uv())
    return UnitParams(units.root or REPO, chosen, units.web.environment())


def render(text: str, params: UnitParams) -> str:
    """A template with its placeholders filled. A line whose optional placeholder has no value is
    left out, and so are the comment lines just above a group of such lines when every line of
    the group went (a group: comments, then lines with optional placeholders)."""
    out: list[str] = []
    pending: list[str] = []  # comments not yet written: they belong to the lines below them
    in_group = False  # lines with optional placeholders have followed the pending comments
    for line in text.splitlines(keepends=True):
        names = PLACEHOLDER.findall(line)
        unknown = [n for n in names if n not in _REQUIRED and not n.startswith(_OPTIONAL)]
        if unknown:
            raise UnitsError(f"unknown placeholder @{unknown[0]}@")
        optional = [n for n in names if n.startswith(_OPTIONAL)]
        if line.lstrip().startswith(("#", ";")):
            if in_group:
                pending, in_group = [], False  # the comments of a group that went entirely
            pending.append(line)
            continue
        if optional:
            in_group = True
            if any(n not in params.values or not params.values[n] for n in optional):
                continue
            out += pending
            pending = []
            out.append(_fill(line, params))
            continue
        if not in_group:
            out += pending
        pending, in_group = [], False
        out.append(_fill(line, params))
    if not in_group:
        out += pending
    return "".join(out)


def _fill(line: str, params: UnitParams) -> str:
    values = {"ROOT": str(params.root), "UV": params.uv, **params.values}

    def one(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in values:
            raise UnitsError(f"unknown placeholder @{name}@")
        return values[name]

    return PLACEHOLDER.sub(one, line)


def rendered_units(params: UnitParams, repo_dir: Path = UNITS_DIR) -> dict[str, str]:
    """Every unit file of ``repo_dir`` rendered, by name."""
    return {
        path.name: render(path.read_text(encoding="utf-8"), params)
        for path in sorted(_unit_files(repo_dir))
    }


def user_unit_dir() -> Path:
    """Where systemd reads a user's own units: $XDG_CONFIG_HOME/systemd/user."""
    config = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(config) / "systemd" / "user"


def control_dirs() -> list[Path]:
    """The other folders where a user's systemd reads configuration that can change ARGUS's
    units (systemd.unit(5)): ``systemctl --user set-property``'s (user.control, persistent and
    runtime), ``systemctl --user edit --runtime``'s, the administrator's and the data home's."""
    config = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    runtime = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    data = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return [
        Path(config) / "systemd" / "user.control",
        Path(runtime) / "systemd" / "user.control",
        Path(runtime) / "systemd" / "user",
        Path("/etc/systemd/user"),
        Path(data) / "systemd" / "user",
    ]


def is_argus_drop_in_dir(name: str) -> bool:
    """A drop-in folder that can change an ARGUS unit: one unit's (``argus-web.service.d``), a
    name prefix's (``argus-.service.d``) or a whole type's (``service.d``, ``timer.d``)."""
    return name.endswith(".d") and (name.startswith("argus-") or name in _TYPE_DROP_INS)


_TYPE_DROP_INS = ("service.d", "timer.d")


@dataclass(frozen=True)
class DropIn:
    path: Path
    applies_to: str  # its folder's name without ".d": a unit, a prefix ("argus-.service"), a type

    def changes(self, unit: str) -> bool:
        stem, _, kind = self.applies_to.rpartition(".")
        if not stem:  # a whole type: service.d
            return unit.endswith(f".{self.applies_to}")
        if stem.endswith("-"):  # a prefix: argus-.service.d
            return unit.startswith(stem) and unit.endswith(f".{kind}")
        return unit == self.applies_to


def drop_ins(folders: list[Path]) -> list[DropIn]:
    """Every drop-in (``*.conf``) in ``folders`` that can change an ARGUS unit. deploy/systemd
    holds whole unit files only, so each one makes a unit differ from the repository's."""
    found = []
    for folder in folders:
        if not folder.is_dir():
            continue
        for entry in sorted(folder.iterdir()):
            if entry.is_dir() and is_argus_drop_in_dir(entry.name):
                applies_to = entry.name.removesuffix(".d")
                found += [DropIn(conf, applies_to) for conf in sorted(entry.glob("*.conf"))]
    return found


@dataclass(frozen=True)
class UnitState:
    name: str
    role: Role
    why: str
    in_repository: bool
    installed: bool
    identical: bool  # the installed copy equals the rendered template, byte for byte
    enabled: bool  # linked from a .wants or .requires directory of the unit directory
    timer_runs: bool = False  # a triggered service: its timer runs, so it must be installed


def enabled_units(installed_dir: Path) -> set[str]:
    """The units linked from ``*.wants`` and ``*.requires`` directories (what ``systemctl
    --user enable`` makes), by name."""
    names: set[str] = set()
    if not installed_dir.is_dir():
        return names
    for pattern in ("*.wants", "*.requires"):
        for folder in installed_dir.glob(pattern):
            if folder.is_dir():
                names.update(entry.name for entry in folder.iterdir())
    return names


MOVED = "moved to its system unit (custody, Q-A5): the user unit stays off"


def unit_states(
    repo_dir: Path = UNITS_DIR,
    installed_dir: Path | None = None,
    moved: frozenset[str] | set[str] = frozenset(),
    params: UnitParams | None = None,
    run: Iterable[str] | None = None,
) -> tuple[list[UnitState], list[str], list[str]]:
    """Each manifest unit's state (its installed copy against its template rendered with
    ``params``, by default for this checkout and the uv running this; its role for an
    installation that runs ``run``); the unit files in the repository that the manifest lacks;
    the ARGUS units installed that the repository lacks. A unit in ``moved`` runs as a system
    unit under custody (argus.ops.custody), so its user unit must be off."""
    installed_dir = user_unit_dir() if installed_dir is None else installed_dir
    params = params_of() if params is None else params
    enabled = enabled_units(installed_dir)
    roles = roles_for(run)
    states = []
    for name, (role, why) in roles.items():
        if name in moved:
            role, why = Role.OFF, MOVED
        source, target = repo_dir / name, installed_dir / name
        in_repo, installed = source.is_file(), target.is_file()
        same = (
            in_repo
            and installed
            and render(source.read_text(encoding="utf-8"), params).encode() == target.read_bytes()
        )
        timer = roles.get(name.removesuffix(".service") + ".timer")
        runs = role is Role.TRIGGERED and timer is not None and timer[0] is Role.RUN
        states.append(UnitState(name, role, why, in_repo, installed, same, name in enabled, runs))
    on_disk = {p.name for p in _unit_files(repo_dir)}
    unlisted = sorted(on_disk - set(MANIFEST))
    stray = sorted({p.name for p in _unit_files(installed_dir)} - set(MANIFEST))
    return states, unlisted, stray


def installed_root(installed_dir: Path, names: Iterable[str] = MANIFEST) -> Path | None:
    """The checkout the installed units run (the first installed one's WorkingDirectory)."""
    for name in names:
        path = installed_dir / name
        if path.is_file():
            folder = working_directory(path)
            if folder is not None and folder.is_absolute():  # a copied template's is @ROOT@
                return folder
    return None


def _unit_files(folder: Path) -> list[Path]:
    if not folder.is_dir():
        return []
    return [p for p in folder.iterdir() if p.name.startswith("argus-") and p.suffix in _SUFFIXES]


_SUFFIXES = (".service", ".timer")


def problems(state: UnitState) -> tuple[str, bool] | None:
    """What is wrong with one unit, and whether it is only a warning; None when nothing is."""
    if not state.in_repository:
        return "missing from deploy/systemd", False
    if state.installed and not state.identical:
        return f"the installed copy differs from its rendered template ({INSTALL})", False
    if state.role is Role.RUN:
        if not state.installed:
            return f"not installed: run {INSTALL} --apply", False
        if not state.enabled:
            return "installed but not enabled", False
    if state.role is Role.CHOICE and state.enabled:
        return (
            f"enabled, but units.run does not list it ({state.why}): add it there"
            " (config/local.yaml) so doctor watches it",
            True,
        )
    if state.role is Role.TRIGGERED and not state.installed:
        return f"not installed: run {INSTALL} --apply", not state.timer_runs
    if state.role is Role.SOON and not state.enabled:
        return f"not enabled yet ({state.why}): a production step", True
    if state.role is Role.OFF and state.enabled:
        return f"enabled before its production step ({state.why})", False
    return None


def unit_environment(path: Path) -> dict[str, str]:
    """The ``Environment=`` assignments of a unit's [Service] section (systemd's quoting, as far
    as ARGUS's units use it: words, optionally in double or single quotes)."""
    return environment_of(path.read_text(encoding="utf-8"))


def environment_of(text: str) -> dict[str, str]:
    """``unit_environment`` of a unit's text."""
    values: dict[str, str] = {}
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        key, sep, value = line.partition("=")
        if section != "Service" or not sep or key.strip() != "Environment":
            continue
        try:
            words = shlex.split(value)
        except ValueError:
            continue
        for word in words:
            name, has, setting = word.partition("=")
            if has and name:
                values[name] = setting
    return values


def working_directory(path: Path) -> Path | None:
    """A unit's WorkingDirectory=, if it has one."""
    return working_directory_of(path.read_text(encoding="utf-8"))


def working_directory_of(text: str) -> Path | None:
    """``working_directory`` of a unit's text."""
    for raw in text.splitlines():
        key, sep, value = raw.strip().partition("=")
        if sep and key.strip() == "WorkingDirectory" and value.strip():
            return Path(value.strip())
    return None


# --------------------------------------------------------------------------- the installer


@dataclass(frozen=True)
class InstallPlan:
    """What ``argus units install`` would change in a unit directory."""

    dest: Path
    rendered: Mapping[str, str]
    changed: tuple[str, ...]
    new: tuple[str, ...]
    same: int
    stray: tuple[str, ...]  # ARGUS units installed that the repository lacks (left alone)
    drop_ins: tuple[Path, ...]
    diffs: Mapping[str, str]  # by changed unit, secrets masked

    @property
    def to_write(self) -> tuple[str, ...]:
        return (*self.changed, *self.new)


_UNIT_NAME = re.compile(r"^argus-[a-z0-9-]+\.(service|timer)$")
_SECRET_VALUE = re.compile(
    r"([A-Za-z0-9_]*(PASSWORD|PASSWD|SECRET|TOKEN|KEY)[A-Za-z0-9_]*=)[^\s\"]*"
)


def mask(text: str) -> str:
    """Values of variables named like secrets masked: an installed copy may hold one."""
    return _SECRET_VALUE.sub(r"\1***", text)


def plan_install(
    params: UnitParams, dest: Path | None = None, repo_dir: Path = UNITS_DIR
) -> InstallPlan:
    """Render every template and compare it with ``dest`` (the user's unit directory). Reads
    only."""
    own = dest is None
    dest = user_unit_dir() if dest is None else dest
    rendered = rendered_units(params, repo_dir)
    if not rendered:
        raise UnitsError(f"no unit files in {repo_dir}")
    changed: list[str] = []
    new: list[str] = []
    diffs: dict[str, str] = {}
    same = 0
    for name, text in rendered.items():
        if not _UNIT_NAME.fullmatch(name):
            raise UnitsError(f"refusing {name} (not an ARGUS unit name)")
        target = dest / name
        if target.is_file() and target.read_bytes() == text.encode():
            same += 1
        elif target.exists():
            changed.append(name)
            before = target.read_text(encoding="utf-8", errors="replace")
            diff = difflib.unified_diff(
                before.splitlines(keepends=True),
                text.splitlines(keepends=True),
                f"installed/{name}",
                f"rendered/{name}",
            )
            diffs[name] = mask("".join(diff))
        else:
            new.append(name)
    stray = sorted({p.name for p in _unit_files(dest)} - set(rendered))
    folders = [dest, *(control_dirs()[:3] if own else ())]
    found = tuple(d.path for d in drop_ins(folders))
    return InstallPlan(dest, rendered, tuple(changed), tuple(new), same, tuple(stray), found, diffs)


def apply_install(plan: InstallPlan) -> None:
    """Write the changed and new units (mode 0644, each through a temporary file renamed into
    place, then read back). Nothing is enabled, started or reloaded here."""
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise UnitsError("these are user units: install them as the user that runs ARGUS, not root")
    plan.dest.mkdir(parents=True, exist_ok=True)
    for name in plan.to_write:
        text = plan.rendered[name]
        fd, temporary = tempfile.mkstemp(prefix=f".{name}.", dir=plan.dest)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(text)
            os.chmod(temporary, 0o644)
            os.replace(temporary, plan.dest / name)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise
        if (plan.dest / name).read_bytes() != text.encode():
            raise UnitsError(f"{name} was not written exactly")
