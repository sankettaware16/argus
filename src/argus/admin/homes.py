"""Where a setting lives on this host, and how a change is written (D-327).

A setting may be set in several places at once: ``config/admin.yaml`` (the app's own, untracked),
``.env``, one service's env file (``local/argus-writer.env``) or its credential folder
(``local/creds-writer/kibana.reader_api_key``). A change is written to every one of them that sets
it, so no copy ever disagrees; a setting set nowhere goes to its home: ``admin.yaml``, ``.env`` for
a secret, the service's own file for one only it reads. Files in git (``argus.yaml``,
``local.yaml``, ``site.yaml``) are never written: they are the defaults a reset returns to."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any, Literal

import yaml

from argus.admin.catalogue import Entry
from argus.config.settings import ADMIN_FILE
from argus.install import files

Where = Literal["admin", "env", "credential"]
REMOVE = object()  # a reset: the setting leaves admin.yaml


@dataclass(frozen=True)
class Home:
    where: Where
    path: Path  # relative to the installation's root

    def describe(self) -> str:
        return {"admin": "set in the app", "env": f"in {self.path}",
                "credential": f"a credential in {self.path.parent}"}[self.where]  # fmt: skip


@dataclass
class Plan:
    """The file edits one change makes, before anything is written."""

    admin: dict[str, Any] = field(default_factory=dict)  # dotted name -> value or REMOVE
    env: dict[Path, dict[str, str]] = field(default_factory=dict)
    credentials: dict[Path, str] = field(default_factory=dict)

    def paths(self) -> list[Path]:
        return [Path("config") / ADMIN_FILE] * bool(self.admin) + [*self.env, *self.credentials]


def env_name(key: str) -> str:
    return "ARGUS_" + key.upper().replace(".", "__")


def env_files(root: Path) -> list[Path]:
    found = [Path(".env")] if (root / ".env").is_file() else []
    local = root / "local"
    if local.is_dir():
        found += sorted(Path("local") / p.name for p in local.glob("*.env") if p.is_file())
    return found


def credential_dirs(root: Path) -> list[Path]:
    local = root / "local"
    if not local.is_dir():
        return []
    return sorted(Path("local") / p.name for p in local.glob("creds-*") if p.is_dir())


def homes(root: Path, entry: Entry) -> list[Home]:
    """Every place on this host that sets ``entry`` (never a value)."""
    found: list[Home] = []
    if not entry.secret and files.has(files.read_yaml(root / "config" / ADMIN_FILE), entry.key):
        found.append(Home("admin", Path("config") / ADMIN_FILE))
    name = env_name(entry.key)
    found += [Home("env", p) for p in env_files(root) if name in files.read_env(root / p)]
    if entry.secret:
        found += [Home("credential", d / entry.key) for d in credential_dirs(root)
                  if (root / d / entry.key).is_file()]  # fmt: skip
    return found


def as_yaml(entry: Entry, value: Any) -> Any:
    if value is None:
        return None
    if entry.kind == "duration":
        return duration_text(value)
    if entry.kind in ("date", "path"):
        return str(value)
    if entry.kind == "list":
        return [str(v) for v in value]
    return value


def as_env(entry: Entry, value: Any) -> str:
    if value is None:
        return ""
    if entry.kind == "bool":
        return "true" if value else "false"
    if entry.kind == "duration":
        return duration_text(value)
    if entry.kind == "list":
        return ",".join(str(v) for v in value)
    return str(value)


def duration_text(value: Any) -> str:
    seconds = int(value.total_seconds()) if isinstance(value, timedelta) else int(value)
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds and seconds % size == 0:
            return f"{seconds // size}{unit}"
    return f"{seconds}s"


def plan(root: Path, entry: Entry, value: Any, *, reset: bool = False) -> Plan:
    """The edits that set ``entry`` to ``value`` (already validated) everywhere it is set."""
    out = Plan()
    found = homes(root, entry)
    if reset:
        out.admin[entry.key] = REMOVE
        if entry.mirror:
            out.admin[entry.mirror] = REMOVE
        return out
    for home in found:
        if home.where == "env":
            out.env.setdefault(home.path, {})[env_name(entry.key)] = as_env(entry, value)
        elif home.where == "credential":
            out.credentials[home.path] = str(value)
    if entry.secret:
        if not found:
            out.env.setdefault(Path(".env"), {})[env_name(entry.key)] = str(value)
        return out
    if entry.unit_file and not found:
        path = Path("local") / entry.unit_file
        out.env.setdefault(path, {})[env_name(entry.key)] = as_env(entry, value)
    out.admin[entry.key] = as_yaml(entry, value)
    if entry.mirror:
        out.admin[entry.mirror] = as_yaml(entry, value)
    return out


def merged(plans: Sequence[Plan]) -> Plan:
    out = Plan()
    for p in plans:
        out.admin.update(p.admin)
        for path, values in p.env.items():
            out.env.setdefault(path, {}).update(values)
        out.credentials.update(p.credentials)
    return out


def admin_text(current: Mapping[str, Any], edits: Mapping[str, Any]) -> str:
    """``admin.yaml`` with ``edits`` applied (``REMOVE`` drops a name and an emptied section)."""
    data: dict[str, Any] = _copy(current)
    for dotted, value in edits.items():
        if value is REMOVE:
            _drop(data, dotted.split("."))
        else:
            files.put(data, dotted, value)
    head = ("# Settings changed in ARGUS's app (Settings). Written by argus-admin; never in git.\n"
            "# A name removed here returns to config/local.yaml's value.\n")  # fmt: skip
    if not data:
        return head
    return head + yaml.safe_dump(data, default_flow_style=False, sort_keys=True, width=100)


def _copy(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {k: _copy(v) for k, v in value.items()}
    return value


def _drop(data: dict[str, Any], parts: list[str]) -> None:
    node: Any = data
    trail: list[tuple[dict[str, Any], str]] = []
    for part in parts[:-1]:
        if not isinstance(node, dict) or part not in node:
            return
        trail.append((node, part))
        node = node[part]
    if isinstance(node, dict):
        node.pop(parts[-1], None)
    for parent, part in reversed(trail):
        if parent[part] == {}:
            del parent[part]


@dataclass(frozen=True)
class Written:
    """What a plan replaced, to put back if the services do not come up again."""

    before: dict[Path, bytes | None]


def write(root: Path, p: Plan) -> Written:
    """Write ``p`` (each file atomically, secrets 0600); what each file held before."""
    before: dict[Path, bytes | None] = {}
    for rel in p.paths():
        target = root / rel
        before[rel] = target.read_bytes() if target.is_file() else None
    if p.admin:
        path = root / "config" / ADMIN_FILE
        files.write_public(path, admin_text(files.read_yaml(path), p.admin))
    for rel, values in p.env.items():
        files.update_env(root / rel, values, replace=frozenset(values))
    for rel, text in p.credentials.items():
        files.write_private(root / rel, text)
    return Written(before)


def restore(root: Path, written: Written) -> None:
    for rel, content in written.before.items():
        target = root / rel
        if content is None:
            target.unlink(missing_ok=True)
        elif rel.parent.name.startswith("creds-") or rel.suffix == ".env" or rel.name == ".env":
            files.write_private(target, content.decode("utf-8"))
        else:
            files.write_public(target, content.decode("utf-8"))
