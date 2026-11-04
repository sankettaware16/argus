"""The files ``argus init`` writes: ``.env`` (secrets, mode 0600, never printed), and this
installation's YAML (``config/local.yaml``, ``config/site.yaml``, ``config/llm.local.yaml``).
Every write goes through a temporary file renamed into place; a value already there is kept
unless the caller replaces it on purpose."""

from __future__ import annotations

import io
import os
import secrets
import stat
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml
from dotenv.parser import parse_stream

from argus.install.answers import InitError

# What docker compose and `argus db bootstrap` need (docker-compose.yml, .env.example,
# argus.db.roles): the logins' names and the server, then the passwords made here. The web's own
# login gets one too; the case writer's does not: writes stay off.
ENV_DEFAULTS: dict[str, str] = {
    "ARGUS_DATABASE__OWNER_USER": "argus",
    "ARGUS_DATABASE__USER": "argus_app",
    "ARGUS_DATABASE__NAME": "argus",
    "ARGUS_DATABASE__HOST": "127.0.0.1",
    "ARGUS_DATABASE__PORT": "55432",
}
GENERATED = (
    "ARGUS_DATABASE__OWNER_PASSWORD",
    "ARGUS_DATABASE__PASSWORD",
    "ARGUS_DATABASE__API_PASSWORD",
    # docker-compose.yml requires it of the whole file (the replica's ${...:?}), db's too
    "REPLICA_ELASTIC_PASSWORD",
)
WEB_PASSWORD = "ARGUS_DATABASE__API_PASSWORD"  # noqa: S105 - a variable name
PLACEHOLDERS = frozenset({"change-me", "change-me-too"})  # .env.example's


def new_password() -> str:
    """A random password libpq, docker compose and a shell line take as it is (URL-safe)."""
    return secrets.token_urlsafe(32)


def read_env(path: Path) -> dict[str, str]:
    """The variables an env file sets (python-dotenv's reading), by name; empty when absent."""
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise InitError(f"cannot read {path} ({exc.strerror})") from None
    found: dict[str, str] = {}
    for binding in parse_stream(io.StringIO(raw)):
        if binding.key is not None and binding.value is not None:
            found[binding.key] = binding.value
    return found


def _line(name: str, value: str) -> str:
    if any(c in value for c in "\n\r\0"):
        raise InitError(f"{name}: a value on one line only")
    if any(c in value for c in " #'\"\\$`"):
        escaped = value.replace("\\", "\\\\").replace("'", "\\'")
        return f"{name}='{escaped}'\n"
    return f"{name}={value}\n"


def update_env(
    path: Path, values: Mapping[str, str], *, replace: frozenset[str] = frozenset()
) -> list[str]:
    """Add each of ``values`` that ``path`` does not set; a name in ``replace`` is set even when
    the file has it (its old line goes). Mode 0600 whatever the umask. The names written, in
    order; no value is ever returned or printed."""
    existing = read_env(path)
    try:
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    except FileNotFoundError:
        lines = []
    written: list[str] = []
    for name, value in values.items():
        if name in existing and name not in replace:
            continue
        if name in existing:
            lines = [line for line in lines if _names(line) != name]
        if lines and not lines[-1].endswith("\n"):
            lines[-1] += "\n"
        lines.append(_line(name, value))
        written.append(name)
    if written or (path.exists() and stat.S_IMODE(path.stat().st_mode) != 0o600):
        write_private(path, "".join(lines))
    return written


def _names(line: str) -> str:
    text = line.strip()
    if text.startswith("export "):
        text = text[len("export ") :].lstrip()
    return text.partition("=")[0].strip().strip("'\"")


def write_private(path: Path, text: str) -> None:
    """``text`` into ``path`` with mode 0600, atomically."""
    _write(path, text, 0o600)


def write_public(path: Path, text: str) -> None:
    """``text`` into ``path`` with mode 0644, atomically (configuration, never a secret)."""
    _write(path, text, 0o644)


def _write(path: Path, text: str, mode: int) -> None:
    if path.is_symlink():
        raise InitError(f"{path} is a link: not written through")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise


# --------------------------------------------------------------------------- YAML


def read_yaml(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, yaml.YAMLError) as exc:
        raise InitError(f"cannot read {path}: {type(exc).__name__}") from None
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise InitError(f"{path} is not a YAML mapping")
    return data


def get(data: Mapping[str, Any], dotted: str) -> Any:
    node: Any = data
    for part in dotted.split("."):
        if not isinstance(node, Mapping) or part not in node:
            return None
        node = node[part]
    return node


def has(data: Mapping[str, Any], dotted: str) -> bool:
    node: Any = data
    for part in dotted.split("."):
        if not isinstance(node, Mapping) or part not in node:
            return False
        node = node[part]
    return True


def put(data: dict[str, Any], dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    node = data
    for part in parts[:-1]:
        child = node.get(part)
        if not isinstance(child, dict):
            child = {}
            node[part] = child
        node = child
    node[parts[-1]] = value


LOCAL_HEADER = (
    "# This installation's own values (D-294), read beside config/argus.yaml, above it and below\n"
    "# .env and the environment. Written by `argus init`; edit freely: a rerun keeps what is\n"
    "# here.\n"
)


def update_yaml(path: Path, changes: Mapping[str, Any], header: str = LOCAL_HEADER) -> list[str]:
    """Set each dotted name of ``changes`` in the YAML file at ``path``; the names that changed.
    The file is rewritten only when one did. Each value is edited in place, so the file's
    comments, order and layout stay; a file whose shape the line editor cannot follow is
    rewritten whole (its leading comment lines kept)."""
    data = read_yaml(path)
    changed = [
        name for name, value in changes.items() if not has(data, name) or get(data, name) != value
    ]
    if not changed:
        return []
    for name in changed:
        put(data, name, changes[name])
    text = path.read_text(encoding="utf-8") if path.is_file() else header + "\n"
    edited: str | None = text
    for name in changed:
        edited = edit_yaml(edited, name, changes[name]) if edited is not None else None
    if edited is not None and _loads(edited) == data:
        write_public(path, edited)
        return changed
    lead = header
    if path.is_file():
        kept = []
        for line in text.splitlines(keepends=True):
            if not line.startswith("#"):
                break
            kept.append(line)
        lead = "".join(kept) or header
    body = yaml.safe_dump(data, default_flow_style=False, sort_keys=False, width=100)
    write_public(path, lead + "\n" + body)
    return changed


def _loads(text: str) -> Any:
    try:
        return yaml.safe_load(text) or {}
    except yaml.YAMLError:
        return None


def _flow(value: Any) -> str | None:
    """``value`` on one line as YAML writes it (a list in brackets); None for a mapping."""
    if isinstance(value, Mapping):
        return None
    dumped = yaml.safe_dump(value, default_flow_style=True, width=10**6).strip()
    return dumped.removesuffix("...").strip()


def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _blank(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith("#")


def _block_end(lines: list[str], start: int, indent: int) -> int:
    """The index after the block that begins below ``lines[start]``: the lines indented deeper
    than ``indent`` (blank and comment lines inside it included, trailing ones not)."""
    end = start + 1
    last = start + 1
    while end < len(lines):
        if not _blank(lines[end]):
            if _indent_of(lines[end]) <= indent and not lines[end].lstrip().startswith("- "):
                break
            if _indent_of(lines[end]) < indent:
                break
            last = end + 1
        end += 1
    return last


def _find(lines: list[str], key: str, start: int, end: int, indent: int) -> int | None:
    for i in range(start, end):
        line = lines[i]
        if _blank(line) or _indent_of(line) != indent:
            continue
        if line.lstrip().startswith(f"{key}:") and (
            line.lstrip()[len(key) + 1 : len(key) + 2] in ("", " ", "\n")
        ):
            return i
    return None


def edit_yaml(text: str, dotted: str, value: Any) -> str | None:
    """``text`` with ``dotted`` set to ``value`` by editing its lines (comments and layout kept);
    None when the file's shape is not one this can follow (the caller rewrites it whole)."""
    flow = _flow(value)
    if flow is None:
        return None
    lines = text.splitlines(keepends=True)
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    parts = dotted.split(".")
    start, end, indent = 0, len(lines), 0
    for depth, part in enumerate(parts):
        at = _find(lines, part, start, end, indent)
        if at is None:
            child = indent
            rest = parts[depth:]
            new = []
            for n, name in enumerate(rest):
                pad = " " * (child + 2 * n)
                new.append(f"{pad}{name}: {flow}\n" if n == len(rest) - 1 else f"{pad}{name}:\n")
            lines[end:end] = new
            return "".join(lines)
        line = lines[at]
        here = _indent_of(line)
        if depth == len(parts) - 1:
            after = line.lstrip()[len(part) + 1 :]
            comment = ""
            if " #" in after:
                comment = "  #" + after.split(" #", 1)[1].rstrip("\n")
            stop = _block_end(lines, at, here)
            lines[at:stop] = [f"{' ' * here}{part}: {flow}{comment}\n"]
            return "".join(lines)
        rest_of_line = line.lstrip()[len(part) + 1 :].split(" #", 1)[0].strip()
        if rest_of_line:
            return None  # a mapping written on one line: not followed here
        start, end = at + 1, _block_end(lines, at, here)
        children = [i for i in range(start, end) if not _blank(lines[i])]
        indent = _indent_of(lines[children[0]]) if children else here + 2
        if children and indent <= here:
            return None
    return None
