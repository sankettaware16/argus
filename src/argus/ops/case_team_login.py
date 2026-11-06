"""The case team's own database login as its unit uses it. ``argus-case-team.service`` reads its
switches from ``local/argus-writer.env`` and its secrets from ``local/creds-writer``, where
``database.writer_password`` is the password of the writer's login (``database.writer_user``).
``argus init`` sets the login's password from that file when the login does not log in with it,
and ``argus doctor`` checks the login with it, as a failure only while this installation runs the
case team: something starts its unit (its timer is listed in ``units.run`` or enabled) and posting
is on. Either stop is a choice: with posting off each run refuses before it logs in."""

from __future__ import annotations

import codecs
import io
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dotenv.parser import parse_stream
from pydantic import SecretStr, TypeAdapter, ValidationError

from argus.config.sources import MAX_FILE_BYTES

CREDENTIALS = Path("local/creds-writer")  # the unit's CREDENTIALS_DIRECTORY, in the checkout
CREDENTIAL = "database.writer_password"
SWITCHES = Path("local/argus-writer.env")  # the unit's EnvironmentFile
SHOWN = f"{CREDENTIALS}/{CREDENTIAL}"
TIMER = "argus-case-team.timer"
SERVICE = "argus-case-team.service"
POST = "ARGUS_CASE_TEAM__POST"
PASSWORD = "ARGUS_DATABASE__WRITER_PASSWORD"  # noqa: S105 - a variable name
USER = "ARGUS_DATABASE__WRITER_USER"
STOPS = (
    f"{POST}=false in {SWITCHES}, or `systemctl --user disable --now {TIMER}` and take it out of"
    " units.run"
)  # the two ways to stop the case team that init and doctor both count as off
MAX_BYTES = MAX_FILE_BYTES  # as the unit's settings read a credential
_BOOL: TypeAdapter[bool] = TypeAdapter(bool)


@dataclass(frozen=True)
class TeamLogin:
    password: str | None = field(repr=False)
    """The credential's value as systemd hands it to ARGUS; None when there is none."""
    problem: str | None
    """Why the credential cannot be used (``is empty`` ...), or None."""
    user: str | None
    """The login the switches file names (``ARGUS_DATABASE__WRITER_USER``), if it names one."""
    runs: tuple[str, ...]
    """Why this installation runs the case team; empty: it is off."""

    def database_update(self) -> dict[str, Any]:
        """The ``DatabaseSettings`` fields the unit sees differently from the shared settings."""
        update: dict[str, Any] = {}
        if self.password is not None:
            update["writer_password"] = SecretStr(self.password)
        if self.user:
            update["writer_user"] = self.user
        return update

    def environment(self) -> dict[str, str]:
        """The same, as environment variables (for ``argus db bootstrap``)."""
        env = {} if self.password is None else {PASSWORD: self.password}
        if self.user:
            env[USER] = self.user
        return env


def read_credential(path: Path) -> tuple[str | None, str | None]:
    """A credential file's value as ``credentials_layer`` reads it (the whole content less one
    final line break) and why it cannot be used; (None, None) when there is no file. Never the
    value in a message."""
    from argus.config.settings import usable_password

    try:
        if not path.exists():  # a link to nothing too: the unit's settings skip it
            return None, None
        if not path.is_file():  # a folder or a FIFO: the unit's settings refuse it
            return None, "is not a regular file"
        with path.open("rb") as handle:
            raw = handle.read(MAX_BYTES + 1)
    except OSError as exc:
        return None, f"cannot be read ({exc.strerror})"
    if len(raw) > MAX_BYTES:
        return None, f"is larger than {MAX_BYTES // 1024} KiB"
    try:
        text = raw.removeprefix(codecs.BOM_UTF8).decode("utf-8")
    except UnicodeDecodeError:
        return None, "is not UTF-8 text"
    value = text.removesuffix("\n").removesuffix("\r") if text.endswith("\n") else text
    if not value:
        return None, "is empty"
    try:
        usable_password(value)
    except ValueError as exc:
        return None, str(exc)
    return value, None


def read_switches(path: Path) -> dict[str, str]:
    """The variables the switches file sets; empty when there is none or it cannot be read
    (then the unit cannot start, and the units check says so)."""
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return {}
    found: dict[str, str] = {}
    for binding in parse_stream(io.StringIO(raw)):
        if binding.key is not None and binding.value is not None:
            found[binding.key] = binding.value
    return found


def posting(switches: Mapping[str, str], configured: bool) -> bool:
    """Whether the unit posts: the switches file's ``ARGUS_CASE_TEAM__POST`` (its environment
    outranks .env and YAML), else ``case_team.post`` as configured. A value that is not a
    boolean stops the unit loading its settings: it posts nothing."""
    if POST not in switches:
        return configured
    try:
        return _BOOL.validate_python(switches[POST].strip())
    except ValidationError:
        return False


def switched_off(switches: Mapping[str, str], configured: bool) -> str | None:
    """Why the unit posts nothing by choice: its switch (or ``case_team.post``) is off, so each
    run refuses before it logs in (``case team run`` exits 2). None while it posts, and for a
    switch that is not a boolean: the unit cannot load its settings, a fault and not a choice."""
    if POST not in switches:
        return None if configured else "case_team.post is false"
    try:
        on = _BOOL.validate_python(switches[POST].strip())
    except ValidationError:
        return None
    return None if on else f"{POST} is off in {SWITCHES}"


def reasons(
    run: Sequence[str] | None, enabled: Collection[str], switches: Mapping[str, str], post: bool
) -> tuple[str, ...]:
    """Why this installation runs the case team: what starts its unit (``units.run`` lists the
    timer, the timer is enabled) and that it posts (the switches file, ``case_team.post``).
    Empty when it is off: nothing starts the unit, or it posts nothing and each run refuses
    before it logs in."""
    found: list[str] = []
    if run is not None and TIMER in run:
        found.append(f"units.run lists {TIMER}")
    if TIMER in enabled:
        found.append(f"{TIMER} is enabled")
    if not found or not posting(switches, post):
        return ()
    found.append(f"{POST} is on in {SWITCHES}" if POST in switches else "case_team.post is on")
    return tuple(found)


def team_login(
    root: Path, *, run: Sequence[str] | None, enabled: Collection[str], post: bool
) -> TeamLogin:
    """The case team's login as its unit in the checkout ``root`` uses it."""
    switches = read_switches(root / SWITCHES)
    password, problem = read_credential(root / CREDENTIALS / CREDENTIAL)
    return TeamLogin(
        password=password,
        problem=problem,
        user=switches.get(USER) or None,
        runs=reasons(run, enabled, switches, post),
    )
