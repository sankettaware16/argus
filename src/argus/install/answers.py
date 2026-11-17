"""Where ``argus init``'s answers come from: a person at the terminal, or an answers file
(``--answers FILE``, YAML) that answers every question and never prompts. A question the file
does not answer stops init with the answer's name; a secret is never in the file: the file names
where it is (``<name>_file``: a file holding it; ``<name>_env``: an environment variable)."""

from __future__ import annotations

import os
import stat
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol

import yaml

# Every answer a file may give, by its dotted name, and what it is (the messages name it).
KNOWN: dict[str, str] = {
    "database.compose": "true: start the database with docker compose; false: use a PostgreSQL"
    " that is already running (the .env names it)",
    "siem.url": "the SIEM's Elasticsearch address, https://host:9200",
    "siem.trust": "how the SIEM's certificate is trusted: file, chain or system",
    "siem.ca_file": "the SIEM's CA certificate file (siem.trust: file)",
    "siem.fingerprint": "the SHA-256 fingerprint of the CA the SIEM presents (siem.trust: chain)",
    "siem.api_key_file": "a file holding the read-only API key (the encoded form)",
    "siem.api_key_env": "an environment variable holding the read-only API key",
    "siem.api_key_expires": "when the key expires: YYYY-MM-DD, the answer's expiration or 90d",
    "siem.log_patterns": "the index patterns of the logs, for the starting role (default logs-*)",
    "elastic.admin_user": "an Elastic administrator's user name: init makes ARGUS's read-only keys"
    " with it (used once, never stored), or none to paste the keys",
    "elastic.admin_password_file": "a file holding that administrator's password",
    "elastic.admin_password_env": "an environment variable holding that administrator's password",
    "case_team.provision": "true: with the administrator's login, also make the Kibana case"
    " team's users and keys (posting stays off)",
    "kibana.url": "Kibana's address, https://host:5601, or none",
    "kibana.trust": "how Kibana's certificate is trusted: same (the SIEM's CA), file, chain or"
    " system",
    "kibana.ca_file": "Kibana's CA certificate file (kibana.trust: file)",
    "kibana.fingerprint": "the SHA-256 fingerprint of the CA Kibana presents (kibana.trust: chain)",
    "kibana.api_key_file": "a file holding Kibana's read-only API key, or none",
    "kibana.api_key_env": "an environment variable holding Kibana's read-only API key",
    "kibana.api_key_expires": "when Kibana's key expires: YYYY-MM-DD, the answer's expiration"
    " or 90d",
    "organisation.name": "the organisation's name",
    "organisation.short_name": "the security team's name (page header, PDF footer)",
    "organisation.kind": "what kind of organisation it is, a lower-case noun (default"
    " organisation)",
    "organisation.own_domains": "the organisation's own domains (at least one)",
    "organisation.own_networks": "the organisation's public networks, CIDR (may be empty)",
    "organisation.timezone": "the zone people read times in, an IANA name (Europe/Berlin)",
    "organisation.timezone_label": "how a time in that zone is labelled (CET), or none",
    "organisation.incident_id_prefix": "the prefix of incident case ids (SOC-IR)",
    "organisation.space": "the Kibana space that holds the Security alerts",
    "discovery.accept": "true: write what `argus discover` proposes to config/site.yaml",
    "llm.keys_file": "the LLM providers' keys file, or none (every LLM feature off)",
    "web.address": "the address people open the web at (this machine's IP or name), or none for"
    " the loopback only",
    "web.ca_cert": "a CA certificate to sign the web's certificate with, or none (self-signed)",
    "web.ca_key": "that CA's private key file (read once, never copied)",
    "web.networks": "the networks people open the web from, CIDR",
    "web.person": "the first person's sign-in name, or none",
    "web.person_name": "the first person's name as ARGUS shows it",
    "web.person_password_file": "a file holding the first person's password",
    "web.person_password_env": "an environment variable holding the first person's password",
    "units.install": "true: install the systemd user units",
    "units.start": "true: enable and start the services",
    "units.backups": "true: the nightly database backup and the weekly restore drill (when"
    " starting)",
}
NONE_WORDS = frozenset({"", "none", "no", "-"})


class InitError(Exception):
    """Init stops here; ``code`` is its exit code (2: an answer or the usage, 1: a step)."""

    def __init__(self, message: str, code: int = 1) -> None:
        super().__init__(message)
        self.code = code


class MissingAnswerError(InitError):
    def __init__(self, name: str, source: Path) -> None:
        what = KNOWN.get(name, name)
        super().__init__(f"{source} does not answer {name} ({what})", code=2)
        self.name = name


class Asker(Protocol):
    """One question at a time; ``name`` is the answer's dotted name."""

    scripted: bool

    def given(self, name: str) -> bool: ...

    def text(self, name: str, question: str, default: str | None = None) -> str: ...

    def optional(self, name: str, question: str, default: str | None = None) -> str | None: ...

    def items(self, name: str, question: str, default: Sequence[str] = ()) -> list[str]: ...

    def secret(self, name: str, question: str, *, required: bool = True) -> str | None: ...

    def confirm(self, name: str, question: str, default: bool) -> bool: ...

    def choose(
        self, name: str, question: str, options: Sequence[str], default: str | None
    ) -> str: ...


# --------------------------------------------------------------------------- the file


def _flatten(data: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in data.items():
        name = f"{prefix}{key}"
        if isinstance(value, Mapping):
            out |= _flatten(value, f"{name}.")
        else:
            out[name] = value
    return out


def load_answers(path: Path) -> dict[str, Any]:
    """The answers of a YAML file, by dotted name. InitError (code 2) when the file cannot be
    read, an answer's name is unknown, or a secret is written in it."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise InitError(f"cannot read the answers file {path}: {type(exc).__name__}", 2) from None
    if data is None:
        data = {}
    if not isinstance(data, Mapping):
        raise InitError(f"{path} is not a YAML mapping of answers", 2)
    flat = _flatten(data)
    for secret in ("siem.api_key", "kibana.api_key", "kibana.reader_api_key",
                   "web.person_password"):  # fmt: skip
        if secret in flat:
            raise InitError(
                f"{path} gives {secret} itself: a key never goes in the answers file; name a file"
                f" ({secret}_file) or an environment variable ({secret}_env) instead",
                2,
            )
    unknown = sorted(set(flat) - set(KNOWN))
    if unknown:
        raise InitError(f"{path}: unknown answers {', '.join(unknown)}", 2)
    return flat


def _words(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, (list, tuple)):
        return [str(part).strip() for part in value if str(part).strip()]
    return [str(value)]


class ScriptedAnswers:
    """Answers from a file; never prompts."""

    scripted = True

    def __init__(
        self,
        answers: Mapping[str, Any],
        source: Path,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self.answers = dict(answers)
        self.source = source
        self.environ = os.environ if environ is None else environ

    def given(self, name: str) -> bool:
        return name in self.answers

    def _missing(self, name: str) -> MissingAnswerError:
        return MissingAnswerError(name, self.source)

    def text(self, name: str, question: str, default: str | None = None) -> str:
        value = self.answers.get(name)
        if value is None or str(value).strip() == "":
            if default is not None:
                return default
            raise self._missing(name)
        return str(value).strip()

    def optional(self, name: str, question: str, default: str | None = None) -> str | None:
        if name not in self.answers:
            return default
        value = self.answers[name]
        if value is None or str(value).strip().lower() in NONE_WORDS:
            return None
        return str(value).strip()

    def items(self, name: str, question: str, default: Sequence[str] = ()) -> list[str]:
        if name not in self.answers:
            return list(default)
        return _words(self.answers[name])

    def secret(self, name: str, question: str, *, required: bool = True) -> str | None:
        file_name, env_name = f"{name}_file", f"{name}_env"
        named_file = self.answers.get(file_name)
        named_env = self.answers.get(env_name)
        if named_file is not None and str(named_file).strip().lower() in NONE_WORDS:
            named_file = None
            if not required:
                return None
        if named_file is not None:
            path = Path(str(named_file)).expanduser()
            try:
                if path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                    raise InitError(f"{file_name}: {path} is readable by others (chmod 600)", 2)
                value = path.read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise InitError(f"{file_name}: cannot read {path} ({exc.strerror})", 2) from None
            if not value:
                raise InitError(f"{file_name}: {path} is empty", 2)
            return value
        if named_env is not None:
            value = self.environ.get(str(named_env), "").strip()
            if not value:
                raise InitError(f"{env_name}: the variable {named_env} is not set", 2)
            return value
        if required:
            raise InitError(
                f"{self.source} does not answer {file_name} or {env_name}"
                f" ({KNOWN.get(file_name, name)})",
                2,
            )
        return None

    def confirm(self, name: str, question: str, default: bool) -> bool:
        if name not in self.answers or self.answers[name] is None:
            return default
        value = self.answers[name]
        if isinstance(value, bool):
            return value
        text = str(value).strip().lower()
        if text in ("yes", "y", "true", "on", "1"):
            return True
        if text in ("no", "n", "false", "off", "0"):
            return False
        raise InitError(f"{self.source}: {name} is true or false, not {value!r}", 2)

    def choose(self, name: str, question: str, options: Sequence[str], default: str | None) -> str:
        value = self.text(name, question, default)
        if options and value not in options:
            raise InitError(f"{self.source}: {name} is one of {', '.join(options)}", 2)
        return value


# --------------------------------------------------------------------------- the terminal


Prompt = Callable[..., Any]


class TerminalAnswers:
    """A person at the terminal (``typer.prompt``); Enter keeps the value in brackets."""

    scripted = False

    def __init__(self, prompt: Prompt | None = None, confirm: Prompt | None = None) -> None:
        import typer

        self._prompt = prompt or typer.prompt
        self._confirm = confirm or typer.confirm

    def given(self, name: str) -> bool:
        return False

    def text(self, name: str, question: str, default: str | None = None) -> str:
        while True:
            value = str(self._prompt(question, default=default)).strip()
            if value:
                return value

    def optional(self, name: str, question: str, default: str | None = None) -> str | None:
        value = str(self._prompt(f"{question} (none to skip)", default=default or "none"))
        return None if value.strip().lower() in NONE_WORDS else value.strip()

    def items(self, name: str, question: str, default: Sequence[str] = ()) -> list[str]:
        shown = ", ".join(default) if default else "none"
        value = str(self._prompt(f"{question} (comma-separated)", default=shown))
        return [] if value.strip().lower() in NONE_WORDS else _words(value)

    def secret(self, name: str, question: str, *, required: bool = True) -> str | None:
        while True:
            hint = "" if required else " (Enter to skip)"
            value = str(
                self._prompt(f"{question}{hint}", default="", hide_input=True, show_default=False)
            ).strip()
            if value or not required:
                return value or None

    def confirm(self, name: str, question: str, default: bool) -> bool:
        return bool(self._confirm(question, default=default))

    def choose(self, name: str, question: str, options: Sequence[str], default: str | None) -> str:
        while True:
            value = self.text(name, f"{question} ({', '.join(options)})", default)
            if not options or value in options:
                return value
