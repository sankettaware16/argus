"""Adversarial tests: secret leakage and redaction robustness (C1 foundation).

Every credential-looking value in this file is synthetic. Tests whose docstring starts with
"DEFECT" currently fail and document a gap against the C1 guarantees; the others lock in
behaviour that works today but had no test.
"""

from __future__ import annotations

import dataclasses
import io
import json
import logging
import os
import signal
import socket
import subprocess
import sys
import textwrap
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
import structlog
from pydantic import BaseModel, SecretStr
from typer.testing import CliRunner

from argus.cli import app
from argus.config.settings import DatabaseSettings, Settings
from argus.db.engine import create_engine
from argus.observability.logs import configure_logging, get_logger
from argus.observability.redaction import (
    MASK,
    is_sensitive_key,
    redact,
    redact_text,
    register_secret,
)

SECRET = "fake-secret-Adv7Q9w2"  # registered where a test needs value-based masking
UNREG = "fake-unreg-K3y9Zz77a"  # never registered: only shape / key-name rules can catch it
UNREG2 = "fake-unreg-B8n2Xx41b"
UNREG3 = "fake-unreg-C5m6Yy03c"
CLI_SECRET = "fake-cli-pw-Adv4410"
CLI_OWNER_SECRET = "fake-cli-owner-pw-Adv5521"
FAKE_ES_APIKEY = "VnVhQ2ZHY0JDZGJrUW0tZTVhT3g6dWkybHAyYXhUTm1zeWFrdzl0dk5udw=="

runner = CliRunner()


# --------------------------------------------------------------------------- helpers


@pytest.fixture
def json_stream() -> Iterator[io.StringIO]:
    stream = io.StringIO()
    configure_logging("DEBUG", "json", stream=stream)
    yield stream
    structlog.contextvars.clear_contextvars()
    configure_logging("WARNING", "console", stream=io.StringIO())


def _records(stream: io.StringIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]


def _argus_handlers_only(stream: io.StringIO) -> None:
    """Re-run configure_logging inside the test body.

    pytest attaches its own capture handler to the root logger for the call phase, and that
    handler re-raises formatting errors. Reconfiguring here leaves only ARGUS's handler, so the
    test observes exactly what a real process would print.
    """
    configure_logging("DEBUG", "json", stream=stream)


class _TookTooLongError(BaseException):
    """BaseException on purpose: redact()'s ``except Exception`` must not swallow the deadline."""


@contextmanager
def _hard_deadline(seconds: float) -> Iterator[None]:
    """Interrupt the block after ``seconds`` (the regex engine checks signals while matching)."""

    def _expire(_signum: int, _frame: object) -> None:
        raise _TookTooLongError

    previous = signal.signal(signal.SIGALRM, _expire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _seconds(fn: Callable[[], object], hard_limit: float = 2.0) -> float:
    """Wall time of ``fn()``; ``inf`` if it had to be interrupted at ``hard_limit``."""
    start = time.perf_counter()
    try:
        with _hard_deadline(hard_limit):
            fn()
    except _TookTooLongError:
        return float("inf")
    return time.perf_counter() - start


def _closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


# --------------------------------------------------------------------------- key=value text rule


_KEY_VALUE_LEAKS = {  # id: (sensitive key name, text containing it)
    "argus-env-file-line": ("ARGUS_DATABASE__PASSWORD", "ARGUS_DATABASE__PASSWORD={s}"),
    "argus-c2-api-key-line": ("ARGUS_ELASTIC__API_KEY", "ARGUS_ELASTIC__API_KEY={s}"),
    "snake-case-prefix": ("db_password", "retrying with db_password={s} against db.internal"),
    "oauth-query-string": (
        "access_token",
        "GET https://api.example.org/v1/items?access_token={s}&page=2",
    ),
    "oauth-token-response": (
        "access_token",
        '{{"access_token": "{s}", "token_type": "bearer"}}',
    ),
    "aws-env-var": ("AWS_SECRET_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY={s}"),
    "authorization-json-without-scheme": ("authorization", '{{"authorization": "{s}"}}'),
    "cookie-header": ("Cookie", "Cookie: sid={s}"),
}


@pytest.mark.parametrize(
    ("key", "template"), list(_KEY_VALUE_LEAKS.values()), ids=list(_KEY_VALUE_LEAKS)
)
def test_key_value_text_masks_prefixed_and_compound_sensitive_names(
    key: str, template: str
) -> None:
    """DEFECT: the text key=value rule anchors key names with ``\\b``, so ``__PASSWORD=``,
    ``_API_KEY=``, ``db_password=`` and ``access_token=`` never match (``_`` is a word
    character), and its key list omits names the key-name rule itself treats as secret
    (authorization, cookie). Every key here is already sensitive per ``is_sensitive_key``;
    these are the formats of ARGUS's own .env lines, OAuth responses and HTTP headers."""
    assert is_sensitive_key(key), key
    out = redact_text(template.format(s=UNREG))
    assert UNREG not in out
    assert MASK in out


@pytest.mark.parametrize(
    ("text", "leaked_fragment"),
    [
        ('password="correct horse battery staple"', "horse battery staple"),
        ("client_secret='Adv;quoted,value&9'", "quoted,value"),
    ],
    ids=["passphrase-with-spaces", "separators-inside-quotes"],
)
def test_quoted_secret_values_are_masked_up_to_the_closing_quote(
    text: str, leaked_fragment: str
) -> None:
    """DEFECT: the value part stops at the first space or ``& , ; ' "`` even inside quotes, so
    only the first word of a quoted passphrase is masked: ``password="*** horse battery
    staple"``."""
    out = redact_text(text)
    assert leaked_fragment not in out
    assert MASK in out


# --------------------------------------------------------------------------- key-name rule


@pytest.mark.parametrize(
    "key",
    [
        "accessToken",
        "refreshToken",
        "newPassword",
        "apiSecret",
        "secret_key",
        "PGPASSWORD",
        "passphrase",
    ],
)
def test_common_sensitive_key_styles_are_masked(key: str) -> None:
    """DEFECT: key-name redaction only recognises a sensitive word after ``_ - .`` or at the start
    and only at the very end, so camelCase JSON keys (accessToken, newPassword), ``secret_key``,
    ``PGPASSWORD`` and ``passphrase`` are logged and audited in clear."""
    assert redact({key: UNREG}) == {key: MASK}


def test_bytes_mapping_keys_are_checked_by_name() -> None:
    """DEFECT: ``is_sensitive_key`` ignores non-str keys, so ``dict(request.headers.raw)``-style
    mappings with bytes keys keep their secret values."""
    out = str(redact({b"password": UNREG, b"x-api-key": UNREG2}))
    assert UNREG not in out
    assert UNREG2 not in out


# --------------------------------------------------------------------------- URL / Authorization


@pytest.mark.parametrize(
    "url",
    [
        "redis://:{s}@cache.internal:6379/0",
        "postgresql://:{s}@db.internal:5432/argus",
        "https://elastic:p@{s}@10.0.0.9:9200/_search",
    ],
    ids=["redis-empty-username", "postgres-empty-username", "at-sign-in-password"],
)
def test_url_userinfo_password_is_fully_masked(url: str) -> None:
    """DEFECT: the userinfo rule needs a non-empty username and stops the password at the first
    ``@``. ``redis://:pw@host`` (the canonical Redis form) leaks entirely and
    ``user:p@ss@host`` (how urllib/httpx parse an unencoded ``@``) leaks everything after it."""
    out = redact_text(url.format(s=UNREG))
    assert UNREG not in out
    assert "@" in out


@pytest.mark.parametrize(
    "header",
    [
        "authorization: bearer {s}",
        "AUTHORIZATION: BEARER {s}",
        "Authorization: basic {s}",
    ],
    ids=["lowercase-bearer", "uppercase-bearer", "lowercase-basic"],
)
def test_authorization_scheme_is_matched_case_insensitively(header: str) -> None:
    """DEFECT: HTTP auth schemes are case-insensitive (RFC 7235) but the rule matches only
    ``Bearer``/``Basic``/``ApiKey``/``Token`` exactly, so ``bearer <token>`` is logged in clear."""
    assert UNREG not in redact_text(header.format(s=UNREG))


# --------------------------------------------------------------------------- structured values


@dataclasses.dataclass(frozen=True)
class _ElasticCredentials:
    host: str
    username: str
    db_password: str
    access_token: str


class _ProviderConfig(BaseModel):
    name: str
    base_url: str
    api_token: str
    es_password: str


def test_dataclass_fields_are_redacted_by_key_name(json_stream: io.StringIO) -> None:
    """DEFECT: dataclasses are redacted only through their repr text, where the key=value rule
    misses ``db_password=``/``access_token=``; the dict path would have masked both fields."""
    creds = _ElasticCredentials(
        host="10.0.0.9", username="argus_ro", db_password=UNREG, access_token=UNREG2
    )
    get_logger("argus.test").info("connecting", creds=creds)
    out = json_stream.getvalue()
    assert UNREG not in out
    assert UNREG2 not in out
    assert "argus_ro" in out


def test_pydantic_model_fields_are_redacted_by_key_name() -> None:
    """DEFECT: same gap for pydantic models with plain ``str`` secret fields (``api_token``,
    ``es_password``) passed as log values or audit details; as dict keys both are masked."""
    assert redact({"api_token": UNREG, "es_password": UNREG2}) == {
        "api_token": MASK,
        "es_password": MASK,
    }
    provider = _ProviderConfig(
        name="groq", base_url="https://api.example.org", api_token=UNREG, es_password=UNREG2
    )
    out = str(redact({"provider": provider}))
    assert UNREG not in out
    assert UNREG2 not in out
    assert "groq" in out


def test_registered_secret_is_masked_in_its_repr_escaped_form(json_stream: io.StringIO) -> None:
    """DEFECT: registered secrets are matched verbatim only. A password containing a backslash
    appears doubled inside any repr (a dict/tuple logged with %r or %s, an exception built
    with !r), so the configured password is printed."""
    password = "Tr0ub4dor\\&3-adv"
    register_secret(password)
    logging.getLogger("thirdparty.pool").warning(
        "connect args %r", {"user": "argus", "pw": password}
    )
    assert "Tr0ub4dor" not in json_stream.getvalue()


# --------------------------------------------------------------------------- logging pipeline


def test_bad_format_string_in_a_log_call_does_not_print_raw_arguments(
    json_stream: io.StringIO, capsys: pytest.CaptureFixture[str]
) -> None:
    """DEFECT: when a stdlib record cannot be formatted, logging.Handler.handleError writes
    ``Arguments: (...)`` with the raw, unredacted args straight to sys.stderr."""
    _argus_handlers_only(json_stream)
    register_secret(SECRET)
    logging.getLogger("thirdparty.client").error("connect timeout after %d s", SECRET)
    captured = capsys.readouterr()
    assert SECRET not in captured.err + captured.out + json_stream.getvalue()


def test_render_failure_does_not_print_raw_arguments(
    json_stream: io.StringIO, capsys: pytest.CaptureFixture[str]
) -> None:
    """DEFECT: same leak through a renderer failure — an ``extra`` dict with int and str keys
    makes JSONRenderer(sort_keys=True) raise, and handleError prints the raw args."""
    _argus_handlers_only(json_stream)
    register_secret(SECRET)
    logging.getLogger("thirdparty.client").warning(
        "authenticated as %s", SECRET, extra={"status_counts": {200: 41, "other": 2}}
    )
    captured = capsys.readouterr()
    assert SECRET not in captured.err + captured.out + json_stream.getvalue()


def test_json_log_with_mixed_key_types_is_not_dropped(
    json_stream: io.StringIO, capsys: pytest.CaptureFixture[str]
) -> None:
    """DEFECT: redaction keeps non-str keys as they are, so a value like ``{200: 41, 'other': 2}``
    crashes the JSON renderer and the whole record is lost ("--- Logging error ---")."""
    _argus_handlers_only(json_stream)
    get_logger("argus.test").info("http status counts", by_status={200: 41, "other": 2})
    assert [r["event"] for r in _records(json_stream)] == ["http status counts"]
    assert "Logging error" not in capsys.readouterr().err


class _ClosedShelf(Mapping[str, Any]):
    """Behaves like ``shelve.Shelf`` after ``close()``: every access raises."""

    def __getitem__(self, key: str) -> Any:
        raise ValueError("invalid operation on closed shelf")

    def __iter__(self) -> Iterator[str]:
        raise ValueError("invalid operation on closed shelf")

    def __len__(self) -> int:
        raise ValueError("invalid operation on closed shelf")


def test_one_unreadable_value_does_not_drop_the_whole_log_record(
    json_stream: io.StringIO,
) -> None:
    """DEFECT: a broken repr only affects its own value (existing test), but a mapping that
    raises while iterated makes redact() fail wholesale and the entire event is replaced."""
    get_logger("argus.test").info("cache snapshot", ok="fine", cache=_ClosedShelf())
    (record,) = _records(json_stream)
    assert record["event"] == "cache snapshot"
    assert record["ok"] == "fine"


def test_python_warnings_go_through_redaction(tmp_path: Path) -> None:
    """DEFECT: configure_logging does not capture the warnings module, so a warning carrying a
    DSN is written to stderr raw, bypassing redaction (in a real process, not under pytest)."""
    code = textwrap.dedent(
        f"""
        import warnings
        from argus.observability.logs import configure_logging
        from argus.observability.redaction import register_secret
        register_secret({SECRET!r})
        configure_logging("INFO", "json")
        warnings.warn("retrying postgresql://argus:{SECRET}@db.internal/argus", UserWarning)
        """
    )
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("ARGUS_")}
    proc = subprocess.run(  # noqa: S603 - fixed interpreter and code
        [sys.executable, "-W", "always::UserWarning", "-c", code],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=tmp_path,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "retrying" in proc.stderr  # the warning is still reported...
    assert SECRET not in proc.stderr + proc.stdout  # ...but redacted


def test_chained_grouped_and_annotated_exceptions_are_redacted(json_stream: io.StringIO) -> None:
    register_secret(SECRET)
    try:
        try:
            raise KeyError(f"password={UNREG}")
        except KeyError as cause:
            group = ExceptionGroup(
                "batch failed",
                [ValueError(SECRET), TypeError(f"Authorization: Bearer {UNREG2}")],
            )
            group.add_note(f"dsn=postgresql://argus:{UNREG3}@db.internal/argus")
            raise group from cause
    except ExceptionGroup:
        get_logger("argus.test").exception("batch failed")
    out = json_stream.getvalue()
    for value in (SECRET, UNREG, UNREG2, UNREG3):
        assert value not in out
    (record,) = _records(json_stream)
    assert "direct cause" in record["exception"]
    assert "ExceptionGroup" in record["exception"]
    assert "dsn=postgresql://argus:" in record["exception"]


def test_stdlib_records_redact_exc_info_stack_info_and_extra(json_stream: io.StringIO) -> None:
    register_secret(SECRET)
    try:
        try:
            raise OSError(f"cannot read {SECRET}")
        except OSError:
            raise RuntimeError("while loading credentials")  # noqa: B904 - implicit __context__
    except RuntimeError:
        logging.getLogger("elastic_transport").error(
            "request failed: %s",
            f"token={UNREG}",
            exc_info=True,
            stack_info=True,
            extra={"headers": {"Authorization": f"ApiKey {FAKE_ES_APIKEY}"}, "api_key": UNREG2},
        )
    out = json_stream.getvalue()
    for value in (SECRET, UNREG, UNREG2, FAKE_ES_APIKEY):
        assert value not in out
    (record,) = _records(json_stream)
    assert record["event"] == f"request failed: token={MASK}"
    assert "During handling" in record["exception"]
    assert "stack" in record


def test_logger_names_event_names_and_keys_are_redacted(json_stream: io.StringIO) -> None:
    register_secret(SECRET)
    get_logger(f"argus.{SECRET}").info(
        f"login as {SECRET}",
        url=f"https://elastic:{UNREG}@10.0.0.9:9200",
        **{f"user_{SECRET}": "x"},
    )
    out = json_stream.getvalue()
    assert SECRET not in out
    assert UNREG not in out
    (record,) = _records(json_stream)
    assert record["logger"] == f"argus.{MASK}"


def test_positional_args_contextvars_and_bound_values_are_redacted(
    json_stream: io.StringIO,
) -> None:
    register_secret(SECRET)
    structlog.contextvars.bind_contextvars(request_token=UNREG)
    log = get_logger("argus.test", api_key=UNREG2)
    log.info("connecting to %s with %s", f"https://elastic:{UNREG3}@10.0.0.9:9200", SECRET)
    out = json_stream.getvalue()
    for value in (SECRET, UNREG, UNREG2, UNREG3):
        assert value not in out
    (record,) = _records(json_stream)
    assert record["request_token"] == MASK
    assert record["api_key"] == MASK


# --------------------------------------------------------------------------- ReDoS / scale

_KB200 = 200_000

_ADVERSARIAL_INPUTS = {
    # URL-userinfo rule, scheme part: long runs of scheme characters with many word boundaries
    "url-scheme-dotted-labels": ".".join(["aGVsbG8"] * (_KB200 // 8)),
    "url-scheme-hyphen-run": "a-" * (_KB200 // 2),
    "url-scheme-provider-prefix-run": "sk-" * (_KB200 // 3),
    # URL-userinfo rule, userinfo part
    "url-userinfo-without-at": "a://b:" + "c" * _KB200,
    "url-userinfo-repeated": "a://b:" * (_KB200 // 6),
    # key=value rule
    "key-then-spaces": "password" + " " * _KB200 + "x",
    "key-equals-then-spaces": "password=" + " " * _KB200,
    "repeated-keys": "token:" * (_KB200 // 6),
    # Authorization rule
    "scheme-then-spaces": "Bearer" + " " * _KB200,
    # PEM rule
    "pem-without-end": "-----BEGIN PRIVATE KEY-----" + "A" * _KB200,  # fake-secret
    "pem-many-begins": "-----BEGIN " * (_KB200 // 11),
    "pem-many-ends": "-----BEGIN PRIVATE KEY-----" + "-----END " * (_KB200 // 9),  # fake-secret
    # provider rules
    "groq-prefix-run": "gsk_" * (_KB200 // 4),
    # plain text
    "prose": ("the quick brown fox jumps over the lazy dog " * 5000)[:_KB200],
}


@pytest.mark.parametrize(
    "payload", list(_ADVERSARIAL_INPUTS.values()), ids=list(_ADVERSARIAL_INPUTS)
)
def test_redaction_of_200kb_adversarial_input_is_fast(payload: str) -> None:
    """DEFECT for the url-scheme-* cases: ``\\b[a-zA-Z][a-zA-Z0-9+.\\-]*://`` rescans the rest of
    the run from every word boundary, so redaction is quadratic (200 KB of ``a-a-a-`` takes
    ~13 s, dotted base64 labels ~3 s). Log/alert content is attacker-controlled (URLs, DNS
    names), and logging is synchronous on the event loop. The other cases lock in linear time."""
    assert _seconds(lambda: redact_text(payload)) < 1.0


def test_large_and_deep_values_are_redacted_quickly_without_crashing() -> None:
    register_secret(SECRET)
    wide = [f"item-{i} {SECRET}" for i in range(50_000)]
    deep: Any = {"password": UNREG}
    for _ in range(10_000):
        deep = {"child": deep}

    class _Node:
        def __init__(self) -> None:
            self.child: _Node | None = None

        def __repr__(self) -> str:
            return f"_Node({self.child!r})"

    chain = _Node()
    tail = chain
    for _ in range(5_000):
        tail.child = _Node()
        tail = tail.child

    results: dict[str, Any] = {}

    def _run() -> None:
        results["wide"] = redact(wide)
        results["deep"] = redact(deep)
        results["chain"] = redact({"tree": chain})

    assert _seconds(_run, hard_limit=4.0) < 2.0
    assert len(results["wide"]) == 50_000
    assert SECRET not in str(results["wide"][:100])
    assert UNREG not in str(results["deep"])
    assert results["chain"] == {"tree": "<unrepresentable>"}


# --------------------------------------------------------------------------- false positives


@pytest.mark.parametrize(
    "text",
    [
        "GET https://10.0.0.9:9200/acme-logs-2026.10.05/_search?size=10 returned 200",
        "cloning ssh://git@github.com:22/org/repo.git",
        "llm usage token_count=5 max_tokens=4096 tokens=12",
        "sha256=3f9a0c1b2d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5061728394a5b6c7d8e",
        '{"_index": "acme-logs-2026.10.05", "_id": "Kx9vZ5IBc-3tLqWqX1yQ"}',
        "alert 0b9c5a8e-4b7e-4f43-9d5e-2f1a7c3e8d90 acknowledged by ra-team",
        "password_policy=strict secretary=alice authority=campus-ca",
        "http://kibana.internal:5601/app/discover#/?_a=(query:'user@example.org')",
    ],
    ids=[
        "url-without-credentials",
        "url-with-username-only",
        "token-counters",
        "hex-digest",
        "es-document-id",
        "kibana-alert-uuid",
        "lookalike-key-names",
        "at-sign-in-query",
    ],
)
def test_ordinary_log_text_is_kept_intact(text: str) -> None:
    assert redact_text(text) == text


@pytest.mark.parametrize(
    "text",
    [
        "Elastic cluster runs on the Basic licence; ML jobs are unavailable",
        "Basic authentication failed for user bob",
        "Token refreshed successfully for connector es-prod",
    ],
    ids=["basic-licence", "basic-authentication", "token-in-prose"],
)
def test_auth_scheme_words_in_plain_prose_are_kept(text: str) -> None:
    """DEFECT (false positive): any ``Basic``/``Token``/``Bearer`` followed by a 6+ letter word is
    treated as a credential, so ordinary prose — including this project's own "Basic licence" —
    is replaced by ``***``."""
    assert redact_text(text) == text


# --------------------------------------------------------------------------- URL & settings


def test_database_url_engine_and_settings_never_render_the_password() -> None:
    password = "fake-db-pw-Adv5521"
    database = DatabaseSettings(password=SecretStr(password))
    settings = Settings(database=database)
    url = database.url()
    engine = create_engine(database)
    renderings = [
        repr(url),
        str(url),
        f"{url}",
        repr(engine.sync_engine),
        str(engine.url),
        repr(database),
        str(database),
        repr(settings),
        str(settings),
        settings.model_dump_json(),
        json.dumps(settings.model_dump(mode="json")),
        repr(settings.model_dump()),
    ]
    for rendering in renderings:
        assert password not in rendering
    assert url.password == password  # the real value is still available to the driver


# --------------------------------------------------------------------------- CLI


@pytest.fixture
def offline_config(tmp_path: Path) -> Path:
    """A config that points at a closed local port and a database name that never exists."""
    path = tmp_path / "argus.yaml"
    path.write_text(
        "history:\n  window: 4d\n"
        "database:\n"
        "  host: 127.0.0.1\n"
        f"  port: {_closed_port()}\n"
        "  name: argus_adv_never_created\n"
        "  connect_timeout: 1s\n"
        "logging:\n  level: DEBUG\n"
    )
    return path


_CLI_COMMANDS = {
    "config-show": (["config", "show"], 0),
    "config-validate": (["config", "validate"], 0),
    "db-current": (["db", "current"], 1),
    "db-check": (["db", "check"], 1),
    "db-upgrade": (["db", "upgrade"], 1),
    "db-downgrade": (["db", "downgrade", "base", "--yes"], 1),
    "doctor": (["doctor"], 1),
}


@pytest.mark.parametrize("source", ["dotenv", "environment"])
@pytest.mark.parametrize("command", list(_CLI_COMMANDS))
def test_cli_never_prints_the_database_password(
    offline_config: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: str,
    command: str,
) -> None:
    if source == "dotenv":
        (tmp_path / ".env").write_text(
            f"ARGUS_DATABASE__PASSWORD={CLI_SECRET}\n"
            f"ARGUS_DATABASE__OWNER_PASSWORD={CLI_OWNER_SECRET}\n"
        )
    else:
        monkeypatch.setenv("ARGUS_DATABASE__PASSWORD", CLI_SECRET)
        monkeypatch.setenv("ARGUS_DATABASE__OWNER_PASSWORD", CLI_OWNER_SECRET)
    args, expected_code = _CLI_COMMANDS[command]
    result = runner.invoke(app, [*args, "-c", str(offline_config)])
    output = result.output + result.stderr
    assert result.exit_code == expected_code, output
    assert CLI_SECRET not in output
    assert CLI_OWNER_SECRET not in output
    assert "Traceback" not in output


@pytest.mark.parametrize("where", ["environment", "dotenv"])
def test_malformed_section_variable_is_a_clean_config_error(
    offline_config: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, where: str
) -> None:
    """DEFECT: ``ARGUS_DATABASE=argus`` (an easy typo for ARGUS_DATABASE__NAME) makes
    pydantic-settings raise SettingsError, which load_settings does not convert to ConfigError:
    every command dies with a traceback and exit code 1 instead of a config error (exit 2).
    Unreadable or non-UTF-8 .env files fail the same way."""
    if where == "environment":
        monkeypatch.setenv("ARGUS_DATABASE__PASSWORD", CLI_SECRET)
        monkeypatch.setenv("ARGUS_DATABASE", "argus")
    else:
        (tmp_path / ".env").write_text(
            f"ARGUS_DATABASE__PASSWORD={CLI_SECRET}\nARGUS_DATABASE=argus\n"
        )
    result = runner.invoke(app, ["config", "validate", "-c", str(offline_config)])
    assert result.exit_code == 2
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "error" in result.stderr.lower()
    assert CLI_SECRET not in result.output + result.stderr


def test_config_show_masks_credentials_inside_string_settings(
    offline_config: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DEFECT: ``config show`` says "secrets masked" but echoes string settings verbatim; a DSN
    pasted into ``database.host`` prints the configured password (the output is not passed
    through redact_text even though the password is registered)."""
    monkeypatch.setenv("ARGUS_DATABASE__PASSWORD", CLI_SECRET)
    monkeypatch.setenv(
        "ARGUS_DATABASE__HOST", f"postgresql://argus:{CLI_SECRET}@db.internal:5432/argus"
    )
    result = runner.invoke(app, ["config", "show", "-c", str(offline_config)])
    assert result.exit_code == 0
    assert "secrets masked" in result.output
    assert CLI_SECRET not in result.output
