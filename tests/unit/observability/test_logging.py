from __future__ import annotations

import io
import json
import logging
from datetime import UTC, datetime

import pytest

from argus.observability.logs import configure_logging, get_logger
from argus.observability.redaction import register_secret

SECRET = "log-secret-9f8e7d"


@pytest.fixture
def json_stream() -> io.StringIO:
    stream = io.StringIO()
    configure_logging("DEBUG", "json", stream=stream)
    return stream


def _records(stream: io.StringIO) -> list[dict[str, object]]:
    return [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]


def test_structlog_event_is_redacted(json_stream: io.StringIO) -> None:
    register_secret(SECRET)
    get_logger("argus.test").info(
        "connecting", password="hunter2", dsn=f"postgresql://argus:{SECRET}@db/argus", note=SECRET
    )
    output = json_stream.getvalue()
    assert SECRET not in output
    assert "hunter2" not in output
    (record,) = _records(json_stream)
    assert record["event"] == "connecting"
    assert record["password"] == "***"
    assert record["level"] == "info"
    assert record["logger"] == "argus.test"


def test_stdlib_loggers_are_redacted(json_stream: io.StringIO) -> None:
    register_secret(SECRET)
    logging.getLogger("sqlalchemy.engine").warning("connect failed for %s", f"argus:{SECRET}@db")
    logging.getLogger("thirdparty").error("Authorization: ApiKey QUJDREVGR0hJSktMTU5PUA==")
    output = json_stream.getvalue()
    assert SECRET not in output
    assert "QUJDREVGR0hJSktMTU5PUA==" not in output
    assert len(_records(json_stream)) == 2


def test_exception_tracebacks_are_redacted(json_stream: io.StringIO) -> None:
    register_secret(SECRET)
    try:
        raise RuntimeError(f"cannot authenticate with {SECRET}")
    except RuntimeError:
        get_logger("argus.test").exception("failure")
    output = json_stream.getvalue()
    assert SECRET not in output
    (record,) = _records(json_stream)
    assert "RuntimeError" in str(record["exception"])


def test_timestamps_are_utc_iso(json_stream: io.StringIO) -> None:
    get_logger().info("tick")
    (record,) = _records(json_stream)
    stamp = datetime.fromisoformat(str(record["timestamp"]).replace("Z", "+00:00"))
    assert stamp.utcoffset() == UTC.utcoffset(None)


def test_level_filtering() -> None:
    stream = io.StringIO()
    configure_logging("WARNING", "json", stream=stream)
    log = get_logger("argus.test")
    log.info("hidden")
    log.warning("shown")
    logging.getLogger("other").info("hidden too")
    assert [r["event"] for r in _records(stream)] == ["shown"]


def test_reconfiguring_does_not_duplicate_output() -> None:
    stream = io.StringIO()
    configure_logging("INFO", "json", stream=stream)
    configure_logging("INFO", "json", stream=stream)
    get_logger().info("once")
    assert len(_records(stream)) == 1


def test_console_format_is_redacted() -> None:
    register_secret(SECRET)
    stream = io.StringIO()
    configure_logging("INFO", "console", stream=stream)
    get_logger("argus.test").info("hello", token=SECRET, other=f"x{SECRET}x")
    output = stream.getvalue()
    assert "hello" in output
    assert SECRET not in output


def test_noisy_third_party_loggers_are_quietened(json_stream: io.StringIO) -> None:
    logging.getLogger("alembic.runtime.migration").info("Context impl PostgresqlImpl.")
    logging.getLogger("sqlalchemy.engine.Engine").info("SELECT 1")
    assert _records(json_stream) == []
