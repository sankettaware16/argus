"""Structured logging for ARGUS (structlog), with every record passing through redaction.

ARGUS's own loggers, third-party stdlib loggers (SQLAlchemy, Alembic, httpx, elasticsearch) and
Python warnings are rendered by the same processor chain, so no path bypasses redaction. Neither
failure path prints raw arguments: a record that cannot be formatted is degraded to its message
template, and one that cannot be written is replaced by a fixed notice.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import Mapping, MutableMapping
from typing import Any, TextIO, override

import structlog
from structlog.types import EventDict, Processor, WrappedLogger

from argus.observability.redaction import distinct_keys, redact, redact_text

_NOISY_LOGGERS = ("alembic", "asyncio", "sqlalchemy.engine", "sqlalchemy.pool", "httpx", "httpcore")
_RECORD_ATTRIBUTES = frozenset(vars(logging.makeLogRecord({})))


def redact_event(_logger: WrappedLogger, _method: str, event_dict: EventDict) -> EventDict:
    """structlog processor: redact every value of the event dict (including exceptions).

    Keys of nested mappings become text, so a JSON renderer can sort them ({200: 41, "x": 2});
    keys that become equal are all kept ({1: "a", "1": "b"} -> {"1 (int)": "a", "1": "b"}).
    """
    redacted = redact(dict(event_dict))
    if not isinstance(redacted, MutableMapping):  # redaction failed wholesale
        return {"event": "<log record dropped: redaction failed>", "level": event_dict.get("level")}
    return _text_keyed(redacted)


def _text_keyed(mapping: Mapping[Any, Any]) -> dict[str, Any]:
    entries = list(mapping.items())
    keys = distinct_keys([(key, _key_text(key)) for key, _ in entries])
    return {key: _with_text_keys(item) for key, (_, item) in zip(keys, entries, strict=True)}


def _with_text_keys(value: Any) -> Any:
    if isinstance(value, dict):
        return _text_keyed(value)
    if isinstance(value, list):
        return [_with_text_keys(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_with_text_keys(item) for item in value)
    return value


def _key_text(key: object) -> str:
    if isinstance(key, str):
        return key
    try:
        return redact_text(str(key))
    except Exception:
        return "<unprintable key>"


class _SafeFormatter(structlog.stdlib.ProcessorFormatter):
    """ProcessorFormatter that degrades a record it cannot format instead of losing it.

    A bad %-format in a third-party call (``log.error("timeout %d", text)``) or a value the
    renderer rejects would otherwise reach ``handleError``. The degraded record keeps the message
    template and names the error type. Arguments and extra fields are dropped: printed on their
    own they lose the context ("password=%s") that lets redaction recognise them.
    """

    @override
    def format(self, record: logging.LogRecord) -> str:
        try:
            return super().format(record)
        except Exception as exc:
            return super().format(_degraded(record, exc))


def _degraded(record: logging.LogRecord, error: Exception) -> logging.LogRecord:
    message = record.msg.get("event") if isinstance(record.msg, dict) else record.msg
    try:
        template = str(message)
    except Exception:
        template = "<unprintable log message>"
    attributes = {key: value for key, value in vars(record).items() if key in _RECORD_ATTRIBUTES}
    attributes.update(
        msg=template,
        args=(),
        exc_text=None,
        log_error=(
            f"the record could not be formatted ({type(error).__name__}); "
            "its arguments and extra fields were dropped"
        ),
    )
    return logging.makeLogRecord(attributes)


class _SafeStreamHandler(logging.StreamHandler[TextIO]):
    """Stream handler whose error path never prints a record's message or arguments.

    ``logging.Handler.handleError`` writes the traceback, the call stack and ``Message: ...
    Arguments: ...`` to stderr, bypassing redaction. Here the record is replaced by a fixed
    notice that names only its (redacted) logger.
    """

    @override
    def handleError(self, record: logging.LogRecord) -> None:
        if not logging.raiseExceptions:
            return
        notice = logging.makeLogRecord(
            {
                "name": record.name,
                "levelno": record.levelno,
                "levelname": record.levelname,
                "msg": "log record dropped: it could not be formatted or written",
            }
        )
        try:
            text = self.format(notice)
        except Exception:
            text = f"<{notice.msg}>"
        for stream in (self.stream, sys.stderr):  # the stream itself may be the problem
            if _wrote(stream, text + self.terminator):
                return


def _wrote(stream: TextIO, text: str) -> bool:
    try:
        stream.write(text)
        stream.flush()
    except Exception:
        return False
    return True


def _shared_processors() -> list[Processor]:
    return [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.ExtraAdder(),
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,  # exceptions become text *before* redaction
        structlog.processors.UnicodeDecoder(),
        redact_event,
    ]


def configure_logging(
    level: str = "INFO", fmt: str = "console", *, stream: TextIO | None = None
) -> None:
    """Configure structlog + stdlib logging. Safe to call more than once."""
    renderer: Processor
    if fmt == "json":
        renderer = structlog.processors.JSONRenderer(sort_keys=True)
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=False, sort_keys=True)

    shared = _shared_processors()
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            *shared,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=False,
    )

    formatter = _SafeFormatter(
        foreign_pre_chain=shared,
        processors=[structlog.stdlib.ProcessorFormatter.remove_processors_meta, renderer],
    )
    handler = _SafeStreamHandler(stream if stream is not None else sys.stderr)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level)
    for name in _NOISY_LOGGERS:
        logging.getLogger(name).setLevel(max(logging.WARNING, logging.getLevelName(level)))
    # warnings.warn() otherwise writes straight to stderr; route it through the chain above.
    logging.captureWarnings(True)


def get_logger(name: str | None = None, **initial_values: Any) -> structlog.stdlib.BoundLogger:
    logger: structlog.stdlib.BoundLogger = structlog.stdlib.get_logger(name, **initial_values)
    return logger
