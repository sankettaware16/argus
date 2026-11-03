"""Turning database and migration failures into one line people can act on (CLI and doctor)."""

from __future__ import annotations

import socket

from alembic.script.revision import RevisionError
from alembic.util import CommandError
from sqlalchemy.exc import DBAPIError, SQLAlchemyError

from argus.observability.redaction import redact_text

# Failures caused by the database or its migration state, not by ARGUS bugs: callers report them
# with short_db_error() instead of a traceback.
DB_ERRORS: tuple[type[Exception], ...] = (SQLAlchemyError, OSError, CommandError, RevisionError)


def short_db_error(exc: BaseException, during: str | None = None) -> str:
    """One redacted line saying what failed, with the server's hint if it gave one.

    Only a failure to *establish* a connection (refused, unreachable, authentication, unknown
    database) says "cannot connect". Errors after connecting, such as a lock or statement timeout
    or a failed migration statement, name the operation instead (``during``, e.g. "upgrade"), so
    nobody goes looking at the network when the problem is a lock.
    """
    original = getattr(exc, "orig", None) or exc
    message = str(original).strip()
    first_line = message.splitlines()[0] if message else type(original).__name__
    if is_connection_failure(exc):
        prefix = "cannot connect"
    elif during:
        prefix = f"{during} failed"
    else:
        prefix = "database error"
    diag = getattr(original, "diag", None)
    hint = getattr(diag, "message_hint", None)  # e.g. "run argus db bootstrap"
    hint = " ".join(hint.split()) if isinstance(hint, str) else ""  # one line, whatever it holds
    suffix = f" (hint: {hint})" if hint else ""
    return redact_text(f"{prefix}: {first_line}{suffix}")


def is_connection_failure(exc: BaseException) -> bool:
    """True if ``exc`` means no connection was established (nothing ran on the server)."""
    if isinstance(exc, OSError):  # psycopg wraps its own socket errors; these come from elsewhere
        return isinstance(exc, ConnectionError | TimeoutError | socket.gaierror | socket.herror)
    # Connecting runs no statement, and the driver's connect errors carry no SQLSTATE; anything
    # the server rejects after connecting has one (57014 statement timeout, 55P03 lock timeout...).
    return (
        isinstance(exc, DBAPIError)
        and exc.statement is None
        and getattr(exc.orig, "sqlstate", None) is None
    )
