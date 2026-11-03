"""What the gateway raises. Every error has a fixed ``reason`` code (stored in the ledger and
shown in the UI); messages name templates, fields and limits, never a query value."""

from __future__ import annotations

from datetime import datetime


class GatewayError(Exception):
    reason = "gateway_error"


# --------------------------------------------------------------------- refused before sending
# Nothing was sent to the SIEM: the transport was not called.


class RefusedError(GatewayError):
    reason = "refused"


class TemplateRejectedError(RefusedError):
    """The final request breaks the query contract."""

    reason = "template_rejected"

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code


class UnsupportedValueError(RefusedError):
    """A value longer than the field's ``ignore_above``: Elasticsearch would silently match
    nothing, so the answer would look empty instead of unknown."""

    reason = "unsupported_value"


class StoppedError(RefusedError):
    """The operator's kill switch, or the SIEM in STOP."""

    reason = "stopped"


class DeferredError(RefusedError):
    """The SIEM's health state does not allow this kind of work now; try again later."""

    reason = "deferred"


class BreakerOpenError(RefusedError):
    reason = "breaker_open"

    def __init__(self, until: datetime | None) -> None:
        super().__init__("the SIEM reported overload; requests pause until the breaker closes")
        self.until = until


class BudgetExhaustedError(RefusedError):
    """The day's server-time or heavy-query budget is spent (``skipped_budget``)."""

    reason = "skipped_budget"


class DeadlinePassedError(RefusedError):
    reason = "deadline_passed"


class LaneBusyError(DeadlinePassedError):
    """The budget frees up only after the caller's deadline, and nothing was sent:
    not a timeout of the work but a debt of the lane, which pays down at ``retry_at``. A
    caller that can wait puts the work back and tries again then; it is a
    ``DeadlinePassedError`` for every caller that does not tell the two apart."""

    def __init__(self, message: str, retry_at: datetime | None = None) -> None:
        super().__init__(message)
        self.retry_at = retry_at


class SourceMissingError(RefusedError):
    """A daily index the time range needs does not exist: deleted by ILM (``source_expired``)
    or not created yet (``source_not_ready``); or a data stream or alias the site names is not
    there (``source_missing``: never created, renamed, mistyped: nothing is known about
    retention, so a caller treats it as not final)."""

    def __init__(self, reason: str, days: tuple[str, ...]) -> None:
        super().__init__(f"{reason}: {', '.join(days)}")
        self.reason = reason
        self.days = days


class LiveSessionError(RefusedError):
    """No usable live-test session (human-issued, time- and request-bounded)."""

    reason = "live_session"


# --------------------------------------------------------------------- after sending


class ResponseError(GatewayError):
    reason = "response_error"


class PartialResultError(ResponseError):
    """Timed out, shard failures, terminated early or a failed document: never used as data."""

    reason = "partial_result"


class OverloadedError(ResponseError):
    """429, rejected execution or a tripped circuit breaker: opens the gateway's breaker."""

    reason = "overloaded"


class AuthFailedError(ResponseError):
    """401/403: the API key is missing, expired, revoked or lacks a privilege. The SIEM goes to
    STOP for ARGUS until an operator acts."""

    reason = "auth_failed"


class SiemError(ResponseError):
    reason = "siem_error"

    def __init__(self, status: int, error_type: str | None) -> None:
        super().__init__(f"HTTP {status}" + (f" {error_type}" if error_type else ""))
        self.status = status
        self.error_type = error_type


class TransportFailedError(ResponseError):
    """No usable HTTP response: connection refused or reset, protocol error, 502/503/504."""

    reason = "transport_failure"

    def __init__(self, message: str, *, retriable: bool, reached: bool = True) -> None:
        super().__init__(message)
        self.retriable = retriable
        self.reached = reached  # False: no connection was made, the SIEM did no work


class TimedOutError(TransportFailedError):
    reason = "timed_out"

    def __init__(
        self, message: str = "no response before the deadline", *, reached: bool = True
    ) -> None:
        super().__init__(message, retriable=False, reached=reached)
