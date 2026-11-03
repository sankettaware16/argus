"""What the Kibana lane raises (Q-D2). Refusals (``RefusedError``) mean nothing was sent. After
sending, every error says whether the request may have taken effect: a write whose outcome is
unknown is never sent again by ARGUS (plan §3 rule 4); reconciliation (Q-D3, Q-D4) decides."""

from __future__ import annotations

from argus.gateway.errors import RefusedError, ResponseError


class KibanaStoppedError(RefusedError):
    """Kibana work is stopped: Kibana refused ARGUS's key (401), or a read was forbidden (403),
    until an operator resumes it (``argus kibana resume``). Collection is not affected."""

    reason = "kibana_stopped"


class WriteRefusedError(RefusedError):
    """A write's own rules said no: its class is off or paused, outside the write window, not
    NORMAL, no verified Kibana version for the run, a cap reached, an approval missing."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason


class KibanaResponseError(ResponseError):
    """Kibana answered, or the exchange failed after sending. ``maybe_applied`` is True when
    the request may have taken effect (a write then goes to reconciliation, never resent)."""

    reason = "kibana_error"
    maybe_applied = False

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class KibanaAuthError(KibanaResponseError):
    """401: Kibana does not accept the key. Stops Kibana work only (DQ9 (b))."""

    reason = "kibana_auth_failed"


class KibanaForbiddenError(KibanaResponseError):
    """403: the key may not do this. A write: its outbox row and its class pause (DQ9 (b))."""

    reason = "kibana_forbidden"


class KibanaNotFoundError(KibanaResponseError):
    reason = "kibana_not_found"


class KibanaConflictError(KibanaResponseError):
    """409: the case changed since ARGUS read it. Re-read and re-plan; never resend as is."""

    reason = "kibana_conflict"


class KibanaNoChangeError(KibanaResponseError):
    """406: every field already has this value (the change is already there)."""

    reason = "kibana_no_change"


class KibanaRejectedError(KibanaResponseError):
    """400 or another 4xx: the body or a value is outside Kibana's schema."""

    reason = "kibana_rejected"


class KibanaOverloadedError(KibanaResponseError):
    """429 or 503: opens Kibana's breaker (Kibana's only; the SIEM's is not touched)."""

    reason = "kibana_overloaded"


class KibanaServerError(KibanaResponseError):
    """5xx (other than 503): Kibana failed; a write may or may not have taken effect."""

    reason = "kibana_server_error"
    maybe_applied = True


class UnknownOutcomeError(KibanaResponseError):
    """Sent, but no usable answer (a timeout, a reset, a truncated answer): a write may have
    landed. It becomes "ambiguous" and is looked for, never resent (plan §7.1)."""

    reason = "unknown_outcome"
    maybe_applied = True

    def __init__(self, message: str, *, reached: bool = True, timed_out: bool = False) -> None:
        super().__init__(message)
        self.reached = reached  # False: no connection was made, nothing can have landed
        self.timed_out = timed_out
        self.maybe_applied = reached


class AnswerMismatchError(KibanaResponseError):
    """A 2xx answer that is not what the request should have produced (another case, a field
    not as sent, Sync alerts on): the write may have landed wrongly. Its class pauses."""

    reason = "answer_mismatch"
    maybe_applied = True
