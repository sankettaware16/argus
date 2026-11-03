"""Query parameters the classic pages and ``/api/v1`` share (the dashboard's filters)."""

from __future__ import annotations

import re
from datetime import date, timedelta
from typing import Annotated, Any, Literal

from fastapi import Depends, Query
from pydantic import BeforeValidator

from argus.web import dashboard

# Text inputs: Postgres cannot store NUL, so it is refused at the door (422), never a 500.
CLEAN = r"^[^\x00]*$"


def _iso_day(value: Any) -> Any:
    """A day as YYYY-MM-DD only (lax parsing would read "0" as 1970-01-01; schemathesis)."""
    if isinstance(value, str) and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise ValueError("a day as YYYY-MM-DD")
    return value


Day = Annotated[date, BeforeValidator(_iso_day)]
EARLIEST, LATEST = date(2020, 1, 1), date(2100, 1, 1)  # a custom dashboard span's bounds
MAX_SPAN_DAYS = 366
SeverityName = Literal["critical", "high", "medium", "low"]
StateName = Literal["unreviewed", "follow_up", "changed_since_review", "reviewed"]
VerdictName = Literal["true_positive", "benign_expected", "benign_policy", "rule_false_positive",
                      "inconclusive", "none"]  # fmt: skip
AiName = Literal["proposed_tp", "proposed_other", "no_proposal", "working", "none"]
KindName = Literal["ip", "host", "domain", "user"]


def dashboard_filters(
    range: dashboard.RangeName = "7d",
    start: Day | Literal[""] | None = None,  # a form sends its empty fields as ""
    end: Day | Literal[""] | None = None,
    severity: Annotated[list[SeverityName], Query(max_length=4)] = [],  # noqa: B006 - FastAPI
    state: Annotated[list[StateName], Query(max_length=4)] = [],  # noqa: B006
    verdict: Annotated[list[VerdictName], Query(max_length=6)] = [],  # noqa: B006
    ai: Annotated[list[AiName], Query(max_length=5)] = [],  # noqa: B006
    rule: Annotated[str | None, Query(max_length=200, pattern=CLEAN)] = None,
    kind: KindName | Literal[""] | None = None,
    value: Annotated[str | None, Query(max_length=300, pattern=CLEAN)] = None,
) -> dashboard.Filters:
    """The dashboard's filters (D-103): a span, then "any of" lists, a rule and an entity. A
    custom span is kept within 2020 to 2100 and to at most 366 days (its last days)."""
    start, end, kind = start or None, end or None, kind or None
    both = start is not None and end is not None
    if start is not None and end is not None:
        start, end = sorted(min(max(d, EARLIEST), LATEST) for d in (start, end))
        start = max(start, end - timedelta(days=MAX_SPAN_DAYS - 1))
    return dashboard.Filters(
        range, start if both else None, end if both else None,
        tuple(dict.fromkeys(severity)), tuple(dict.fromkeys(state)),
        tuple(dict.fromkeys(verdict)), tuple(dict.fromkeys(ai)),
        rule or None, kind if value else None, value if kind else None,
    )  # fmt: skip


DashboardFilters = Annotated[dashboard.Filters, Depends(dashboard_filters)]
