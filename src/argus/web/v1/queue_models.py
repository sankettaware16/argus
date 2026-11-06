"""The typed contract of the case-first queue (AR4, D-182): what needs a person, in order.

One answer for the app's front page: ARGUS's open cases that need a person (each with its verdict
or reading in one line, its devices and why it is here), the single investigations in Needs
attention that belong to no case, and the order in which "Next" walks through the work. The
patterns ARGUS recommends closing are the Patterns page's own answer (``/patterns``), and the
counts of new and known work are ``/counts``: the queue repeats neither, so every page says the
same numbers."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from argus.web.v1.case_models import CaseSeverity, CaseState
from argus.web.v1.models import InvestigationOut, Out, StanceOut

QueueKind = Literal["suggested", "changed", "attention", "unowned", "new"]


class QueueCaseOut(Out):
    """A case that needs a person, and why. ``stance`` is ARGUS's verdict or reading on the
    case's first investigation to look at (``first_investigation_id``)."""

    id: uuid.UUID
    number: int
    title: str
    state: CaseState
    severity: CaseSeverity
    # suggested: ARGUS suggests it; changed: new since the owner was told; attention: ARGUS,
    # Kibana or an approval asks; unowned: nobody has it; new: it holds new work in a worked case
    kind: QueueKind
    why: str  # ARGUS's sentence: why it is in the queue
    changes: list[str]  # kind "changed": what is new since the notice, at most three
    notified_at: datetime | None
    stance: StanceOut
    devices: list[str]  # the case's campus hosts and addresses, at most four
    devices_total: int
    outside: list[str]  # the case's outside (public) addresses, at most four: never "devices"
    outside_total: int
    investigations: int
    new_members: int  # investigations in Needs attention that it holds (all of them, not a page)
    unreviewed: int  # investigations a person still has to look at
    alerts: int
    last_alert_at: datetime | None
    waiting_for_approval: int
    first_investigation_id: uuid.UUID | None  # None: nothing left to review in it


class QueueSingleOut(Out):
    """An investigation in Needs attention that belongs to no case."""

    investigation: InvestigationOut
    stance: StanceOut


class QueueOut(Out):
    """The queue: cases, then single investigations. The patterns to close are ``/patterns``;
    the counts of new work and of notified work are ``/counts``."""

    cases: list[QueueCaseOut]  # the first ones, most urgent first (at most 30)
    cases_total: int
    singles: list[QueueSingleOut]  # the first ones, most urgent first (at most 20)
    singles_total: int
    notified_cases: int  # open or assigned cases whose owner was told: tracked quietly
    order: list[uuid.UUID]  # the investigations "Next" walks through, in this order (at most 150)
    order_total: int  # how many the whole queue holds (the cases' work and the singles), uncapped
