"""The typed contract of the incident engine's view (P4-F E5, ``docs/p4f-ui-spec.md`` §2): the
``engine`` block a case made by the engine carries, and the Today page (``GET /api/v1/today``).

A possible incident is a suspected case; its members are alert groups. The engine block says
how urgent it is (``priority`` 0-100 in bands P1-P4), why (``why``: the stored score breakdown
in words, largest first; ``op`` "+" adds points, the times sign multiplies), what ARGUS checked
(``checks``: ``checked`` found something that backs it, ``ruled_out`` looked and found nothing,
``unknown`` could not look), what else it could be (``alternatives``, each with its
deterministic test) and the evidence's word for it (``certainty``; "Confirmed" is never sent:
the UI says it from the case's state, spec §3.2). Every text here is ARGUS's own words, made by
code; rule names and addresses inside it came from alerts."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from argus.web.v1.models import Out

Band = Literal["P1", "P2", "P3", "P4"]
Lane = Literal["decisive", "burst", "slow", "campaign", "exposure"]
Certainty = Literal["Likely", "Suspected", "Unclear", "Likely harmless"]
CaseState = Literal["suspected", "open", "assigned", "contained", "closed"]
# incident: a case (its id, its version; it can be acted on); alert_group: an investigation;
# shadow: the engine's own incident while ``risk.present`` is off (the engine's id and version:
# nothing to act on); gray: an object just under a lane ("gray:<object id>")
CardKind = Literal["incident", "alert_group", "shadow", "gray"]


class WhyItemOut(Out):
    op: Literal["+", "\u00d7"]
    points: float  # added points (negative: taken off), or the factor
    text: str


class EngineCheckOut(Out):
    state: Literal["checked", "ruled_out", "unknown"]
    text: str


class AlternativeOut(Out):
    name: str
    state: Literal["ruled_out", "fits", "unknown"]
    test: str  # the deterministic test and what it found


class EngineObjectOut(Out):
    kind: Literal["device", "account", "site"]
    label: str
    role: Literal["affected", "actor"]


class EngineOut(Out):
    incident_id: int
    priority: int  # 0-100
    band: Band
    lane: Lane  # "slow" when none of its objects is left in the window
    certainty: Certainty  # the evidence's word (never "Confirmed": the case's state says that)
    why: list[WhyItemOut]
    why_line: str  # the why items in one line: "+49 outside detection · x1.2 still active"
    checks: list[EngineCheckOut]
    alternatives: list[AlternativeOut]
    objects: list[EngineObjectOut]  # the campus objects, those that acted first (at most 50)
    raised_by_ai: bool  # the AI's gray-band judge put it in front of a person
    active: bool  # an observation in the last 72 hours
    first_seen: datetime
    last_seen: datetime
    version: int  # raised by each material change (the engine's, never shown)
    changed: list[str]  # the material changes since the viewer last looked, in words
    alert_groups: int
    alerts: int


class TakenByOut(Out):
    username: str
    name: str


class TodayCardOut(Out):
    """One card of Today (the spec's ``Card``): the case that presents the incident (kind
    ``incident``); in shadow (``risk.present`` off) there is none, and the card is the engine's
    own incident (kind ``shadow``, ``id`` its incident id); a gray item is kind ``gray``."""

    kind: CardKind
    id: str  # the case's id; in shadow the engine's incident id; a gray item: "gray:<object>"
    number: int | None  # the incident's number; None without a case
    title: str
    state: CaseState | None  # None without a case
    version: int  # the case's (send it back as expected_version); the engine's without one
    engine: EngineOut | None  # None for a case in Needs you that the engine did not make
    taken_by: TakenByOut | None  # who took its case
    notified_at: datetime | None  # the owner was told
    in_kibana: bool  # a Kibana create was planned for its case
    kibana_wait: str | None  # why Kibana does not have its case yet
    waiting_since: datetime | None  # since when it waits for a person


class HandledCategoryOut(Out):
    key: str
    label: str
    count: int  # alert groups


class AuditItemOut(Out):
    """One item the digest handled, to spot-check in ten seconds: was ARGUS right?"""

    id: str  # the alert group's investigation id
    kind: Literal["alert_group"]
    title: str  # the rule's name, or the category's label
    closed_as: str  # the digest category, in words
    category: str
    at: datetime


class HandledOut(Out):
    since: datetime
    count: int  # alert groups ARGUS handled since then, presented ones not counted
    categories: list[HandledCategoryOut]  # the largest first
    audit: AuditItemOut | None


class TodayOut(Out):
    mode: Literal["shadow", "present"]  # present: the cards are suspected cases to decide
    # presenting: the cases of ``GET /cases?view=queue`` (possible incidents nobody decided,
    # confirmed ones nobody has taken, and the other reasons a person has to look) that are
    # cards today: every P1 and P2, then P3 and P4 the daily capacity has shown, up to 50 in
    # all; by band, a quiet one after the live ones of its band, then priority, then the cases
    # the engine did not make. In shadow: the engine's own live incidents, no case.
    needs_you: list[TodayCardOut]
    # the rest of the queue: what the daily capacity holds back (never P1 or P2) and what is
    # past the list's length, so needs_you + more_waiting is the queue's count (spec Q-2)
    more_waiting: int
    # confirmed incidents with a material change since the viewer acted, and closed ones told
    # of new strong evidence on the alert groups they hold
    new_activity: list[TodayCardOut]
    gray: list[TodayCardOut]  # at most five, just under a lane
    handled: HandledOut
