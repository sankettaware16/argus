"""The typed contract of UI v2's finding pages (spec §2.3): an entity's page (A11), the one search
box (A12), the incident reports list (A13) and the Kibana-posting health (A5).

Values that came from alerts or logs (addresses, names, titles, rule names) are returned as
stored: the app shows them as untrusted text. Each list is cut at a fixed size and says how many
there are in all."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Literal

from argus.web.v1.case_models import CaseRowOut, EntityNoteOut
from argus.web.v1.models import InCaseOut, Out
from argus.web.v1.report_models import ReportFileOut
from argus.web.v1.work_models import SentOut

PageKind = Literal["device", "account", "site", "outside"]
StoredKind = Literal["ip", "host", "domain", "user"]
Guess = Literal["number", "ir", "device_address", "outside_address", "domain", "name", "words"]


class AssetOut(Out):
    """What the asset map says of an address (its own fields, as the site wrote them)."""

    name: str
    network: str
    fields: dict[str, str]


class ReputationOut(Out):
    """What one outside source said of the value, when ARGUS last asked."""

    source: str
    words: str  # ARGUS's sentence of it
    flagged: bool
    at: datetime


class GroupRowOut(Out):
    """An alert group (an investigation) that holds the value."""

    id: uuid.UUID
    rule_name: str | None
    alerts: int
    first_at: datetime | None
    last_at: datetime | None
    case: InCaseOut | None  # the incident it belongs to


class EntityDayOut(Out):
    """One day of the value in ARGUS's records: its alert groups (by the site's day their bucket
    is named for), and for an address the host names that day's alert groups named (from the
    SIEM, untrusted) and the accounts that signed in from it (by UTC day, as ARGUS keeps
    sign-ins; names only with ``see_logs``)."""

    day: date
    alert_groups: int
    hosts: list[str]  # an address's host names that day, most named first, at most 5; []: unknown
    accounts: int | None  # None: no sign-in data that day
    account_names: list[str] | None  # None: hidden (needs see_logs) or none kept


class TimelineEventOut(Out):
    """An alert group of the value, at its newest alert: the rule's name (from the SIEM,
    untrusted), its alerts, and the incident it is in (None: in none)."""

    at: datetime
    rule_name: str | None
    alerts: int
    investigation_id: uuid.UUID
    case_number: int | None


class EntityPageOut(Out):
    """What ARGUS knows of a device, account, campus site or outside address: its incidents, its
    alert groups, a timeline, the notes people wrote. ``history_days``: how far back ARGUS keeps
    alert detail (it keeps every incident and decision)."""

    kind: PageKind
    value: str
    stored_kind: StoredKind
    noun: str  # "Device", "Account", "Campus site", "Outside address"
    history_days: int
    address_class: str | None  # for an address: asset, campus, internal, public, special
    asset: AssetOut | None
    first_seen: datetime | None  # in ARGUS's alert groups
    last_seen: datetime | None
    owner_told: bool  # one of its incidents' device owners was told
    incidents: list[CaseRowOut]  # newest activity first, at most 20
    incidents_total: int
    open_incidents: int
    alert_groups: list[GroupRowOut]  # newest first, at most 20
    alert_groups_total: int
    timeline: list[TimelineEventOut]  # newest first, at most 50
    days: list[EntityDayOut]  # newest first, the days ARGUS holds
    # a different device behind the address on different days (two days' host names never meet);
    # False: the same device or people recur; None: ARGUS cannot tell (sign-ins alone never say
    # True: a lab PC has different people each day)
    dynamic: bool | None
    shared_by: int | None  # the most accounts seen behind it in one day; None: no data
    reputation: list[ReputationOut]  # outside sources' answers (outside addresses and domains)
    notes: list[EntityNoteOut]  # newest first, at most 5
    notes_total: int


class SearchEntityOut(Out):
    kind: PageKind
    value: str
    noun: str


class IncidentReportRowOut(Out):
    """A confirmed incident's report, newest version."""

    case_id: uuid.UUID
    number: int
    ir: str | None
    title: str
    case_state: str
    version: int
    generated_at: datetime
    files: list[ReportFileOut]
    in_kibana: bool
    sent: SentOut | None  # the newest "sent to the CISO"


class SearchOut(Out):
    """One box: what the text looks like, the entity it names, and what holds it (at most five
    of each, with how many there are in all)."""

    q: str
    guess: Guess
    entity: SearchEntityOut | None
    incidents: list[CaseRowOut]
    incidents_total: int
    alert_groups: list[GroupRowOut]
    alert_groups_total: int
    reports: list[IncidentReportRowOut]
    reports_total: int


class ReportsPageOut(Out):
    items: list[IncidentReportRowOut]  # newest report first
    offset: int
    limit: int
    has_more: bool
