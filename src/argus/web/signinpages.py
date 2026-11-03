"""The pages' side of "who used this device": the stored sightings of an investigation's or a
case's devices as the API's answer, and the sign-ins as timeline entries. Names are for ``see_logs``
only; without it the counts are kept and no account name appears in any field (``hidden``).
Nothing here writes, and nothing reaches the SIEM."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncConnection

from argus.signins import view
from argus.signins.attribute import (
    LEAD,
    STATES,
    Attribution,
    Entry,
    entry_words,
    gap_word,
    sentence,
)
from argus.web.v1 import case_models
from argus.web.v1 import models as m

MAX_DEVICES = 100
MAX_ENTRIES = 25  # of the timeline's 80: sign-ins are context, not the case's events
ORDER = {"likely": 0, "possible": 1, "unknown": 2, "shared": 3, "none_seen": 4}


def _device(att: Attribution, hidden: bool) -> m.SigninDeviceOut:
    accounts = (
        []
        if hidden
        else [
            m.SigninAccountOut(
                user=a.user,
                first_at=a.first_at,
                last_at=a.last_at,
                events=a.events,
                successes=a.successes,
                failures=a.failures,
                days=list(a.days),
                devices=list(a.devices),
            )
            for a in att.accounts
        ]
    )
    return m.SigninDeviceOut(
        address=att.address,
        state=att.state,
        words=sentence(att, names=not hidden),
        accounts=accounts,
        account_count=att.account_count,
        at_least=att.at_least,
        shared_days=list(att.shared_days),
        gaps=[m.SigninGapOut(day=g.day, why=g.why, words=gap_word(g)) for g in att.gaps],
        hands=[] if hidden else [m.SigninHandOut(day=d, user=u) for d, u in att.hands],
        failed_only=[] if hidden else list(att.failed_only),
        outside_window=att.outside_window,
    )


def out(users: view.Users, *, enabled: bool, hidden: bool) -> m.SigninsOut:
    """The API's answer for a set of devices. ``hidden``: this account may not see names."""
    ranked = sorted(users.attributions, key=lambda a: (ORDER[a.state], a.address))
    counts = dict.fromkeys(STATES, 0)
    for a in users.attributions:
        counts[a.state] += 1
    return m.SigninsOut(
        enabled=enabled,
        hidden=hidden,
        lead=LEAD,
        states=[m.SigninStateCountOut(state=s, devices=counts[s]) for s in STATES if counts[s]],
        devices=[_device(a, hidden) for a in ranked[:MAX_DEVICES]],
        devices_total=users.devices_total,
    )


def entries(found: list[Entry]) -> list[case_models.TimelineItemOut]:
    """The sign-ins as timeline entries, marked as context (kind ``signin``): one for each
    account on each day. Only for an account that may see names."""
    return [
        case_models.TimelineItemOut(
            at=e.first_at,
            until=e.last_at if e.last_at != e.first_at else None,
            kind="signin",
            text=entry_words(e),
            by=None,
            investigation_id=None,
        )
        for e in found[:MAX_ENTRIES]
    ]


async def for_investigation(
    conn: AsyncConnection,
    reading: view.Reading | None,
    investigation_id: uuid.UUID,
    now: datetime,
    *,
    hidden: bool,
) -> m.SigninsOut | None:
    """The card on an investigation page; None when the feature is not set up on this server."""
    if reading is None:
        return None
    users = await view.for_investigation(conn, reading, investigation_id, now)
    return out(users, enabled=reading.enabled, hidden=hidden)


async def for_case(
    conn: AsyncConnection,
    reading: view.Reading | None,
    case_id: uuid.UUID,
    now: datetime,
    *,
    hidden: bool,
) -> tuple[m.SigninsOut | None, list[case_models.TimelineItemOut]]:
    """The card on a case page and its timeline entries (none for an account without names)."""
    if reading is None:
        return None, []
    users = await view.for_case(conn, reading, case_id, now)
    return out(users, enabled=reading.enabled, hidden=hidden), (
        [] if hidden else entries(list(users.entries))
    )
