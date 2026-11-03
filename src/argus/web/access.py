"""The "Your access" page (Q-E2, plan §7.2): what this person may do in ARGUS, why, how fresh
that is, and what to ask for when it is not enough, in plain words. Built from the session
alone (no request to ELK: the page never waits)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from argus.site import Words
from argus.web import auth
from argus.web.capabilities import ALL, LABELS, Capability

NEEDS_IN_ELK = Words(
    {
        Capability.VIEW: "your ELK account needs access to the {team} space in Kibana and to"
        " read the alerts",
        Capability.SEE_LOGS: "your ELK account needs to read the raw logs ({logs})",
        Capability.REVIEW: "your ELK account needs permission to change alert status",
        Capability.ANSWER_GOLD: "you need the review access, and an ARGUS admin has to name you an"
        " owner of the gold set",
        Capability.MANAGE_CASES: "your ELK account needs Kibana's case privileges to create, update"
        " and comment on cases",
        Capability.REOPEN: "your ELK account needs Kibana's privilege to reopen cases",
        Capability.APPROVE: "you need the case access above and the ARGUS privilege “approver”"
        " from your ELK admin",
        Capability.ADMIN: "you need the ARGUS privilege “admin” from your ELK admin",
    }
)
NEEDS_LOCAL = "an ARGUS admin has to grant it to your account (argus user grant)"
NEEDS_BREAK_GLASS = "the emergency account only views and reviews"
MODE_TEXT = {
    "local": "a local ARGUS account (a password kept by ARGUS)",
    "elk": "your own ELK account, checked against Elasticsearch",
    "break_glass": "the emergency (break-glass) account",
}


@dataclass(frozen=True)
class Row:
    capability: Capability
    label: str
    held: bool
    needs: str  # what is missing, when it is not held


@dataclass(frozen=True)
class AccessView:
    mode: str
    mode_text: str
    elk_username: str | None
    rows: list[Row]
    checked: str | None  # "2 minutes ago", ELK sessions
    status: str  # one sentence on whether ARGUS can verify the person right now
    status_ok: bool
    custody: str | None
    ends: datetime | None
    idle_minutes: int


def ago(moment: datetime | None, now: datetime) -> str | None:
    if moment is None:
        return None
    seconds = max(int((now - moment).total_seconds()), 0)
    if seconds < 60:
        return "less than a minute ago"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    hours = minutes // 60
    return f"{hours} hour{'s' if hours != 1 else ''} ago"


def describe(reviewer: auth.Reviewer, now: datetime, idle: timedelta) -> AccessView:
    mode = reviewer.mode
    missing = {"local": NEEDS_LOCAL, "break_glass": NEEDS_BREAK_GLASS}
    rows = [
        Row(
            c, LABELS[c], c in reviewer.capabilities,
            "" if c in reviewer.capabilities else missing.get(mode, NEEDS_IN_ELK[c]),
        )
        for c in ALL
    ]  # fmt: skip
    status, ok = "ARGUS checks your password when you sign in.", True
    custody = None
    if mode == "elk":
        since = reviewer.unverified_since
        if since is not None:
            when = ago(since, now)
            if reviewer.unverified_why == "outage":
                status = (
                    f"ARGUS cannot reach ELK to confirm your access (since {when}). You can read"
                    " and review for up to an hour; your reviews are saved here and not sent to"
                    " Kibana, and approvals and other changes wait."
                )
            else:
                status = (
                    f"ARGUS has not been able to confirm your access (since {when}). You can"
                    " review for 15 minutes, then only read; after an hour you are signed out."
                )
            ok = False
        else:
            status = (
                "ARGUS checked your access in ELK "
                f"{ago(reviewer.snapshot_at, now) or 'at sign-in'}, and checks again every five"
                " minutes and before every change. If your ELK access changes, so does this page."
            )
        custody = (
            "ARGUS keeps no copy of your password (an admin account): confirm it is you on the"
            " step-up page before a change."
            if reviewer.no_custody
            else "ARGUS keeps your ELK password sealed in this session to check your access, and"
            " wipes it when you sign out or the session ends."
        )
    elif mode == "break_glass":
        status = (
            "This is the emergency account: it can view and review, nothing it does is sent to"
            " Kibana, it approves nothing, and every action is recorded."
        )
        ok = False
    return AccessView(
        mode, MODE_TEXT[mode], reviewer.elk_username, rows, ago(reviewer.snapshot_at, now),
        status, ok, custody, reviewer.expires_at, int(idle.total_seconds() // 60),
    )  # fmt: skip
