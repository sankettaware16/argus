"""A seeded world for the Reporter's tests (Q-H3): rows placed on and around the edges of the
period (a microsecond inside, exactly at the end, a day before), so a figure that counts the
wrong rows differs from the independent recomputation in ``test_numbers``.

The seed logs in as the schema owner and switches the user triggers of the seeded tables off in
its own transaction: the tables' guards (the case machine, the approval functions, the chain)
are tested elsewhere; here the rows only have to exist, with the database's CHECKs and foreign
keys still holding."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

DAY = datetime(2026, 10, 20, tzinfo=UTC)  # the daily report's day; the weekly ends with it
AS_AT = DAY + timedelta(days=1, hours=6)  # the report is made at 11:30 AM IST the next day
HEX = "0123456789abcdef" * 4

GUARDED = (
    "cases",
    "case_events",
    "case_members",
    "case_indicators",
    "case_actions",
    "case_watch_checks",
    "approval_requests",
    "approval_decisions",
    "kibana_outbox",
    "kibana_steps",
    "kibana_findings",
    "kibana_sync_cycles",
    "action_ledger",
    "coverage_gaps",
    "siem_probes",
    "ti_sources",
    "writeback_outbox",
    "kibana_writer_runs",
    "assessments",
    "investigations",
)


def t(days: float = 0, hours: float = 0, minutes: float = 0, seconds: float = 0, us: int = 0):
    """``DAY`` plus an offset."""
    return DAY + timedelta(
        days=days, hours=hours, minutes=minutes, seconds=seconds, microseconds=us
    )


async def ins(conn: AsyncConnection, table: str, **cols: Any) -> Any:
    names = ", ".join(cols)
    marks = ", ".join(
        f"CAST(:{c} AS jsonb)" if isinstance(v, dict | list) and c in JSON_COLUMNS else f":{c}"
        for c, v in cols.items()
    )
    values = {c: json.dumps(v) if c in JSON_COLUMNS else v for c, v in cols.items()}
    row = await conn.execute(
        text(f"INSERT INTO {table} ({names}) VALUES ({marks}) RETURNING 1"),  # noqa: S608
        values,
    )
    return row.scalar()


JSON_COLUMNS = {"payload", "details", "switches", "capabilities", "ingest_lag_s", "detail"}


async def one(conn: AsyncConnection, sql: str, **p: Any) -> Any:
    return (await conn.execute(text(sql), p)).scalar_one()


class Seed:
    """What the seed made, by name."""

    def __init__(self) -> None:
        self.cases: dict[str, uuid.UUID] = {}
        self.users: dict[str, int] = {}
        self.versions: dict[str, int] = {}
        self.requests: dict[str, int] = {}
        self.events: dict[str, int] = {}


async def seed(engine: AsyncEngine) -> Seed:
    made = Seed()
    async with engine.begin() as conn:
        for table in GUARDED:
            await conn.execute(text(f"ALTER TABLE {table} DISABLE TRIGGER USER"))
        await _people_and_cases(conn, made)
        await _watch_and_actions(conn, made)
        await _approvals_and_outbox(conn, made)
        await _kibana(conn, made)
        await _results(conn, made)
        await _platform(conn, made)
        for table in GUARDED:
            await conn.execute(text(f"ALTER TABLE {table} ENABLE TRIGGER USER"))
    return made


# --------------------------------------------------------------------------- cases


async def _case(
    conn: AsyncConnection, made: Seed, name: str, state: str, created: datetime, **more: Any
) -> uuid.UUID:
    cid = uuid.uuid4()
    made.cases[name] = cid
    made.versions[name] = 1
    confirmed = state in ("open", "assigned", "contained")
    await ins(
        conn,
        "cases",
        id=cid,
        title=f"Case {name}",
        state=state,
        severity="high",
        version=1,
        cause="person",
        created_at=created,
        updated_at=created,
        opened_at=more.pop("opened_at", created if confirmed else None),
        **more,
    )
    return cid


async def event(
    conn: AsyncConnection,
    made: Seed,
    case: str,
    kind: str,
    frm: str | None,
    to: str,
    when: datetime,
) -> int:
    made.versions[case] += 1
    row = await conn.execute(
        text(
            "INSERT INTO case_events (case_id, case_version, kind, actor, from_state, to_state,"
            " occurred_at) VALUES (:c, :v, :k, 'argus:test', :f, :t, :at) RETURNING id"
        ),
        {"c": made.cases[case], "v": made.versions[case], "k": kind, "f": frm, "t": to, "at": when},
    )
    return int(row.scalar_one())


async def _people_and_cases(conn: AsyncConnection, made: Seed) -> None:
    for name in ("asha", "ravi"):
        made.users[name] = await one(
            conn,
            "INSERT INTO users (username, display_name, password_hash, capabilities)"
            " VALUES (:u, :u, 'x', ARRAY['view']) ON CONFLICT (username)"
            " DO UPDATE SET display_name = EXCLUDED.display_name RETURNING id",
            u=name,
        )
    # unclosed cases of every state and age (as at AS_AT = DAY + 30 h)
    await _case(conn, made, "old_suspected", "suspected", t(-10))  # 11 days 6 h old
    await _case(conn, made, "new_open", "open", t(0, 2))  # 28 h: in the period
    await _case(conn, made, "assigned", "assigned", t(-1, 12), owner_user_id=made.users["asha"])
    await _case(conn, made, "contained_a", "contained", t(-5))  # 6 days 6 h
    await _case(conn, made, "contained_b", "contained", t(-3, 20))  # 3 days 10 h
    await _case(conn, made, "old_open", "open", t(-8))  # 9 days 6 h
    await _case(conn, made, "edge_age", "open", AS_AT - timedelta(days=1))  # exactly 1 day
    await _case(conn, made, "edge_age_7", "open", AS_AT - timedelta(days=7))  # exactly 7 days
    await _case(conn, made, "just_under", "open", AS_AT - timedelta(days=3, microseconds=-1))
    # closed cases: never confirmed, so no approval is needed to close them
    closed = [
        ("closed_at_start", t(0), "created_in_error"),  # exactly the period's start: in
        ("closed_late", t(0, 23, 59, 59, 999999), "benign_expected"),  # last microsecond: in
        ("closed_at_end", t(1), "benign_expected"),  # exactly the end: out
        ("closed_before", t(-0, 0, 0, 0, -1), "benign_policy"),  # a microsecond before: out
        ("closed_midweek", t(-3, 5), "rule_false_positive"),  # weekly only
        ("closed_week_start", t(-6), "attempt_no_impact"),  # the weekly's first instant: in
        ("closed_week_before", t(-6, 0, 0, 0, -1), "duplicate"),  # out of the week
    ]
    for name, when, reason in closed:
        extra: dict[str, Any] = {}
        if reason == "duplicate":
            extra["merged_into_id"] = made.cases["new_open"]
        await _case(
            conn,
            made,
            name,
            "closed",
            when - timedelta(hours=1),
            closed_at=when,
            closure_reason=reason,
            **extra,
        )
    # reopened events: in the period, at the end (out), in the week only, before the week
    for case, when in (
        ("assigned", t(0, 12)),
        ("new_open", t(1)),
        ("old_open", t(-2)),
        ("contained_a", t(-7)),
    ):
        made.events[f"reopened_{case}"] = await event(
            conn, made, case, "reopened", "closed", "open", when
        )
    # cases closed through an approval (their requests are made with the approvals)
    await _case(conn, made, "closed_by_approval", "open", t(-2))
    await _case(conn, made, "merged_src", "open", t(-5))
    await _case(conn, made, "fresh", "suspected", AS_AT - timedelta(hours=5))
    await _case(conn, made, "edge_age_3", "open", AS_AT - timedelta(days=3))


# --------------------------------------------------------------------------- watch and actions


async def _watch_and_actions(conn: AsyncConnection, made: Seed) -> None:
    def check(case: str, day: int, outcome: str = "active", hosts: list[Any] | None = None) -> Any:
        return ins(
            conn,
            "case_watch_checks",
            case_id=made.cases[case],
            day=(DAY + timedelta(days=day)).date(),
            source="alerts",
            subject="",
            part=0,
            outcome=outcome,
            reason=None if outcome in ("active", "quiet") else "test",
            window_start=t(day),
            window_end=t(day + 1),
            **({} if hosts is None else {"detail": {"requests": 4, "hosts": hosts}}),
        )

    await check("new_open", 0, hosts=["ws-017", "10.1.1.5"])
    await check("new_open", 0 + 1, hosts=["ws-day-after"])  # the day after the period: out
    await check("new_open", -1, hosts=["ws-017"])  # weekly only
    await check("assigned", -1, hosts=["ws-017", "lab-3"])
    await check("contained_a", 0, hosts=["lab-3"])
    await check("contained_a", -2, hosts=["lab-3", {"bad": 1}, 7, "", "x" * 300])  # junk is out
    await check("contained_b", 0, "quiet", hosts=["ws-quiet"])
    await check("contained_b", -4, "unverified")
    await check("closed_midweek", 0, hosts=["ws-closed"])  # a closed case: out
    await check("old_open", -7, hosts=["ws-old"])  # before the week
    await check("assigned", 0)  # an answer of the alerts: no host named
    for case, kind, value, role, removed in (
        ("new_open", "host", "ws-017", "actor", False),
        ("new_open", "ip", "10.1.1.5", "actor", False),
        ("new_open", "ip", "198.51.100.7", "c2", False),
        ("new_open", "host", "ws-gone", "actor", True),
        ("assigned", "host", "ws-017", "actor", False),
        ("contained_a", "host", "lab-3", "actor", False),
        ("contained_a", "user", "bob", "actor", False),
        ("old_open", "host", "ws-old", "actor", False),
    ):
        extra: dict[str, Any] = {"removed_version": 2, "removed_at": t(-1)} if removed else {}
        await ins(
            conn,
            "case_indicators",
            case_id=made.cases[case],
            kind=kind,
            value=value,
            role=role,
            source="investigation",
            added_version=1,
            added_by="argus:test",
            **extra,
        )
    argus = {"recommended_at": t(0, 5), "recommended_by": "argus:responder"}
    person = {"requested_at": t(0, 6), "requested_by": f"user:{made.users['asha']}"}
    done = {
        "reported_at": t(0, 7),
        "reported_by": f"user:{made.users['ravi']}",
        "attestation": "isolated",
    }
    verdict = {"verdict_at": t(0, 8), "verdict": "no contact since"}
    rows = [
        # (case, action, owner, state, columns)
        ("new_open", "proxy.isolate", "network_team", "recommended", argus),
        ("new_open", "proxy.block", "network_team", "requested", {**argus, **person}),
        ("assigned", "mail.reset", "mail_admin", "reported_done", {**argus, **person, **done}),
        ("assigned", "web.remove", "site_owner", "verified", {**argus, **done, **verdict}),
        (
            "contained_a",
            "web.rotate",
            "site_owner",
            "not_verified",
            {**argus, **done, **verdict, "last_beat": t(0, 7, 30)},
        ),
        (
            "contained_a",
            "proxy.watch",
            "network_team",
            "recommended",
            {"recommended_at": t(-4), "recommended_by": "argus:responder"},
        ),
        (
            "contained_b",
            "web.patch",
            "site_owner",
            "requested",
            {"requested_at": t(-2), "requested_by": f"user:{made.users['asha']}"},
        ),  # no advice time
        ("closed_at_start", "proxy.old", "network_team", "recommended", argus),  # closed: out
    ]
    for case, action, owner, state, cols in rows:
        await ins(
            conn,
            "case_actions",
            case_id=made.cases[case],
            action=action,
            family="test",
            owner=owner,
            catalogue_version=1,
            state=state,
            **cols,
        )


# --------------------------------------------------------------------------- approvals, outbox


async def request(
    conn: AsyncConnection,
    made: Seed,
    name: str,
    case: str,
    kind: str,
    asked: datetime,
    lasts: timedelta,
    *,
    required: int = 1,
    reason: str | None = None,
    **more: Any,
) -> int:
    row = await conn.execute(
        text(
            "INSERT INTO approval_requests (case_id, case_version, kind, reason, payload,"
            " payload_hash, alert_count, alert_digest, required_approvals,"
            " requested_by_user_id, proposed_by, requested_at, expires_at, target_case_id,"
            " outbox_id, outbox_sent_count) VALUES (:c, 1, :k, :r, CAST('{}' AS jsonb), :h, 1, :h,"
            " :n, :u, :pb, :at, :ex, :target, :outbox, :sent) RETURNING id"
        ),
        {
            "c": made.cases[case],
            "k": kind,
            "r": reason,
            "h": HEX,
            "n": required,
            "u": None if more.get("proposed_by") else made.users["asha"],
            "pb": more.get("proposed_by"),
            "at": asked,
            "ex": asked + lasts,
            "target": more.get("target"),
            "outbox": more.get("outbox"),
            "sent": more.get("sent"),
        },
    )
    made.requests[name] = int(row.scalar_one())
    return made.requests[name]


async def decide(conn: AsyncConnection, made: Seed, name: str, who: str, decision: str) -> None:
    await ins(
        conn,
        "approval_decisions",
        request_id=made.requests[name],
        approver_user_id=made.users[who],
        decision=decision,
        capabilities=["approve"],
    )


async def outbox(
    conn: AsyncConnection,
    made: Seed,
    name: str,
    state: str,
    created: datetime,
    *,
    sent: int = 0,
    sent_at: datetime | None = None,
    approval: int | None = None,
) -> int:
    ev = await event(conn, made, "assigned", "linked", "assigned", "assigned", created)
    row = await conn.execute(
        text(
            "INSERT INTO kibana_outbox (case_id, case_event_id, position, idempotency_key,"
            " write_class, op, payload, payload_hash, state, sent_count, resends, sent_at,"
            " created_at, updated_at, approval_request_id) VALUES (:c, :ev, 0, :key, 'W1',"
            " 'comment', CAST('{}' AS jsonb), :h, :state, :sent, :resends, :sent_at, :at, :at,"
            " :appr) RETURNING id"
        ),
        {
            "c": made.cases["assigned"],
            "ev": ev,
            "key": f"key-{name}",
            "h": HEX,
            "state": state,
            "sent": sent,
            "resends": max(sent - 1, 0),
            "sent_at": sent_at,
            "at": created,
            "appr": approval,
        },
    )
    return int(row.scalar_one())


async def step(
    conn: AsyncConnection, made: Seed, name: str, outbox_id: int, request_id: int, sent: int
) -> None:
    """A compensating write's Kibana step: ``sent`` 1 when it went out."""
    await ins(
        conn,
        "kibana_steps",
        case_id=made.cases["assigned"],
        outbox_id=outbox_id,
        approval_request_id=request_id,
        kind="compensate_update",
        seq=0,
        key=f"step-{name}",
        write_class="W3",
        payload={},
        payload_hash=HEX,
        state="sent" if sent else "planned",
        sent_count=sent,
    )


async def _approvals_and_outbox(conn: AsyncConnection, made: Seed) -> None:
    h = timedelta(hours=1)
    # expired inside the period with one of two approvals: nothing was sent
    await request(
        conn,
        made,
        "r1",
        "new_open",
        "closure",
        t(-1, 20),
        14 * h,
        required=2,
        reason="remediated_unverified",
    )
    await decide(conn, made, "r1", "asha", "approved")
    # approved in the period; expires after it (before the making): not "expired in the period"
    await request(
        conn, made, "r2", "assigned", "closure", t(0, 9), 18 * h, reason="benign_expected"
    )
    await decide(conn, made, "r2", "ravi", "approved")
    # rejected (also by one approver while another approved): rejected
    await request(
        conn, made, "r3", "contained_a", "closure", t(0, 10), 24 * h, reason="benign_policy"
    )
    await decide(conn, made, "r3", "ravi", "rejected")
    await decide(conn, made, "r3", "asha", "approved")
    # waiting: no decision, not expired at the making
    await request(
        conn, made, "r4", "contained_b", "closure", t(0, 11), 21 * h, reason="rule_false_positive"
    )
    # a merge, weekly only, approved by one of one, applied (its case closed by it)
    r5 = await request(
        conn,
        made,
        "r5",
        "merged_src",
        "merge",
        t(-3),
        24 * h,
        reason="duplicate",
        target=made.cases["new_open"],
    )
    await decide(conn, made, "r5", "ravi", "approved")
    await conn.execute(
        text(
            "UPDATE cases SET state = 'closed', closed_at = :at, closure_reason = 'duplicate',"
            " closure_request_id = :r, merged_into_id = :m WHERE id = :c"
        ),
        {"at": t(-2, 1), "r": r5, "m": made.cases["new_open"], "c": made.cases["merged_src"]},
    )
    # a closure that closed its case: expired in the period but applied
    r9 = await request(
        conn,
        made,
        "r9",
        "closed_by_approval",
        "closure",
        t(-1, 10),
        34 * h,
        reason="remediated_verified",
    )
    await decide(conn, made, "r9", "ravi", "approved")
    await conn.execute(
        text(
            "UPDATE cases SET state = 'closed', closed_at = :at, closure_reason ="
            " 'remediated_verified', closure_request_id = :r WHERE id = :c"
        ),
        {"at": t(0, 18), "r": r9, "c": made.cases["closed_by_approval"]},
    )
    # a resend: asked and approved in the period; its outbox row went out again (sent_count 1 ->
    # 2, after the send it was asked at); expires in the period
    sent = await outbox(conn, made, "sent_twice", "sent", t(-1), sent=2, sent_at=t(0, 13))
    await request(conn, made, "r6", "assigned", "resend", t(0, 12), 11 * h, outbox=sent, sent=1)
    await decide(conn, made, "r6", "ravi", "approved")
    # a resend asked, undecided and expired in the period: nothing was sent for it
    stuck = await outbox(conn, made, "ambiguous", "ambiguous", t(-2), sent=1, sent_at=t(-2, 1))
    await request(conn, made, "r7", "assigned", "resend", t(-1, 6), 20 * h, outbox=stuck, sent=1)
    # a resend asked in the week, rejected
    await request(conn, made, "r8", "assigned", "resend", t(-2, 6), 20 * h, outbox=stuck, sent=1)
    await decide(conn, made, "r8", "ravi", "rejected")
    # compensating writes asked in the week, expiring in the period: one whose Kibana step went
    # out, one whose step never did
    comp = await outbox(conn, made, "comp_row", "sent", t(-2), sent=1, sent_at=t(-2, 1))
    r10 = await request(conn, made, "r10", "assigned", "compensating", t(-1, 12), 20 * h,
                        outbox=comp)  # fmt: skip
    await step(conn, made, "r10", comp, r10, 1)
    r11 = await request(conn, made, "r11", "assigned", "compensating", t(-1, 13), 20 * h,
                        outbox=comp)  # fmt: skip
    await step(conn, made, "r11", comp, r11, 0)
    # re-confirmations ARGUS asked for a held-back write: one went out afterwards, one did not
    held_out = await outbox(conn, made, "held_sent", "sent", t(-2), sent=1, sent_at=t(0, 5))
    await request(conn, made, "r12", "assigned", "reconfirm", t(-1, 14), 20 * h, outbox=held_out,
                  proposed_by="argus:sendcheck")  # fmt: skip
    held = await outbox(conn, made, "held", "paused", t(-2))
    await request(conn, made, "r13", "assigned", "reconfirm", t(-1, 15), 20 * h, outbox=held,
                  proposed_by="argus:sendcheck")  # fmt: skip
    # the rest of the outbox: backlog (planned, approved, sending), paused, conflict
    await outbox(conn, made, "planned_old", "planned", t(-2, 3))
    await outbox(conn, made, "planned_new", "planned", t(0, 20))
    await outbox(conn, made, "approved", "approved", t(0, 1))
    await outbox(conn, made, "sending", "sending", t(1, 1))
    await outbox(conn, made, "paused", "paused", t(-1))
    await outbox(conn, made, "conflict_a", "conflict", t(-1))
    await outbox(conn, made, "conflict_b", "conflict", t(0))
    await outbox(conn, made, "sent_in", "sent", t(-1), sent=1, sent_at=t(0, 23, 59, 59, 999999))
    await outbox(conn, made, "sent_at_end", "sent", t(-1), sent=1, sent_at=t(1))
    await outbox(
        conn, made, "sent_before", "sent", t(-3), sent=1, sent_at=t(-1, 23, 59, 59, 999999)
    )
    await outbox(conn, made, "verified", "verified", t(-1), sent=1, sent_at=t(-6))


# --------------------------------------------------------------------------- Kibana read-back


async def _kibana(conn: AsyncConnection, made: Seed) -> None:
    for i, (at_, outcome, stale) in enumerate(
        [
            (t(0), "complete", False),
            (t(0, 6), "complete", True),
            (t(0, 12), "partial", False),
            (t(0, 18), "failed", False),
            (t(0, 23, 59, 59, 999999), "complete", False),
            (t(1), "complete", False),
            (t(-1, 23), "failed", False),
            (t(-3), "partial", True),
        ]
    ):
        await ins(
            conn,
            "kibana_sync_cycles",
            started_at=at_,
            finished_at=at_ + timedelta(seconds=30),
            outcome=outcome,
            reads=3,
            changed=i,
            findings=0,
            stale=stale,
        )
    kinds = [
        "closed_in_kibana",
        "person_edited",
        "person_commented",
        "unexplained_argus_action",
        "alert_status_by_person",
        "settings_changed",
        "status_changed_in_kibana",
        "alert_change_unexplained",
        "argus_tags_changed",
        "deleted_in_kibana",
    ]
    # 24 findings in the period with lags 10, 20 ... 240 s (p95 = 10 x (1 + 0.95 x 23) = 228.5)
    for i in range(24):
        await ins(
            conn,
            "kibana_findings",
            found_at=t(0, 0, i * 59, 59),
            kind=kinds[i % len(kinds)],
            severity=("alarm", "attention", "info")[i % 3],
            dedupe_key=f"in-{i}",
            lag_s=10 * (i + 1),
            resolved_at=t(0, 23) if i % 4 == 0 else None,
        )
    # edge rows: the period's end (out), a microsecond before the start (out), no lag (in)
    await ins(
        conn,
        "kibana_findings",
        found_at=t(1),
        kind="closed_in_kibana",
        severity="alarm",
        dedupe_key="at-end",
        lag_s=9999,
    )
    await ins(
        conn,
        "kibana_findings",
        found_at=t(0, 0, 0, 0, -1),
        kind="person_edited",
        severity="attention",
        dedupe_key="before",
        lag_s=8888,
    )
    await ins(
        conn,
        "kibana_findings",
        found_at=t(0),
        kind="person_deleted",
        severity="alarm",
        dedupe_key="at-start-nolag",
    )
    # the week: a few lags on other days
    for i in range(3):
        await ins(
            conn,
            "kibana_findings",
            found_at=t(-2, i),
            kind="closed_in_kibana",
            severity="info",
            dedupe_key=f"week-{i}",
            lag_s=5 + i,
        )
    for i, (outcome, cls, when) in enumerate(
        [
            ("sent", "W1", t(0, 1)),
            ("sent", "W1", t(0, 2)),
            ("sent", "W2", t(0, 3)),
            ("ambiguous", "W1", t(0, 4)),
            ("conflict", "W2", t(0, 5)),
            ("refused", "W1", t(0, 6)),
            ("refused", "W3", t(0, 7)),
            ("failed", "W1", t(0, 8)),
            ("sent", "W3", t(1)),
            ("sent", "W1", t(-1, 23)),
            ("refused", "W2", t(-3)),
        ]
    ):
        await ins(
            conn,
            "action_ledger",
            at=when,
            idempotency_key=f"led-{i}",
            write_class=cls,
            method="POST",
            path="/api/cases",
            health="normal",
            switches={},
            outcome=outcome,
            elapsed_ms=5,
        )
    for cls, when, sent, verified, mism, amb in [
        ("W1", t(0, 2), 5, 4, 1, 0),
        ("W2", t(0, 3), 2, 2, 0, 0),
        ("W1", t(1), 9, 9, 0, 0),
        ("W1", t(-2), 3, 3, 0, 0),
        ("W3", t(0, 4), 0, 0, 0, 1),
    ]:
        await ins(
            conn,
            "kibana_writer_runs",
            write_class=cls,
            kind="scheduled",
            step=1,
            started_at=when,
            finished_at=when + timedelta(minutes=1),
            units=sent,
            sent=sent,
            verified=verified,
            mismatches=mism,
            ambiguous=amb,
            by="argus:test",
        )


# --------------------------------------------------------------------------- results


async def _investigation(conn: AsyncConnection, created: datetime) -> uuid.UUID:
    inv = uuid.uuid4()
    await ins(
        conn,
        "investigations",
        id=inv,
        grouping_version="2",
        rule_id="r",
        group_key=inv.hex,
        bucket_start=created,
        bucket_end=created + timedelta(days=1),
        previous_id=uuid.uuid4(),
        severity="high",
        alert_count=1,
        version=1,
        created_at=created,
        updated_at=created,
    )
    return inv


async def assessment(
    conn: AsyncConnection,
    made: Seed,
    created: datetime,
    finished: datetime | None,
    status: str,
) -> None:
    inv = await _investigation(conn, created)
    n = len(made.events) + 1
    made.events[f"assessment-{n}"] = n
    await ins(
        conn,
        "assessments",
        investigation_id=inv,
        version=1,
        pack="p",
        dossier_hash=HEX,
        view_hash=f"{n:064x}",
        assessor="engine",
        status=status,
        run_after=created,
        outcome="true_positive" if status == "proposed" else None,
        created_at=created,
        finished_at=finished,
    )


async def _results(conn: AsyncConnection, made: Seed) -> None:
    # 24 results finished in the period, taking 60, 120 ... 1440 s: p95 = 60 x (1 + 0.95 x 23)
    for i in range(24):
        finished = t(0, 0, 30 + i, 0)
        await assessment(
            conn, made, finished - timedelta(seconds=60 * (i + 1)), finished, "proposed"
        )
    await assessment(conn, made, t(0, 1), t(1), "proposed")  # finished exactly at the end: out
    await assessment(conn, made, t(-1, 1), t(-1, 2), "proposed")  # the day before: weekly only
    await assessment(conn, made, t(0, 1), t(0, 0, 0, 0, 0), "no_decision")
    await assessment(conn, made, t(0, 1), t(0, 5), "no_decision")
    await assessment(conn, made, t(0, 1), t(0, 6), "failed")
    await assessment(conn, made, t(-1), None, "queued")
    await assessment(conn, made, t(0, 22), None, "running")
    for i, (created, sent_at, state, err) in enumerate(
        [
            (t(0, 1), t(0, 2), "sent", None),
            (t(0, 3), None, "planned", None),
            (t(-1, 3), t(0, 0), "sent", None),
            (t(0, 4), None, "paused", "boom"),
            (t(1), t(1), "sent", None),
            (t(-2), t(-2, 1), "skipped", "gone"),
        ]
    ):
        inv = await _investigation(conn, created)
        await ins(
            conn,
            "writeback_outbox",
            review_id=1000 + i,
            investigation_id=inv,
            status="closed",
            alert_ids=["a"],
            state=state,
            created_at=created,
            sent_at=sent_at,
            error=err,
            sent_count=1 if state == "sent" else 0,
        )


# --------------------------------------------------------------------------- platform


async def _platform(conn: AsyncConnection, made: Seed) -> None:
    for lane, outcome, ms, when in [
        ("collector", "ok", 120, t(0, 1)),
        ("collector", "ok", 80, t(0, 2)),
        ("investigation", "ok", 4000, t(0, 3)),
        ("investigation", "overloaded", 10, t(0, 4)),
        (None, "ok", 7, t(0, 5)),
        ("kibana_read", "ok", 33, t(0, 6)),
        ("kibana_write", "breaker_open", 0, t(0, 7)),
        ("freshness", "ok", 500, t(0, 23)),
        ("collector", "ok", 1000, t(1)),
        ("collector", "ok", 2000, t(-1, 23, 59, 59, 999999)),
        ("identity", "ok", 25, t(-3)),
        ("collector", "ok", 6000, t(-4, 5)),
        ("measurement", "ok", 11, t(-2)),
        ("enrichment", "ok", 876, t(0, 20)),
        ("checking", "ok", 300, t(0, 21)),
    ]:
        await ins(
            conn,
            "siem_requests",
            at=when,
            component="collector",
            purpose="test",
            template="t",
            version=1,
            indices=["x"],
            outcome=outcome,
            took_ms=ms,
            elapsed_ms=ms,
            response_bytes=0,
            attempts=1,
            lane=lane,
        )
    for when, kind, end, subject in (
        (t(-1), "breaker_open", t(0, 1), "siem"),  # begins before, ends in: 60 minutes inside
        (t(0, 5), "source_stalled", t(0, 5, 30), "squid"),  # inside: 30 minutes
        (
            t(0, 22),
            "argus_collector_lag",
            None,
            "live",
        ),  # open: runs on to the making (and past end)
        (t(1), "rule_not_running", t(1, 2), "rule-a"),  # begins at the end: out
        (t(-2), "rule_gap_reported", t(-1, 23, 59), "rule-b"),  # ends before the period
        (t(-5), "truncated_execution", t(-5, 1), "rule-c"),  # weekly only
        # the collector's late stretches (D-321): caught up and checked (only gaps.late); two
        # whose first covering reconciliation found a difference (in its window); one longer
        # than an hour; one no reconciliation has covered yet
        (t(0, 8, 10), "argus_collector_lag", t(0, 8, 30), "alerts"),
        (t(0, 10, 10), "argus_collector_lag", t(0, 10, 30), "alerts"),
        (t(0, 12, 10), "argus_collector_lag", t(0, 12, 30), "alerts"),
        (t(0, 14, 10), "argus_collector_lag", t(0, 15, 10), "alerts"),
        (t(0, 16, 10), "argus_collector_lag", t(0, 16, 30), "alerts"),
    ):
        await ins(conn, "coverage_gaps", kind=kind, subject=subject, start_at=when, end_at=end)
    for started, first, last, differed, recovered in (
        (t(0, 8, 31), t(-1, 8), t(0, 8), 0, 0),  # after the close, the last hour not covered
        (t(0, 9, 31), t(-1, 9), t(0, 9), 0, 0),  # covers 08:10-08:30: late
        (t(0, 10, 31), t(-1, 10), t(0, 10), 0, 0),  # does not touch 10:10-10:30
        (t(0, 13, 5), t(-1, 13), t(0, 13), 1, 2),  # covers 10:10 and 12:10, found a difference
        (t(0, 16, 5), t(-1, 16), t(0, 16), 0, 0),  # covers 14:10-15:10, but over an hour
    ):
        await ins(
            conn, "reconciliation_runs", started_at=started, finished_at=started,
            window_start=first, window_end=last, hours=24, hours_mismatched=differed,
            recovered=recovered, missing_in_es=0, outcome="ok",
        )  # fmt: skip
    for state, when in [
        ("normal", t(0, 1)),
        ("normal", t(0, 2)),
        ("caution", t(0, 3)),
        ("degraded", t(0, 4)),
        ("stop", t(1)),
        ("stop", t(0, 0, 0, 0, -1)),
        ("normal", t(-3)),
    ]:
        await ins(
            conn,
            "siem_probes",
            at=when,
            state=state,
            reasons=[],
            probe_ok=True,
            auth_failed=False,
            blocked_indices=[],
        )
    for source, newest, checked, n, err in (
        (
            "abuse-ioc",
            AS_AT - timedelta(hours=5, minutes=59),
            AS_AT - timedelta(hours=1),
            1200,
            None,
        ),
        ("misp", None, None, None, "timeout"),
        ("clock-ahead", AS_AT + timedelta(hours=3), AS_AT + timedelta(minutes=90), 4, None),
        ("otx pulse", AS_AT - timedelta(days=3), AS_AT - timedelta(hours=26, seconds=-1), 0, None),
    ):
        await ins(
            conn,
            "ti_sources",
            source=source,
            newest=newest,
            checked_at=checked,
            indicators=n,
            error=err,
        )
    for when, actor, action, outcome in (
        (t(0, 1), "user:asha", "access", "denied"),
        (t(0), "user:asha", "access", "denied"),
        (t(0, 23, 59, 59, 999999), "user:ravi", "access", "denied"),
        (t(1), "user:ravi", "access", "denied"),
        (t(0, 0, 0, 0, -1), "user:ravi", "access", "denied"),
        (t(0, 2), "user:asha", "login", "denied"),
        (t(0, 3), "user:ravi", "stepup", "denied"),
        (t(0, 4), "user:ravi", "login", "success"),
        (t(0, 5), "argus:test", "case.opened", "success"),
        (t(-2), "user:asha", "login", "denied"),
        (t(-2), "user:asha", "access", "denied"),
    ):
        await ins(
            conn,
            "audit_events",
            occurred_at=when,
            actor=actor,
            action=action,
            outcome=outcome,
            details={},
        )
