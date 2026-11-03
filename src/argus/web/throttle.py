"""The one sign-in throttle (plan §7.2 step 3), for every way in: ``/signin``, ``/login``,
``/api/login`` and the step-up page.

Only a **refusal that counts** is counted: a wrong password that Elasticsearch (or, in local
mode, the account's hash) refused. A check ARGUS never made (a reserved name, a locked name, a
wait not over, ELK not reachable, an account ARGUS refuses after a right password) is written
to the audit trail but counts for nothing, so a request every few minutes cannot keep a name
locked: the old throttle counted its own refusals.

* **Exponential waits per name and client:** after the second counted refusal of a name from
  a client the next check waits ``web.signin_delay_s``, then twice, four times that (the fifth
  refusal locks the name). An attempt inside the wait is answered like any failure, unread.
* **5 counted refusals of a name in 15 minutes lock it**; **20 from a client** lock the client;
  **60 an hour across all names** lock everyone, and an alarm goes up (once an hour).
* **A device cookie** from an earlier good sign-in to that name passes all three locks (not the
  waits): the person is not shut out by someone else's guesses. In ELK mode "that name" is the
  account's exact ELK name, never its ARGUS handle: one person's cookie is nobody else's key.
* **The emergency account is outside the counts and the locks** (``signin``): its one-time
  password has 144 bits, so a guess needs no limit, and a limit would be a way to lock the holder
  out in the middle of an outage.
* Step-up failures count like sign-in failures; three end the session (``auth``).

Counts come from the audit trail (``audit_events``, the database's clock): failures are
recorded by the name's HMAC in ELK mode, by the name in local mode.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.web import auth

WINDOW = timedelta(minutes=15)
HOUR = timedelta(hours=1)
NAME_LIMIT = 5
CLIENT_LIMIT = 20
SPRAY_LIMIT = 60
MAX_WAIT = WINDOW
ALARM_ACTION = "signin.alarm"


class Verdict(StrEnum):
    GO = "go"
    DELAYED = "delayed"  # a wait between checks is not over
    NAME_LOCKED = "name_locked"
    CLIENT_LOCKED = "client_locked"
    SPRAY_LOCKED = "spray_locked"


@dataclass(frozen=True)
class Standing:
    """What the audit trail says about one name from one client, as of now."""

    name: int = 0  # counted refusals of this name within WINDOW
    pair: int = 0  # ... from this client
    pair_age_s: float | None = None  # seconds since the newest of those
    client: int = 0  # counted refusals from this client within WINDOW, any name
    hour: int = 0  # counted refusals within the hour, any name, any client


def wait_for(pair_refusals: int, base: timedelta) -> timedelta:
    """How long after its last counted refusal a name from a client waits for the next check:
    none after the first, ``base`` after the second, twice that after the third, and so on."""
    if pair_refusals < 2 or base <= timedelta(0):
        return timedelta(0)
    wait: timedelta = base * 2 ** min(pair_refusals - 2, 30)  # no overflow for a long spray
    return min(wait, MAX_WAIT)


def decide(standing: Standing, *, device: bool, base: timedelta) -> Verdict:
    """Pure: whether a check may be made. A device cookie passes the locks, not the waits."""
    if not device:
        if standing.hour >= SPRAY_LIMIT:
            return Verdict.SPRAY_LOCKED
        if standing.client >= CLIENT_LIMIT:
            return Verdict.CLIENT_LOCKED
        if standing.name >= NAME_LIMIT:
            return Verdict.NAME_LOCKED
    wait = wait_for(standing.pair, base)
    if (
        wait > timedelta(0)
        and standing.pair_age_s is not None
        and standing.pair_age_s < wait.total_seconds()
    ):
        return Verdict.DELAYED
    return Verdict.GO


_STANDING = """
SELECT
  count(*) FILTER (WHERE occurred_at > :now - make_interval(secs => :w) AND k = :key),
  count(*) FILTER (WHERE occurred_at > :now - make_interval(secs => :w) AND k = :key
                   AND details->>'client' = :client),
  extract(epoch FROM :now - max(occurred_at) FILTER (
      WHERE occurred_at > :now - make_interval(secs => :w) AND k = :key
      AND details->>'client' = :client)),
  count(*) FILTER (WHERE occurred_at > :now - make_interval(secs => :w)
                   AND details->>'client' = :client),
  count(*)
FROM (SELECT occurred_at, details, coalesce(details->>'name_hmac', details->>'username') AS k
      FROM audit_events
      WHERE action IN ('login', 'stepup') AND outcome = 'denied'
        AND details->>'counted' = 'true'
        AND occurred_at > :now - make_interval(secs => :h)) AS refusals
"""


async def read_standing(
    conn: AsyncConnection, name_key: str, client: str, *, now: datetime | None = None
) -> Standing:
    """The counts for ``name_key`` (the name as the trail records it) from ``client``. ``now``
    is the database's clock unless a test names a time."""
    stamp = now if now is not None else (await conn.execute(text("SELECT clock_timestamp()"))
                                         ).scalar_one()  # fmt: skip
    row = (
        await conn.execute(
            text(_STANDING),
            {"now": stamp, "key": name_key, "client": client, "w": WINDOW.total_seconds(),
             "h": HOUR.total_seconds()},
        )
    ).one()  # fmt: skip
    return Standing(
        name=int(row[0]),
        pair=int(row[1]),
        pair_age_s=None if row[2] is None else float(row[2]),
        client=int(row[3]),
        hour=int(row[4]),
    )


_DEVICE_BY_ELK_NAME = (
    "SELECT 1 FROM user_devices d JOIN users u ON u.id = d.user_id"
    " WHERE d.token_hash = :t AND NOT u.disabled AND u.elk_username = :n"
)
_DEVICE_BY_HANDLE = (
    "SELECT 1 FROM user_devices d JOIN users u ON u.id = d.user_id"
    " WHERE d.token_hash = :t AND NOT u.disabled AND u.username = :n"
)


async def device_known(
    conn: AsyncConnection, token_hash: str | None, name: str, *, elk: bool
) -> bool:
    """Whether ``token_hash`` is a device cookie from an earlier good sign-in to the account
    that goes by ``name``: in ELK mode (``elk``) its exact ELK name and nothing else, in local
    mode its ARGUS name. The two must not mix: an ELK name can equal another person's handle,
    and a cookie of one person would pass, and void the approvals of, the other."""
    if not token_hash:
        return False
    found = await conn.scalar(
        text(_DEVICE_BY_ELK_NAME if elk else _DEVICE_BY_HANDLE), {"t": token_hash, "n": name}
    )
    return found is not None


async def record(
    conn: AsyncConnection,
    *,
    action: str,
    name_field: str,
    name_key: str,
    client: str,
    counted: bool,
    why: str | None = None,
) -> None:
    """A refusal in the audit trail: ``counted`` says whether the throttle counts it. The name
    is the trail's own form (``username``: a valid ARGUS name, or ``name_hmac``)."""
    details: dict[str, object] = {name_field: name_key, "client": client, "counted": counted}
    if why is not None:
        details["why"] = why
    await auth.audit(conn, actor="web", action=action, outcome="denied", details=details)


async def raise_alarm_if_due(conn: AsyncConnection) -> bool:
    """At the spray limit (counted refusals across all names within an hour), an alarm: one
    audit event an hour, which ``argus doctor`` shows. True when this call raised it.

    Called after a refusal is recorded (its own row counted) and when the spray lock itself
    answers, never from a standing read before the insert: checks that overlap each read the
    same count, and none of them would see the limit crossed by the others. Raisers take turns
    without waiting (a try-lock): one that finds another raising it has nothing to add."""
    hour = await conn.scalar(
        text(
            "SELECT count(*) FROM audit_events WHERE action IN ('login', 'stepup')"
            " AND outcome = 'denied' AND details->>'counted' = 'true'"
            " AND occurred_at > clock_timestamp() - make_interval(secs => :h)"
        ),
        {"h": HOUR.total_seconds()},
    )
    if int(hour or 0) < SPRAY_LIMIT:
        return False
    taken = await conn.scalar(
        text("SELECT pg_try_advisory_xact_lock(hashtextextended('argus.signin.alarm', 0))")
    )
    if not taken:
        return False
    recent = await conn.scalar(
        text(
            "SELECT 1 FROM audit_events WHERE action = :a"
            " AND occurred_at > clock_timestamp() - make_interval(secs => :h) LIMIT 1"
        ),
        {"a": ALARM_ACTION, "h": HOUR.total_seconds()},
    )
    if recent is not None:
        return False
    await auth.audit(conn, actor="web", action=ALARM_ACTION, outcome="failure",
                     details={"refused_checks_in_an_hour": int(hour or 0)})  # fmt: skip
    return True
