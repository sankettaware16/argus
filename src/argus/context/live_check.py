"""The first production runs of the log templates (R12, R13; D-056, D-068, D-069).

* ``web``: one ``web.followups`` search inside a live-test session, within its limits
  (15 minutes of nginx, at most 10 rows).
* ``proxy``: live tests never aggregate (the gateway refuses), so the two proxy aggregations
  run once as a measured job the user confirms at the terminal, under the normal budget and
  health gate (a user-approved, journaled, budgeted job), over one hour of
  squid inside one daily index.

Subjects come from the stored alerts. Each request's server time is printed; a part passes
when every request answers in time. Nothing is stored but the gateway's ledger."""

from __future__ import annotations

import ipaddress
from collections.abc import Awaitable, Callable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus import site
from argus.context.proxy import MARGIN, ProxyDestination, ProxyHost, WindowParams, _days
from argus.context.web import FollowParams, WebFollowups
from argus.gateway.gateway import Result
from argus.gateway.templates import Params, Template
from argus.site import Role, reads, source_param

Run = Callable[[Template, Params], Awaitable[Result]]
SLOW_MS = {"proxy.host": 10_000, "proxy.destination": 10_000, "web.followups": 3_000}


def _public(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _private(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def _remember(found: dict[str, str | None], key: str, role: Role, indices: str | None) -> None:
    """Note which family of ``role`` the subject's rule reads, only when the site has two or more
    (a one-family site's requests carry no source)."""
    named = source_param(role, [indices or ""])
    if named is not None:
        found[key] = named


async def subjects(conn: AsyncConnection) -> dict[str, str | None]:
    """An internal proxy host, an outside destination and a web client from the newest
    stored alerts of rules that read squid and nginx."""
    found: dict[str, str | None] = {"host": None, "destination": None, "client": None}
    rows = await conn.execute(
        text(
            "SELECT raw #>> '{source,ip}' AS src, raw #>> '{destination,ip}' AS dst,"
            " raw ->> 'kibana.alert.rule.indices' AS indices FROM alert_records"
            " WHERE status = 'normalized' ORDER BY detected_at DESC LIMIT 2000"
        )
    )
    for row in rows:
        squid, nginx = reads([row.indices or ""], Role.PROXY), reads([row.indices or ""], Role.WEB)
        if squid and found["host"] is None and row.src and _private(row.src):
            found["host"] = row.src
            _remember(found, "host_source", Role.PROXY, row.indices)
        if squid and found["destination"] is None and row.dst and _public(row.dst):
            found["destination"] = row.dst
            _remember(found, "destination_source", Role.PROXY, row.indices)
        if nginx and found["client"] is None and row.src:
            found["client"] = row.src
            _remember(found, "client_source", Role.WEB, row.indices)
        if all(found[key] for key in ("host", "destination", "client")):
            break
    return found


def window(
    now: datetime, length: timedelta = timedelta(hours=1)
) -> tuple[datetime, datetime] | str:
    """The last full ``length`` before the ingest margin, inside one daily index; or why not
    now."""
    if site.in_quiet_hours(now):
        quiet = site.quiet_hours()
        return (
            f"{quiet.start} to {quiet.end} UTC is the SIEM's busy time (index creation):"
            f" try after {quiet.end}"
        )
    step = int(length.total_seconds() // 60)
    cut = now - MARGIN
    end = cut.replace(minute=cut.minute - cut.minute % step if step < 60 else 0, second=0,
                      microsecond=0)  # fmt: skip
    start = end - length
    if _days(start, end) > 1:
        return "the last hour touches midnight's index change: try between 02:15 and 23:14 UTC"
    return start, end


LIVE_WINDOW = timedelta(minutes=15)  # the live-test tier's limit (plan §10)
LIVE_ROWS = 10


async def check(
    conn: AsyncConnection, run: Run, now: datetime | None = None, part: str = "web"
) -> list[str]:
    """Run one part (``web`` or ``proxy``); the last line is LIVE CHECK PASSED or FAILED."""
    length = LIVE_WINDOW if part == "web" else timedelta(hours=1)
    span = window(now or datetime.now(UTC), length)
    if isinstance(span, str):
        return [f"not now: {span}", "LIVE CHECK FAILED"]
    start, end = span
    who = await subjects(conn)
    lines = [f"window {start:%Y-%m-%d %H:%M} to {end:%H:%M} UTC; subjects {who}"]
    plans: Sequence[tuple[Template, Params | None]]
    if part == "web":
        client = who["client"]
        follow = (
            FollowParams(
                ip=client, start=start, end=end, size=LIVE_ROWS, source=who.get("client_source")
            )
            if client
            else None
        )
        plans = ((WebFollowups(), follow),)
    else:
        plans = (
            (ProxyHost(), WindowParams(ip=who["host"], start=start, end=end,
                                       source=who.get("host_source")) if who["host"] else None),
            (ProxyDestination(), WindowParams(ip=who["destination"], start=start, end=end,
                                              source=who.get("destination_source"))
             if who["destination"] else None),
        )  # fmt: skip
    ok = True
    for template, params in plans:
        if params is None:
            lines.append(f"{template.name}: no subject in the stored alerts (skipped)")
            ok = False
            continue
        result = await run(template, params)
        slow = result.took_ms > SLOW_MS[template.name]
        ok = ok and not slow
        lines.append(f"{template.name}: {result.took_ms} ms server time"
                     f"{' (too slow)' if slow else ''}; {_shape(result.body)}")  # fmt: skip
    lines.append("LIVE CHECK " + ("PASSED" if ok else "FAILED"))
    return lines


def _shape(body: dict[str, Any]) -> str:
    aggs = body.get("aggregations") or {}
    if aggs:
        values = {k: (v.get("value") if "value" in v else len(v.get("buckets", [])))
                  for k, v in sorted(aggs.items())}  # fmt: skip
        return ", ".join(f"{k} {v}" for k, v in values.items())
    return f"{len(body.get('hits', {}).get('hits', []))} rows"
