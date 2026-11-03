"""§7.1's read load at projected case counts (Q-D3): how many small reads a day the read-back
makes, what they cost the Kibana read lane (plan §7.8: 200 ms a minute, 4 minutes a day, D-131)
and whether one cycle fits the lane's minute share. Pure; ``argus kibana sync model`` prints it.

Per day, with ``C`` open or in-progress cases of ARGUS, ``K`` closed ones, ``X`` changed
cases and ``W`` writes (Q-D4's read-back after each):

- ``kibana.status``: 24 (hourly) plus one per write run;
- the change poll: one ``cases.find`` per cycle (144 at 10 minutes), more pages only when
  more than 100 cases changed in one cycle;
- the listings (the id-set diff): ``ceil(C_open/100) + ceil(C_in_progress/100)`` finds a
  cycle (at least one each), and the closed ones, ``ceil(K/100)``, once a day and again after
  each closed case that is deleted;
- the closed probe: one ``cases.find`` of one closed case per cycle, whose ``total`` is
  compared with the mirror (a closed case deleted shows within a cycle, not a day);
- user actions: two pages per changed case (``2X``: a case changed moments ago is read once
  more at the next cycle, for Kibana writes the case and its user action separately),
  deletions one ``cases.get`` each;
- the case team's cases (P4-B1, D-270) add no request to the finds above (the same finds name
  the team's users as reporters too) and ``T`` to ``X``: each case the team posts changes in a
  few cycles (its steps are written over minutes, up to an hour with the alert pauses), and a
  person's later edit, close or comment is one more;
- discovery (hourly): at most ``diff_calls`` searches of the alerts on ARGUS's open and
  recent cases (a rotating slice: the alerts of all of them are looked at once every
  ``sweep_hours`` hours, however many there are) and ``discovery_calls`` searches of known
  alerts, plus one get per new people's case;
- one read-back per write (``W``).

Each read is charged max(round trip, its template's estimate): 100 ms a find or user-action
page, 50 ms a get, status or search (Q-D2, decision 9); the measured round trips replace them
after the read-only days (§7.8).
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import timedelta

FIND_MS = 100
PAGE_MS = 100
GET_MS = 50
STATUS_MS = 50
SEARCH_MS = 50
LANE_DAY_MS = 4 * 60 * 1000  # §7.8: the Kibana read lane's day
LANE_MINUTE_MS = 200  # its minute share (D-131; the burst is one minute's share)


@dataclass(frozen=True)
class Load:
    open_cases: int
    in_progress: int
    closed: int
    changed_per_day: int
    writes_per_day: int
    deletions_per_day: int = 0
    people_cases_per_day: int = 0
    team_changed_per_day: int = 0  # T: case-team cases read again after a change (cycles)
    interval: timedelta = timedelta(minutes=10)
    discovery_calls: int = 3  # searches of known alerts per discovery (SyncConfig)
    diff_calls: int = 5  # searches of the alerts on ARGUS's cases per discovery (SyncConfig)
    alerts_per_case: int = 20  # alerts attached to an open case, on average
    per_page: int = 100


@dataclass(frozen=True)
class Estimate:
    reads_per_day: int
    lane_ms_per_day: int
    cycle_reads: int  # a quiet cycle's reads
    cycle_ms: int
    lane_day_share: float  # of the Kibana read lane's 4 minutes
    cycle_minutes: float  # minutes of the lane's minute share a quiet cycle needs
    fits: bool  # within the lane's day, and a quiet cycle within its interval
    parts: dict[str, int]
    sweep_hours: int = 1  # hours until every alert on the open cases was looked at once


def _pages(n: int, per: int) -> int:
    return max(1, math.ceil(n / per))


def estimate(load: Load) -> Estimate:
    cycles = int(timedelta(days=1) / load.interval)
    per = load.per_page
    listings = _pages(load.open_cases, per) + _pages(load.in_progress, per)
    live = load.open_cases + load.in_progress
    # a sweep of the alerts on the live cases: one search per batch of 100 cases at least,
    # one per 100 alerts; each discovery makes at most diff_calls of them
    sweep = max(_pages(live, per), math.ceil(live * load.alerts_per_case / per))
    diff = min(load.diff_calls, sweep)
    parts = {
        "kibana.status": 24 + math.ceil(load.writes_per_day / 10),
        "change polls": cycles * max(1, math.ceil(load.changed_per_day / cycles / per)),
        "listings": cycles * listings + _pages(load.closed, per) * (1 + load.deletions_per_day),
        "closed probes": cycles,
        "user actions": 2 * (load.changed_per_day + load.team_changed_per_day),
        "deletion gets": load.deletions_per_day,
        "discovery searches": 24 * (diff + load.discovery_calls),
        "people's case gets": load.people_cases_per_day,
        "write read-backs": load.writes_per_day,
    }
    cost = {
        "kibana.status": STATUS_MS,
        "change polls": FIND_MS,
        "listings": FIND_MS,
        "closed probes": FIND_MS,
        "user actions": PAGE_MS,
        "deletion gets": GET_MS,
        "discovery searches": SEARCH_MS,
        "people's case gets": GET_MS,
        "write read-backs": GET_MS,
    }
    reads = sum(parts.values())
    lane_ms = sum(parts[k] * cost[k] for k in parts)
    cycle_reads = 2 + listings  # the poll, the listings and the closed probe
    cycle_ms = FIND_MS * cycle_reads
    cycle_minutes = cycle_ms / LANE_MINUTE_MS
    return Estimate(
        reads_per_day=reads,
        lane_ms_per_day=lane_ms,
        cycle_reads=cycle_reads,
        cycle_ms=cycle_ms,
        lane_day_share=lane_ms / LANE_DAY_MS,
        cycle_minutes=cycle_minutes,
        fits=lane_ms <= LANE_DAY_MS and cycle_minutes < load.interval.total_seconds() / 60,
        parts=parts,
        sweep_hours=math.ceil(sweep / diff) if diff else 1,
    )


# The plan's example (100 cases, 50 writes a day), the exit's projection and a year's: DQ4
# opens cases only for incidents a person confirms (≤ 20 an hour); Phase 2 confirmed about
# 19 true positives in 36 gold items, so a few new cases a day, most closed within weeks.
SCENARIOS: dict[str, Load] = {
    "plan §7.1 (100 cases, 50 writes)": Load(60, 40, 0, 60, 50),
    "exit (2027-02, ~100 live, 150 closed)": Load(
        60, 40, 150, 60, 50, 1, 2, team_changed_per_day=40
    ),
    "a year (~150 live, 1,500 closed)": Load(90, 60, 1_500, 90, 80, 2, 3, team_changed_per_day=60),
    "busy (500 live, 3,000 closed)": Load(300, 200, 3_000, 300, 200, 5, 10),
}
