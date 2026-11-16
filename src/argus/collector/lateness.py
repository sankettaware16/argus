"""Whether a stretch the collector could not poll was an outage or only lateness (D-321).

A failed poll opens a gap (``argus_collector_lag``) from the live cursor; the next poll that
works reads everything from that cursor (so the gap closes only once the poll caught up) and
reconciliation then compares the SIEM's alerts with the store, hour by hour. A gap reads:

- ``late``: ARGUS collected late, caught up and missed nothing. The gap closed within
  :data:`LATE_WITHIN`, and the first reconciliation that began after it closed and covered all
  its hours finished, and neither it nor any reconciliation between the close and it that touched
  those hours found an hour that differed or an alert to recover.
- ``late_unchecked``: closed within :data:`LATE_WITHIN`, but no such reconciliation has finished
  yet (the hour the gap ended in is reconciled from the next hour on). Alerts may still be missing.
- ``outage``: everything else: a gap still open, one that lasted :data:`LATE_WITHIN` or more, one
  whose reconciliation found differences, and every gap of another kind.

The counts of a reconciliation are its whole window's (24 hours), not the gap's own hours: a
difference anywhere in it keeps the gap an outage (the stricter reading). :data:`LATE_WITHIN` is
the notices' :data:`argus.notices.model.OUTAGE_AFTER`: a gap is noticed only once it has lasted
that long, so a gap that reads ``late`` was never announced as an outage on its own. (The notices
follow the kind, not one gap: short gaps back to back, one open at every 10-minute pass for an
hour, are announced as one outage even if each later reads ``late``.)
"""

from __future__ import annotations

from datetime import timedelta
from typing import Literal

LATE_KIND = "argus_collector_lag"
LATE_WITHIN = timedelta(hours=1)
Reading = Literal["outage", "late", "late_unchecked"]
READINGS: tuple[Reading, ...] = ("outage", "late", "late_unchecked")


def reading_sql(gap: str = "g", asof: str | None = None) -> str:
    """A SQL expression giving the reading (``late``, ``late_unchecked`` or ``outage``) of the
    ``coverage_gaps`` row aliased ``gap``. ``asof``: a SQL timestamp expression; reconciliations
    that began after it are not seen (a report as at its making). Only whole-hour run windows
    are stored, so "covers the gap's hours" is ``window_start <= start_at AND window_end >=
    end_at`` and "touches them" is ``window_start < end_at AND window_end > start_at``."""
    seen = "" if asof is None else f" AND r.started_at <= {asof}"
    first_check = (
        "SELECT min(r.started_at) FROM reconciliation_runs r"  # noqa: S608 - constant fragments
        f" WHERE r.outcome = 'ok' AND r.started_at >= {gap}.end_at{seen}"
        f" AND r.window_start <= {gap}.start_at AND r.window_end >= {gap}.end_at"
    )
    seconds = int(LATE_WITHIN.total_seconds())
    still_open = "" if asof is None else f" OR {gap}.end_at > {asof}"  # open as at ``asof``
    return (
        f"(CASE WHEN {gap}.kind <> '{LATE_KIND}' OR {gap}.end_at IS NULL{still_open}"  # noqa: S608
        f" OR {gap}.end_at - {gap}.start_at >= interval '{seconds} seconds' THEN 'outage'"
        " WHEN EXISTS (SELECT 1 FROM reconciliation_runs r"
        f" WHERE r.started_at >= {gap}.end_at{seen}"
        f" AND r.started_at <= coalesce(({first_check}), 'infinity')"
        f" AND r.window_start < {gap}.end_at AND r.window_end > {gap}.start_at"
        " AND (r.hours_mismatched > 0 OR r.recovered > 0)) THEN 'outage'"
        f" WHEN ({first_check}) IS NOT NULL THEN 'late'"
        " ELSE 'late_unchecked' END)"
    )
