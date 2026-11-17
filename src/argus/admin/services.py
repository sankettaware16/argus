"""ARGUS's services and timers in the app (D-329): what each does in plain words, whether it runs
here, and the switch. A unit is switched on or off by ``units.run`` (written to ``admin.yaml``, so
a deploy and ``argus doctor`` agree) and ``systemctl --user enable --now`` / ``disable --now``;
a long-running service may be restarted. ARGUS's core services are never switched off from the
app, and argus-admin never restarts itself."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from argus.ops.units import CORE, MANIFEST, Role

LABELS = {
    "argus-collector.service": "Collector: takes in the SIEM's alerts every minute",
    "argus-worker.service": "Worker: gathers the evidence of each investigation",
    "argus-web.service": "The web app",
    "argus-assess.service": "Assessments: proposes outcomes, runs the AI investigator",
    "argus-admin.service": "Applies the changes made in the app",
    "argus-risk.timer": "Incident engine: turns alerts into possible incidents (every 10 minutes)",
    "argus-risk-check.timer": "Checking lane: the incidents' evidence and exposure checks",
    "argus-backup.timer": "Nightly database backup",
    "argus-backup-drill.timer": "Weekly restore drill of the latest backup",
    "argus-purge.timer": "Retention purge: deletes what is older than the retention periods",
    "argus-notices.timer": "Notices: short e-mails about new incidents",
    "argus-report-daily.timer": "Daily report",
    "argus-report-weekly.timer": "Weekly report",
    "argus-kibana-sync.service": "Kibana read-back: reads Kibana cases and writes verdict comments",
    "argus-case-team.timer": "Kibana case team: posts confirmed incidents as Kibana cases",
    "argus-writer.service": "Kibana writer: alert status and case writes",
    "argus-soak-sample.timer": "Soak samples (a measuring period)",
    "argus-soak-phase3.timer": "Soak gate, daily (a measuring period)",
}
# Switching one of these on lets ARGUS write to the SIEM: a step-up and the typed words.
SIEM_WRITES = frozenset({"argus-kibana-sync.service", "argus-case-team.timer",
                         "argus-writer.service"})  # fmt: skip
# Deletes data when it runs: a step-up.
DESTRUCTIVE = frozenset({"argus-purge.timer"})
ACTIONS = ("on", "off", "restart")


def switchable(unit: str) -> bool:
    role = MANIFEST.get(unit, (Role.TRIGGERED, ""))[0]
    return role in (Role.CHOICE, Role.SOON, Role.OFF)


def check(unit: str, action: str) -> None:
    """ValueError when the app may not do ``action`` to ``unit``."""
    if unit not in MANIFEST or MANIFEST[unit][0] is Role.TRIGGERED:
        raise ValueError(f"{unit} is not one of ARGUS's services or timers")
    if action not in ACTIONS:
        raise ValueError("on, off or restart")
    if action == "restart":
        if not unit.endswith(".service") or unit == "argus-admin.service":
            raise ValueError(f"{unit} cannot be restarted from the app")
    elif not switchable(unit):
        raise ValueError(f"{unit} is one of ARGUS's core services: it always runs")


def run_after(run: Sequence[str] | None, unit: str, on: bool) -> list[str]:
    now = list(CORE if run is None else run)
    if on and unit not in now:
        now.append(unit)
    if not on:
        now = [u for u in now if u != unit]
    return now


def listing(run: Sequence[str] | None, active: Any) -> list[dict[str, Any]]:
    """Each service and timer, whether it is meant to run here and whether it runs."""
    chosen = set(CORE if run is None else run)
    return [
        {"unit": name, "label": LABELS.get(name, name), "core": role is Role.RUN,
         "switchable": switchable(name), "on": name in chosen, "running": bool(active(name)),
         "writes_siem": name in SIEM_WRITES, "deletes": name in DESTRUCTIVE}
        for name, (role, _) in MANIFEST.items() if role is not Role.TRIGGERED
    ]  # fmt: skip
