"""Discovery on a self-managed Elastic stack with Logstash-style names: weekly (``2026.45``) and
monthly (``2026.11``) log indices are families, and with alerts in several spaces the busiest is
proposed (the one with the most alerts indices), not the first by name."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from argus.discover import propose
from argus.discover.classify import candidates

pytestmark = pytest.mark.unit


def test_weekly_and_monthly_indices_are_families() -> None:
    listing = {"indices": [{"name": n} for n in (
        "corp-logs-mail_auth-2026.45", "corp-logs-mail_auth-2026.46", "corp-logs-web-2026.10",
        "corp-logs-web-2026.11", "corp-logs-dns-2026.11.16", "corp-logs-bad-2026.54")]}  # fmt: skip
    skipped: list[str] = []
    found = {c.pattern: c for c in candidates(listing, skipped)}
    assert found["corp-logs-mail_auth-*"].period == "week"
    assert found["corp-logs-mail_auth-*"].days == ("2026.11.02", "2026.11.09")
    assert found["corp-logs-web-*"].period == "month"
    assert found["corp-logs-web-*"].days == ("2026.10.01", "2026.11.01")
    assert found["corp-logs-dns-*"].period == "day"
    assert "corp-logs-bad-*" not in found
    assert skipped == ["corp-logs-bad-2026.54"]


def test_the_busiest_space_is_proposed() -> None:
    alerts = {"aliases": [
        {"name": ".alerts-security.alerts-cloud", "indices": ["a1"]},
        {"name": ".alerts-security.alerts-soc", "indices": ["b1", "b2", "b3"]},
        {"name": ".alerts-security.alerts-default", "indices": ["c1"]}]}  # fmt: skip
    inputs = propose.Inputs(alerts=alerts, spaces=[{"id": "cloud"}, {"id": "default"},
                                                   {"id": "soc"}])  # fmt: skip
    warnings: list[str] = []
    chosen, _why, _aliases, _spaces = propose._space(inputs, warnings)
    assert chosen == "soc"
    assert "soc, the one with the most alerts indices, is proposed" in warnings[0]
    assert datetime.now(UTC)  # (no clock in this rule)
