"""The engine block names the organisation's own devices, accounts and sites as the affected side,
whichever of them opened the connection: a beaconing campus device acts, and is what is at risk
(the lead's walk of production, 7 Nov: campus devices were shown as "Outside address")."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from argus.web.v1 import engine_routes

pytestmark = pytest.mark.unit

WHEN = datetime(2026, 11, 7, tzinfo=UTC)


def test_campus_objects_are_the_affected_side() -> None:
    row = SimpleNamespace(
        id=1, priority=90, band="P1", certainty="Likely", raised_by_ai=False, first_seen=WHEN,
        last_seen=WHEN, version=1, changed=[], view={"objects": [
            {"kind": "device", "label": "10.20.30.40", "role": "actor"},
            {"kind": "account", "label": "USER_1", "role": "actor"},
            {"kind": "site", "label": "www.example.edu", "role": "actor"},
        ]},
    )  # fmt: skip
    roles = [(o.kind, o.role) for o in engine_routes.engine_view(row).objects]
    assert roles == [("device", "affected"), ("account", "affected"), ("site", "affected")]
