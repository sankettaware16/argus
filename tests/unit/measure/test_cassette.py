"""A whole session replayed from a strict cassette (Q-A3's gate: guard tests and cassette
replay). The cassette pins every request the session may send at 10:00 UTC on 2026-10-23:
a request it does not hold fails the session instead of being sent anywhere. It was recorded
from the scripted the SIEM of fakes.py (synthetic values only):

    MEASURE_RECORD=1 uv run pytest tests/unit/measure/test_cassette.py
"""

from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path

import pytest

from argus.gateway.cassettes import CassetteTransport
from argus.measure.session import COMPONENT, LIMITS, MINUTE, verify
from tests.unit.measure.fakes import T0, plan_at, rig

pytestmark = pytest.mark.unit

CASSETTE = Path(__file__).parent / "data" / "session.cassette.json"
RECORD = os.environ.get("MEASURE_RECORD") == "1"


async def test_the_session_replays_from_its_cassette() -> None:
    cassette: CassetteTransport | None = None

    def through(elastic: object) -> CassetteTransport:
        nonlocal cassette
        if RECORD:
            CASSETTE.unlink(missing_ok=True)
            cassette = CassetteTransport(CASSETTE, "record", inner=elastic)  # type: ignore[arg-type]
        else:
            cassette = CassetteTransport(CASSETTE, "replay")
        return cassette

    r = rig(inner=through)
    report = await r.session.run()
    if RECORD:
        assert cassette is not None
        cassette.save()
    assert report.stopped is None, report.stopped
    assert report.complete
    assert report.requests_sent <= LIMITS.max_requests
    assert report.heavy_sent == 6
    assert {s.outcome for s in report.samples} == {"ok"}
    if not RECORD:
        assert r.elastic.calls == []  # replay: nothing reached the scripted the SIEM either
    rows = await r.store.requests_since(T0 - MINUTE)
    verdict = verify(rows, await r.store.probes_since(T0 - MINUTE), report.started,
                     report.ended or r.clock(), requests_sent=report.requests_sent)  # fmt: skip
    assert verdict.passed, verdict.problems
    assert {row.component for row in rows} == {COMPONENT}  # its index listings included


def test_the_cassette_holds_only_synthetic_values() -> None:
    text = CASSETTE.read_text(encoding="utf-8")
    assert "10.20." not in text  # the suite's SIEM's network
    for own in ("example.edu", "example-univ.org", "131.21.12"):  # the site's domains and range
        assert own not in text.lower()


async def test_a_request_the_cassette_does_not_hold_ends_the_session_unsent() -> None:
    """A plan made an hour later asks other windows: the first one the cassette lacks ends
    the session (strict replay), and nothing reaches the scripted the SIEM."""
    r = rig(inner=lambda _elastic: CassetteTransport(CASSETTE, "replay"),
            plan=plan_at(T0 + timedelta(hours=1)))  # fmt: skip
    report = await r.session.run()
    assert report.stopped is not None
    assert "cassette_miss" in report.stopped
    assert r.elastic.calls == []
