"""AR2b's step of an assessment pass (D-160), as ``argus assess run`` takes it: the flags of new
dossiers are stored on every pass, cases are suggested at most every 15 minutes and only while
``cases.suggest`` is on, and a failure is said, never raised."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus import raising
from argus.assess import raised
from argus.assets.classify import IpClassifier
from tests.integration.assess.test_raised_db import BEACON, LISTED, NOW, in_attention, make
from tests.integration.cases.conftest import rows

pytestmark = pytest.mark.integration
CLASSIFIER = IpClassifier(None)
POISON = {"name": "poison", "status": "known", "value": 1}


async def story(owner: AsyncEngine) -> None:
    """One host, a download and a beacon, both flagged and low or medium."""
    await make(owner, severity="low", signals=(BEACON, LISTED), host=1, rule="download")
    await make(owner, severity="medium", signals=(BEACON, LISTED), host=1, rule="beacon")


async def test_every_pass_reads_the_evidence_and_suggests_every_fifteen_minutes(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await story(migrated_engine)
    first = await raising.run(app_engine, CLASSIFIER, NOW, suggesting=True, last=None)
    assert first.said == ["raised: read 2 raised 2", "cases: suggested 1"]
    assert (first.warned, first.suggested_at) == ([], NOW)
    assert len(await in_attention(app_engine)) == 2
    assert len(await rows(app_engine, "SELECT * FROM cases")) == 1

    soon = NOW + timedelta(minutes=5)
    quiet = await raising.run(
        app_engine, CLASSIFIER, soon, suggesting=True, last=first.suggested_at
    )
    assert quiet.said == ["raised: read 0 raised 0"]  # evidence every pass, cases not yet
    assert quiet.suggested_at == NOW

    due = NOW + raising.SUGGEST_EVERY
    third = await raising.run(app_engine, CLASSIFIER, due, suggesting=True, last=NOW)
    assert third.said == ["raised: read 0 raised 0", "cases: none"]
    assert third.suggested_at == due


async def test_with_the_switch_off_only_the_evidence_is_read(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await story(migrated_engine)
    done = await raising.run(app_engine, CLASSIFIER, NOW, suggesting=False, last=None)
    assert done.said == ["raised: read 2 raised 2"]
    assert done.suggested_at is None
    assert len(await in_attention(app_engine)) == 2  # still raised into Needs attention
    assert await rows(app_engine, "SELECT * FROM cases") == []
    no_map = await raising.run(app_engine, None, NOW, suggesting=True, last=None)
    assert no_map.said == ["raised: read 0 raised 0"]  # no classifier: no case step


async def test_a_malformed_dossier_does_not_stop_the_pass_or_the_suggestions(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    await story(migrated_engine)
    await make(migrated_engine, severity="low", signals=(POISON,), host=2, rule="unreadable")
    real = raised.flags_of

    def flags_of(local_signals: Any, signals: Any) -> tuple[str, ...]:
        if POISON in (local_signals or []):
            raise ValueError("unreadable")
        return real(local_signals, signals)

    monkeypatch.setattr(raised, "flags_of", flags_of)
    done = await raising.run(app_engine, CLASSIFIER, NOW, suggesting=True, last=None)
    assert done.said == ["raised: read 3 raised 2 skipped 1", "cases: suggested 1"]
    assert (done.warned, done.suggested_at) == ([], NOW)  # not "raising or suggesting failed"
    assert len(await rows(app_engine, "SELECT * FROM cases")) == 1


class Broken:
    """An engine that cannot be reached."""

    def begin(self) -> Any:
        raise ConnectionError("down")


async def test_a_failure_is_said_and_never_raised() -> None:
    done = await raising.run(Broken(), CLASSIFIER, datetime.now(UTC),  # type: ignore[arg-type]
                             suggesting=True, last=None)  # fmt: skip
    assert done.said == []
    assert done.warned == ["warning: raising or suggesting failed (ConnectionError); retrying"]
