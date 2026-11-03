"""Snapshot tests: every committed fixture and every synthetic variant, normalized, compared
with ``tests/fixtures/normalized/<name>.json`` (plan §6, R3 gate).

A change to any output must be deliberate: bump NORMALIZER_VERSION when behaviour changes,
regenerate with ``ARGUS_UPDATE_SNAPSHOTS=1 uv run pytest tests/unit/normalize/test_snapshots.py``
and review the diff. The snapshot directory is under tests/fixtures/, so the pre-commit hook
leak-checks it like the fixtures themselves.
"""

from __future__ import annotations

import json
import os

import pytest

from argus.normalize import normalize
from tests.unit.normalize.alerts import SNAPSHOTS, all_alerts

pytestmark = pytest.mark.unit

ALERTS = all_alerts()
# Read before the unit-test fixture clears ARGUS_* variables from the environment.
UPDATE = os.environ.get("ARGUS_UPDATE_SNAPSHOTS") == "1"


@pytest.mark.parametrize("name", sorted(ALERTS))
def test_snapshot(name: str) -> None:
    result = normalize(ALERTS[name])
    produced = json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
    path = SNAPSHOTS / f"{name}.json"
    if UPDATE:
        path.parent.mkdir(exist_ok=True)
        path.write_text(produced)
    assert path.is_file(), f"no snapshot for {name}: regenerate (see module docstring)"
    assert produced == path.read_text()


def test_no_stale_snapshots() -> None:
    assert sorted(p.stem for p in SNAPSHOTS.glob("*.json")) == sorted(ALERTS)


def test_every_rule_type_and_adapter_is_covered() -> None:
    results = [normalize(hit) for hit in ALERTS.values()]
    assert {r.rule_type.value for r in results} == {  # type: ignore[union-attr]
        "query", "saved_query", "threat_match", "new_terms", "threshold", "esql", "eql",
        "machine_learning", "unknown",
    }  # fmt: skip
    assert {r.adapter.value for r in results} == {  # type: ignore[union-attr]
        "event", "threshold", "esql_aggregate", "eql_sequence", "generic",
    }  # fmt: skip
