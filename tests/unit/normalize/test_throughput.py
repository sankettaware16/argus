"""Throughput (R3 gate: ≥ 1,000 alerts/s) and, where the local corpus exists, the whole
2026-10-08 corpus: every alert normalizes, none is quarantined, none has a field issue."""

from __future__ import annotations

import copy
import gzip
import json
import time

import pytest

from argus.normalize import NormalizedAlert, normalize
from tests.conftest import cpu_limit
from tests.unit.normalize.alerts import REPO_ROOT, all_alerts, with_id

pytestmark = pytest.mark.unit

CORPUS = sorted((REPO_ROOT / "data" / "corpus").glob("*/alerts.jsonl.gz"))


def test_at_least_1000_alerts_per_second() -> None:
    hits = []
    for i, hit in enumerate(list(all_alerts().values()) * 300):
        hits.append(with_id(copy.deepcopy(hit), f"{i:064x}"))
    start = time.process_time()
    results = [normalize(hit) for hit in hits]
    elapsed = time.process_time() - start
    assert all(isinstance(r, NormalizedAlert) for r in results)
    assert elapsed < cpu_limit(len(hits) / 1000), f"{len(hits) / elapsed:.0f} alerts/s"


@pytest.mark.skipif(not CORPUS, reason="no local corpus (data/ is never committed)")
def test_whole_local_corpus() -> None:
    for path in CORPUS:
        with gzip.open(path, "rt") as handle:
            hits = [json.loads(line) for line in handle]
        start = time.process_time()
        results = [normalize(hit) for hit in hits]
        elapsed = time.process_time() - start
        assert all(isinstance(r, NormalizedAlert) and not r.field_issues for r in results)
        assert elapsed < cpu_limit(len(hits) / 1000)
