"""Q-A1's measurement of criterion 14's list endpoints at the exit's scale: 350,000
investigations (twice the exit's projection, plan §8 criterion 14) over 90 days, a fifth of
them reviewed, one alert each (the lists never read alerts), on this machine, in process.
Opt in (``RUN_SCALE_TEST=1``, not an ``ARGUS_`` name: the settings refuse unknown ones; a few
minutes and about 1 GB in a throwaway database): it is not part of every suite run. The 30-day
suite measurement is test_performance.py."""

from __future__ import annotations

import os
import random
import statistics
import time

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.web import auth, queries
from argus.web.app import create_app
from tests.integration.web.conftest import BASE, NOW, PASSWORD, SAME_ORIGIN

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("RUN_SCALE_TEST") != "1",
        reason="opt-in: RUN_SCALE_TEST=1 (exit-scale measurement)",
    ),
]
DAYS, PER_DAY = 90, 3_889  # 350,010 investigations; a fifth reviewed, under 1 % follow-ups
SAMPLES, LIMIT_MS = 40, 300

SEED = f"""
INSERT INTO investigations (id, grouping_version, rule_id, rule_name, group_key, bucket_start,
  bucket_end, previous_id, alert_count, first_event_at, last_event_at, severity, version)
SELECT md5('inv-' || d || '-' || j)::uuid, '1', 'rule-' || (j % 40), 'Rule ' || (j % 40),
  '[["source.ip","10.' || (j % 200) || '.' || (j % 250) || '.' || (d % 7) || '"]]',
  :now - make_interval(days => d + 1), :now - make_interval(days => d),
  md5('prev-' || d || '-' || j)::uuid, 1 + (j % 30),
  :now - make_interval(days => d + 1), :now - make_interval(days => d, mins => j % 600),
  (ARRAY['low','medium','high','critical'])[1 + (j % 4)], 1
FROM generate_series(0, {DAYS - 1}) d, generate_series(0, {PER_DAY - 1}) j;

INSERT INTO alert_records (alert_id, index, status, normalizer_version, rule_id, detected_at,
  event_time, fingerprint, workflow_status, raw, normalized, content_hash, state_hash,
  recovered_by)
SELECT md5('alert-' || i.id), 'idx', 'normalized', '1', i.rule_id, i.last_event_at,
  i.last_event_at, md5('fp-' || i.id), 'open', '{{"note": "synthetic"}}'::jsonb,
  jsonb_build_object('severity', i.severity, 'entities', '[]'::jsonb),
  md5('c' || i.id), md5('s' || i.id), 'live'
FROM investigations i;

INSERT INTO investigation_alerts (alert_id, investigation_id)
SELECT md5('alert-' || id), id FROM investigations;

INSERT INTO investigation_entities (investigation_id, kind, value)
SELECT id, 'ip', group_key::jsonb->0->>1 FROM investigations;

INSERT INTO entities (kind, value, investigations)
SELECT kind, value, count(*) FROM investigation_entities GROUP BY kind, value;

INSERT INTO review_events (investigation_id, version, alert_count, user_id, action, outcome)
SELECT id, 1, alert_count, :user, 'reviewed', 'benign_expected' FROM investigations
WHERE get_byte(decode(md5(id::text), 'hex'), 0) < 51;

INSERT INTO review_events (investigation_id, version, alert_count, user_id, action, outcome)
SELECT id, 1, alert_count, :user, 'follow_up', NULL FROM investigations
WHERE get_byte(decode(md5(id::text), 'hex'), 1) < 2;

ANALYZE;
"""  # noqa: S608 - constants only


@pytest.fixture
async def huge(app_engine: AsyncEngine, migrated_engine: AsyncEngine) -> AsyncEngine:
    async with app_engine.begin() as conn:
        user = await auth.add_user(conn, "asha", "Asha", PASSWORD)
    async with migrated_engine.begin() as conn:
        for statement in SEED.split(";\n"):
            if statement.strip():
                await conn.execute(text(statement), {"now": NOW, "user": user})
    return app_engine


async def p95(http: httpx.AsyncClient, paths: list[str]) -> float:
    times = []
    for path in paths:
        started = time.perf_counter()
        response = await http.get(path)
        times.append((time.perf_counter() - started) * 1000)
        assert response.status_code == 200, (path, response.status_code)
    return statistics.quantiles(times, n=20)[-1]


@pytest.mark.timeout(3600)
async def test_the_lists_at_twice_the_exits_scale(
    huge: AsyncEngine, web_engine: AsyncEngine
) -> None:
    async with huge.connect() as conn:
        count = (await conn.execute(text("SELECT count(*) FROM investigations"))).scalar_one()
    assert count == DAYS * PER_DAY
    rnd = random.Random(14)
    offsets = [rnd.randrange(0, 10_000, 100) for _ in range(SAMPLES)]
    deepest = queries.DEEPEST  # the deepest page /api/v1 serves (review F2)
    app = create_app(web_engine, clock=lambda: NOW)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE,
                                 headers=SAME_ORIGIN) as http:  # fmt: skip
        made = await http.post("/api/login", json={"username": "asha", "password": PASSWORD})
        assert made.status_code == 200
        checks = {
            "attention": ["/api/v1/investigations"] * SAMPLES,
            "open, paged": [f"/api/v1/investigations?view=open&offset={o}" for o in offsets],
            "all, urgent": ["/api/v1/investigations?view=all&sort=urgent"] * SAMPLES,
            "all, urgent, paged": [f"/api/v1/investigations?view=all&sort=urgent&offset={o}"
                                   for o in offsets],
            **{f"{view}, {sort}, deepest": [
                f"/api/v1/investigations?view={view}&sort={sort}&offset={deepest}"] * SAMPLES
               for view in ("all", "open", "attention")
               for sort in ("newest", "oldest", "urgent", "reviewed")},
            "reviewed, deepest": [
                f"/api/v1/investigations?view=reviewed&offset={deepest}"] * SAMPLES,
            "classic, urgent": ["/api/investigations?view=all"] * SAMPLES,
            "classic, deepest": [f"/api/investigations?view=all&offset={deepest}"] * SAMPLES,
            "by rule": [f"/api/v1/investigations?view=all&rule=rule-{n % 40}"
                        for n in range(SAMPLES)],
            "by entity": [f"/api/v1/investigations?view=all&kind=ip&value=10.{n}.{n}.{n % 7}"
                          for n in range(SAMPLES)],
            "reviewed": ["/api/v1/investigations?view=reviewed"] * SAMPLES,
            "counts": ["/api/v1/counts"] * SAMPLES,
            "rules": ["/api/v1/rules"] * SAMPLES,
            "entities": ["/api/v1/entities"] * SAMPLES,
            "proposals": ["/api/v1/proposals"] * SAMPLES,
            "patterns": ["/api/v1/patterns"] * SAMPLES,
        }  # fmt: skip
        results = {name: await p95(http, paths) for name, paths in checks.items()}
        for deeper in (
            f"/api/v1/investigations?offset={deepest + 1}",
            f"/api/investigations?offset={deepest + 1}",
            f"/?offset={deepest + 1}",
        ):
            assert (await http.get(deeper)).status_code == 422, deeper
    shown = {name: round(ms) for name, ms in results.items()}
    print("p95 ms at 350,010 investigations:", shown)
    slow = {name: ms for name, ms in shown.items() if ms > LIMIT_MS}
    assert slow == {}, slow
