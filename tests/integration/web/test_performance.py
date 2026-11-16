"""R7 gate: p95 < 300 ms for every Inbox read on 30 days of synthetic data (about 15,000 alerts
and 1,130 investigations a day, as on 2026-10-08: 450,000 alerts, 34,000 investigations, a
fifth of them reviewed). Measured in process (app + database, no network)."""

from __future__ import annotations

import random
import statistics
import time

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.web import auth
from argus.web.app import create_app
from tests.integration.web.conftest import BASE, NOW, PASSWORD, SAME_ORIGIN

pytestmark = pytest.mark.integration

DAYS, PER_DAY, INVESTIGATIONS = 30, 15_000, 1_130
SAMPLES = 40
LIMIT_MS = 300
# Home's patterns (AR4 review, D-187): about 100 ms here, where every one of the 27,000 unreviewed
# investigations is in one of 360 patterns (the most it can be); about 36 ms with a third of them
# covered and 12 ms with a tenth. A tripwire well under the 300 ms limit, not the figure.
SUMMARY_MS = 150

SEED = f"""
INSERT INTO investigations (id, grouping_version, rule_id, rule_name, group_key, bucket_start,
  bucket_end, previous_id, alert_count, first_event_at, last_event_at, severity, version)
SELECT md5('inv-' || d || '-' || j)::uuid, '1', 'rule-' || (j % 12), 'Rule ' || (j % 12),
  '[["source.ip","10.0.' || (j % 250) || '.' || (j % 7) || '"]]',
  :now - make_interval(days => d + 1), :now - make_interval(days => d),
  md5('prev-' || d || '-' || j)::uuid, 13,
  :now - make_interval(days => d + 1), :now - make_interval(days => d, mins => j % 600),
  (ARRAY['low','medium','high','critical'])[1 + (j % 4)], 1
FROM generate_series(0, {DAYS - 1}) d, generate_series(0, {INVESTIGATIONS - 1}) j;

INSERT INTO alert_records (alert_id, index, status, normalizer_version, rule_id, detected_at,
  event_time, fingerprint, workflow_status, raw, normalized, content_hash, state_hash,
  recovered_by)
SELECT md5('alert-' || i), 'idx', 'normalized', '1',
  'rule-' || ((i % {PER_DAY}) % {INVESTIGATIONS} % 12),
  :now - make_interval(secs => i * 5.76), :now - make_interval(secs => i * 5.76),
  md5('fp-' || i), 'open', '{{"note": "synthetic"}}'::jsonb,
  jsonb_build_object('severity', 'high', 'entities', jsonb_build_array(jsonb_build_object(
    'kind', 'ip', 'field', 'source.ip', 'value', '10.0.' || (i % 250) || '.' || (i % 7)))),
  md5('c' || i), md5('s' || i), 'live'
FROM generate_series(0, {DAYS * PER_DAY - 1}) i;

INSERT INTO investigation_alerts (alert_id, investigation_id)
SELECT md5('alert-' || i),
  md5('inv-' || (i / {PER_DAY}) || '-' || ((i % {PER_DAY}) % {INVESTIGATIONS}))::uuid
FROM generate_series(0, {DAYS * PER_DAY - 1}) i;

INSERT INTO investigation_entities (investigation_id, kind, value)
SELECT id, 'ip', group_key::jsonb->0->>1 FROM investigations;

INSERT INTO entities (kind, value, investigations)
SELECT kind, value, count(*) FROM investigation_entities GROUP BY kind, value;

INSERT INTO review_events (investigation_id, version, alert_count, user_id, action, outcome)
SELECT id, 1, 13, :user, 'reviewed', 'benign_expected' FROM investigations
WHERE get_byte(decode(md5(id::text), 'hex'), 0) < 51;

-- AR4 review (D-186): the AI investigator's runs. One proposed run for each rule and IST day
-- (360 patterns of about 90 investigations: 34,000 shares), on a member of the pattern; the
-- run stands for all of its members, as the picker (assess.patterns) makes them.
INSERT INTO assessments (investigation_id, version, pack, dossier_hash, view_hash, assessor,
  run_after, status, outcome, confidence, decided_by, reasons, finished_at)
SELECT DISTINCT ON (rule_id, bucket_start) id, 1, 'p', repeat('a', 64),
  md5(id::text) || md5('x' || id::text), 'agent@1', now(), 'proposed',
  (ARRAY['benign_expected','benign_policy','rule_false_positive'])[1 + get_byte(decode(
   md5(rule_id), 'hex'), 0) % 3], 0.8, 'agent@1#m', '[]'::jsonb, now()
FROM investigations ORDER BY rule_id, bucket_start, id;

INSERT INTO assessment_shares (assessment_id, investigation_id, version, pattern, day)
SELECT a.id, i.id, 1, encode(sha256(convert_to(i.rule_id || i.bucket_start::text, 'UTF8')), 'hex'),
  (i.bucket_start AT TIME ZONE 'Asia/Kolkata')::date
FROM investigations i JOIN LATERAL (SELECT x.id FROM assessments x JOIN investigations r
  ON r.id = x.investigation_id WHERE r.rule_id = i.rule_id AND r.bucket_start = i.bucket_start
  LIMIT 1) a ON true;

ANALYZE;
"""  # noqa: S608 - constants only


@pytest.fixture
async def big(app_engine: AsyncEngine, migrated_engine: AsyncEngine) -> AsyncEngine:
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


@pytest.mark.timeout(900)
async def test_every_read_is_fast_on_30_days(big: AsyncEngine, web_engine: AsyncEngine) -> None:
    app = create_app(web_engine, clock=lambda: NOW)  # as the web's own login (Q-A2)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=BASE, headers=SAME_ORIGIN
    ) as http:
        login = await http.post("/api/login", json={"username": "asha", "password": PASSWORD})
        assert login.status_code == 200
        ids = [i["id"] for i in (await http.get("/api/investigations?view=all")).json()]
        async with big.connect() as conn:
            sample = [str(i) for (i,) in await conn.execute(text(
                "SELECT id FROM investigations ORDER BY md5(id::text) LIMIT :n"),
                {"n": SAMPLES})]  # fmt: skip
        rnd = random.Random(30)
        offsets = [rnd.randrange(0, 5_000, 100) for _ in range(SAMPLES)]
        checks = {
            "attention": ["/api/investigations"] * SAMPLES,
            "open, paged": [f"/api/investigations?view=open&offset={o}" for o in offsets],
            "by rule filter": [
                f"/api/investigations?view=all&rule=rule-{n % 12}" for n in range(SAMPLES)
            ],
            "by entity filter": [
                f"/api/investigations?view=all&kind=ip&value=10.0.{n}.{n % 7}"
                for n in range(SAMPLES)
            ],
            "detail": [f"/api/investigations/{i}" for i in sample],
            "rules": ["/api/rules"] * SAMPLES,
            "entities": ["/api/entities"] * SAMPLES,
            "health": ["/api/health"] * SAMPLES,
            # /api/v1 (Q-A1; criterion 14's list endpoints)
            "v1 attention": ["/api/v1/investigations"] * SAMPLES,
            "v1 open, paged": [f"/api/v1/investigations?view=open&offset={o}" for o in offsets],
            "v1 all, urgent": ["/api/v1/investigations?view=all&sort=urgent"] * SAMPLES,
            "v1 by rule": [
                f"/api/v1/investigations?view=all&rule=rule-{n % 12}" for n in range(SAMPLES)
            ],
            "v1 by entity": [
                f"/api/v1/investigations?view=all&kind=ip&value=10.0.{n}.{n % 7}"
                for n in range(SAMPLES)
            ],
            "v1 reviewed": ["/api/v1/investigations?view=reviewed"] * SAMPLES,
            "v1 counts": ["/api/v1/counts"] * SAMPLES,
            "v1 detail": [f"/api/v1/investigations/{i}" for i in sample],
            "v1 alerts": [f"/api/v1/investigations/{i}/alerts" for i in sample],
            "v1 rules": ["/api/v1/rules"] * SAMPLES,
            "v1 entities": ["/api/v1/entities"] * SAMPLES,
            "v1 proposals": ["/api/v1/proposals"] * SAMPLES,
            "v1 session": ["/api/v1/session"] * SAMPLES,
            # AR4 and its review (D-182, D-186): Home's queue and the patterns it recommends closing
            "v1 queue": ["/api/v1/queue"] * SAMPLES,
            "v1 attention, queue order": ["/api/v1/investigations?view=attention&sort=queue"]
            * SAMPLES,
            "v1 patterns summary": ["/api/v1/patterns/summary"] * SAMPLES,
            "v1 cases, queue view": ["/api/v1/cases?view=queue"] * SAMPLES,
        }
        assert ids
        results = {name: await p95(http, paths) for name, paths in checks.items()}
    slow = {name: round(ms) for name, ms in results.items() if ms >= LIMIT_MS}
    print({name: round(ms) for name, ms in results.items()})
    assert slow == {}, slow
    # Home's patterns are well under the limit, and small (a few cards, never a sampled list)
    assert results["v1 patterns summary"] < SUMMARY_MS, results["v1 patterns summary"]


@pytest.mark.timeout(900)
async def test_the_patterns_summary_is_lean_on_30_days(
    big: AsyncEngine, web_engine: AsyncEngine
) -> None:
    app = create_app(web_engine, clock=lambda: NOW)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=BASE, headers=SAME_ORIGIN
    ) as http:
        login = await http.post("/api/login", json={"username": "asha", "password": PASSWORD})
        assert login.status_code == 200
        timed: list[float] = []
        for _ in range(SAMPLES):
            started = time.perf_counter()
            response = await http.get("/api/v1/patterns/summary")
            timed.append((time.perf_counter() - started) * 1000)
            assert response.status_code == 200
        found = response.json()
        print({"patterns summary median ms": round(statistics.median(timed)),
               "bytes": len(response.content), "total": found["total"],
               "listed": len(found["items"])})  # fmt: skip
    assert found["total"] > 300  # all of the day's patterns are counted, though few are listed
    assert len(found["items"]) == 8
    assert len(response.content) < 8_000
    assert statistics.median(timed) < SUMMARY_MS
