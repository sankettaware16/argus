"""The incident report against the database (AR7, D-190), as the runtime login runs it: the Amadey
shaped case in a database has every section, its timeline matches its alerts, every evidence line
has a query and a Discover link, the indicators are the case's and the files open; a report is
written once for the same evidence, again when it changes, and the versions are kept; the
assessment pass writes within its cap and a failure never stops it."""

from __future__ import annotations

import csv
import io
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from pypdf import PdfReader
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.incident import build, files, gather, run, store
from argus.incident import model as m
from argus.responder import store as responder_store
from tests.integration.cases.conftest import Person
from tests.integration.cases.knownkit import HOST, SERVERS, make
from tests.integration.incident import kit

pytestmark = pytest.mark.integration


async def scalar(engine: AsyncEngine, sql: str, **params: object) -> object:
    async with engine.connect() as conn:
        return (await conn.execute(text(sql), params)).scalar()


async def test_the_amadey_acceptance_report_has_every_section_and_its_files_open(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case, invs = await kit.amadey(migrated_engine, app_engine, people["asha"])
    now = kit.NOW
    ctx = kit.context(catalogue=responder_store.current())
    async with app_engine.connect() as conn:
        facts = await gather.gather(conn, case, now)
    assert facts is not None
    report = build.build(facts, ctx)

    # every section
    h = report.header
    assert h.incident_id.startswith("ACME-IR-")
    assert h.case_state == "open"
    assert report.summary.sentences
    assert report.summary.standing in ("ongoing", "quiet")
    assert report.verdict.outcome == "true_positive"
    assert report.verdict.kind == "proposal"
    assert report.verdict.confidence == pytest.approx(0.8)
    assert report.actors
    assert report.assets
    assert report.evidence
    assert report.hypotheses
    assert report.indicators
    assert report.actions.lines
    assert report.queries
    assert report.facts

    # the timeline matches the alerts the database holds
    stored = await scalar(
        migrated_engine,
        "SELECT count(*) FROM investigation_alerts WHERE investigation_id = ANY(:i)",
        i=invs,
    )
    assert report.timeline.alerts == stored == 35
    assert sum(d.total for d in report.timeline.days) == 35
    first, last = await _span(migrated_engine, invs)
    assert report.timeline.first_seen == first
    assert report.timeline.last_seen == last
    assert {p.name for p in report.timeline.phases} == {"Rule beacon", "Rule download"} or {
        p.name for p in report.timeline.phases
    } == {"Rule download", "Rule beacon"}

    # every evidence line has its query and a Discover link, built from config only
    assert [e.id for e in report.evidence][:2] == ["E1", "E2"]
    for line in report.evidence:
        assert line.query.text
        assert line.query.index
        assert line.query.url.startswith("https://kibana.example/s/acme-soc/app/discover#/?_g=")
    pairs = [e for e in report.evidence if e.query.template == "proxy.pair@1"]
    assert len(pairs) >= 3
    assert all(f'source.ip == "{HOST}"' in e.query.text for e in pairs)
    assert {e.count for e in pairs} <= {40, 41, 42, 43, 44}

    # the indicators equal the case's
    held = await _indicators(migrated_engine, case)
    assert {(i.kind, i.value, i.role) for i in report.indicators} == held
    assert {v for _, v, r in held if r == "c2"} == set(SERVERS)
    assert {a.value for a in report.assets if a.kind == "device"} == {HOST}
    assert "T1071" in report.header.tags[-4:] or any(t == "mitre:T1071" for t in report.header.tags)
    assert any(a.id == "c2_beacon.isolate_host" for a in report.actions.lines)

    # the files open
    pdf = PdfReader(io.BytesIO(files.pdf(report)))
    body = "\n".join(p.extract_text() for p in pdf.pages)
    assert len(pdf.pages) >= 3
    assert "1. Summary" in body
    assert h.incident_id in body
    ind = list(csv.reader(io.StringIO(files.indicators_csv(report)[1:])))
    assert ind[0] == ["indicator", "type", "role", "evidence"]
    assert {r[0] for r in ind[1:]} == {v for _, v, _ in held}
    aff = list(csv.reader(io.StringIO(files.affected_csv(report)[1:])))
    assert aff[1][0] == HOST
    assert aff[1][2] == "5"


async def _span(engine: AsyncEngine, invs: list[uuid.UUID]) -> tuple[object, object]:
    async with engine.connect() as conn:
        row = (
            await conn.execute(
                text(
                    "SELECT min(COALESCE(a.event_time, a.detected_at)) AS lo,"
                    " max(COALESCE(a.event_time, a.detected_at)) AS hi FROM alert_records a"
                    " JOIN investigation_alerts l ON l.alert_id = a.alert_id"
                    " WHERE l.investigation_id = ANY(:i)"
                ),
                {"i": invs},
            )
        ).one()
    return row.lo, row.hi


async def _indicators(engine: AsyncEngine, case: uuid.UUID) -> set[tuple[str, str, str]]:
    async with engine.connect() as conn:
        rows = await conn.execute(
            text("SELECT kind, value, role FROM case_indicators WHERE case_id = :c"), {"c": case}
        )
        return {(r.kind, r.value, r.role) for r in rows}


async def test_the_same_evidence_is_the_same_version_and_a_change_makes_the_next(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case, invs = await kit.amadey(migrated_engine, app_engine, people["asha"])
    one, new = await kit.write(app_engine, case)
    assert new
    assert one.version == 1
    again, new = await kit.write(app_engine, case, kit.NOW + timedelta(minutes=5))
    assert not new
    assert again.id == one.id
    assert again.report.meta.as_at == one.report.meta.as_at
    await kit.pair_evidence(migrated_engine, invs[0], SERVERS[3], 99, kit.NOW)
    two, new = await kit.write(app_engine, case, kit.NOW + timedelta(minutes=10))
    assert new
    assert two.version == 2
    assert two.content_hash != one.content_hash
    listed = await _versions(app_engine, case)
    assert [v.version for v in listed] == [2, 1]  # both kept, the newest first
    got = await _stored(app_engine, case, 1)
    assert got is not None
    assert got.report == one.report
    newest = await _newest(app_engine, case)
    assert newest is not None
    assert newest.version == 2
    with pytest.raises(DBAPIError, match="append-only"):  # a version is never changed
        async with migrated_engine.begin() as conn:
            await conn.execute(text("UPDATE incident_reports SET writer = 'x'"))


async def _versions(engine: AsyncEngine, case: uuid.UUID) -> list[store.Listed]:
    async with engine.connect() as conn:
        return await store.versions(conn, case)


async def _stored(engine: AsyncEngine, case: uuid.UUID, version: int) -> store.Stored | None:
    async with engine.connect() as conn:
        return await store.version(conn, case, version)


async def _newest(engine: AsyncEngine, case: uuid.UUID) -> store.Stored | None:
    async with engine.connect() as conn:
        return await store.latest(conn, case)


async def test_the_pass_is_capped_quiet_when_unchanged_and_isolates_a_failure(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    people: dict[str, Person],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, _ = await kit.amadey(migrated_engine, app_engine, people["asha"])
    other = await make(migrated_engine, when=kit.day(1), host="10.55.7.9", rule="beacon-2")
    second = await _open(app_engine, people["asha"], other)
    cfg = kit.settings()
    cfg = cfg.model_copy(
        update={
            "incident": cfg.incident.model_copy(
                update={"per_pass": 1, "min_interval": timedelta(0)}
            )
        }
    )

    pass1 = await run.run_pass(app_engine, cfg, kit.NOW)
    assert (pass1.written, pass1.unchanged, pass1.failed) == (1, 0, 0)  # the cap: one this pass
    assert pass1.looked == 2
    assert not pass1.warned
    pass2 = await run.run_pass(app_engine, cfg, kit.NOW + timedelta(minutes=5))
    assert pass2.written == 1
    assert pass2.unchanged == 1
    pass3 = await run.run_pass(app_engine, cfg, kit.NOW + timedelta(minutes=10))
    assert (pass3.written, pass3.unchanged) == (0, 2)
    assert await scalar(migrated_engine, "SELECT count(*) FROM incident_reports") == 2
    assert await scalar(migrated_engine, "SELECT count(*) FROM incident_report_checks") == 2

    # a change makes the next version; a failure in one case is said and the others go on
    async with migrated_engine.begin() as conn:  # a new device joins the case
        await conn.execute(
            text(
                "INSERT INTO case_indicators (case_id, kind, value, role, source, added_version,"
                " added_by) VALUES (:c, 'ip', '10.55.9.9', 'actor', 'investigation', 1, 'argus')"
            ),
            {"c": first},
        )
    await make(migrated_engine, when=kit.day(2), host="10.55.7.9", rule="beacon-3")
    real = build.build

    def broken(facts, ctx):  # type: ignore[no-untyped-def]
        if facts.case.id == second:
            raise RuntimeError("the writer broke on this case")
        return real(facts, ctx)

    monkeypatch.setattr(run.build, "build", broken)
    cfg2 = cfg.model_copy(
        update={
            "incident": cfg.incident.model_copy(
                update={"per_pass": 5, "min_interval": timedelta(0)}
            )
        }
    )
    # generated_at is the database's clock, and kit.NOW was read at import: in a long run the
    # reports above are "newer" than kit.NOW, so these passes count from the real time
    late = datetime.now(UTC)
    after = await run.run_pass(app_engine, cfg2, late + timedelta(minutes=20))
    assert after.written == 1
    assert after.failed == 0
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text(
                "UPDATE investigations SET alert_count = alert_count + 1 WHERE id = ("
                "SELECT investigation_id FROM case_members WHERE case_id = :c LIMIT 1)"
            ),
            {"c": second},
        )
    broke = await run.run_pass(app_engine, cfg2, late + timedelta(minutes=30))
    assert broke.failed == 1
    assert any("the writer broke" in w for w in broke.warned)
    row = await _check(migrated_engine, second)
    assert row.failure
    assert "the writer broke" in row.failure
    assert row.failed_at is not None
    assert (await _newest(app_engine, second)) is not None  # it keeps the report it had
    quiet = await run.run_pass(app_engine, cfg2, late + timedelta(minutes=35))
    assert quiet.failed == 0
    assert quiet.unchanged >= 1
    monkeypatch.undo()
    retry = await run.run_pass(app_engine, cfg2, late + timedelta(hours=2))
    assert retry.failed == 0
    assert retry.written == 1
    assert (await _check(migrated_engine, second)).failure is None


async def _open(engine: AsyncEngine, person: Person, inv: uuid.UUID) -> uuid.UUID:
    from tests.integration.cases.knownkit import open_case

    return await open_case(engine, person, [inv], host="10.55.7.9", servers=(SERVERS[0],))


async def _members(engine: AsyncEngine, case: uuid.UUID) -> list[uuid.UUID]:
    async with engine.connect() as conn:
        rows = await conn.execute(
            text("SELECT investigation_id FROM case_members WHERE case_id = :c ORDER BY 1"),
            {"c": case},
        )
        return list(rows.scalars())


async def _check(engine: AsyncEngine, case: uuid.UUID):  # type: ignore[no-untyped-def]
    async with engine.connect() as conn:
        return await store.check_of(conn, case)


async def test_a_disabled_pass_writes_nothing(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    await kit.amadey(migrated_engine, app_engine, people["asha"])
    cfg = kit.settings()
    off = cfg.model_copy(update={"incident": cfg.incident.model_copy(update={"enabled": False})})
    done = await run.run_pass(app_engine, off, kit.NOW)
    assert done.looked == 0
    assert await scalar(migrated_engine, "SELECT count(*) FROM incident_reports") == 0


async def test_the_report_model_round_trips_through_the_database(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case, _ = await kit.amadey(migrated_engine, app_engine, people["asha"])
    written, _ = await kit.write(app_engine, case)
    got = await _newest(app_engine, case)
    assert got is not None
    assert isinstance(got.report, m.IncidentReport)
    assert got.report == written.report
    assert m.content_hash(got.report) == got.content_hash
    assert got.verdict_outcome == "true_positive"
    assert got.verdict_confidence == pytest.approx(0.8)


async def test_the_report_keeps_when_its_alerts_were_made_and_what_fields_they_hold(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """P4-F V2: the live charts plot each alert's own time, which a rule's lookback or a late run
    puts after its event, and a chart over a field the alerts lack would be empty. The report
    keeps the first and newest making time and the chart fields most of its alerts hold."""
    case, _ = await kit.amadey(migrated_engine, app_engine, people["asha"])
    late = timedelta(hours=9)
    async with migrated_engine.begin() as conn:  # every alert made 9 hours after its event
        await conn.execute(
            text(
                "UPDATE alert_records SET detected_at = event_time + CAST(:late AS interval)"
                " WHERE alert_id IN (SELECT l.alert_id FROM case_members m"
                " JOIN investigation_alerts l ON l.investigation_id = m.investigation_id"
                " WHERE m.case_id = :c) AND event_time IS NOT NULL"
            ),
            {"c": case, "late": "9 hours"},
        )
        made = (
            await conn.execute(
                text(
                    "SELECT min(a.detected_at), max(a.detected_at) FROM case_members m"
                    " JOIN investigation_alerts l ON l.investigation_id = m.investigation_id"
                    " AND l.duplicate_of IS NULL JOIN alert_records a ON a.alert_id = l.alert_id"
                    " WHERE m.case_id = :c"
                ),
                {"c": case},
            )
        ).one()
    async with app_engine.connect() as conn:
        facts = await gather.gather(conn, case, kit.NOW)
    assert facts is not None
    report = build.build(facts, kit.context())
    h = report.header
    assert (h.first_detected_at, h.last_detected_at) == (made[0], made[1])
    assert h.last_alert_at is not None
    assert h.last_detected_at is not None
    assert h.last_detected_at - h.last_alert_at == late
    assert report.meta.carried == ("source.ip", "destination.ip")  # what the alerts hold
    stored, _ = await kit.write(app_engine, case)
    assert stored.report.header.last_detected_at == h.last_detected_at
    assert stored.report.meta.carried == report.meta.carried
