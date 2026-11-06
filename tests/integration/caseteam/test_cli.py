"""``argus case team`` end to end on a throwaway database (AR8): the preview shows exactly what
would be sent while posting is off (and writes nothing), ``status`` says nothing has been posted,
``run`` refuses at once on a host that is not set up to post (and says why), and an unknown case
is an error."""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine
from typer.testing import Result

from tests.integration.cases.conftest import Person
from tests.integration.incident import kit
from tests.integration.test_cli_db import _run, cli_env  # noqa: F401 - the fixture

pytestmark = pytest.mark.integration


@pytest.fixture
async def seeded(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> uuid.UUID:
    case, _ = await kit.amadey(migrated_engine, app_engine, people["asha"])
    await kit.write(app_engine, case)
    return case


def ok(result: Result) -> str:
    assert result.exit_code == 0, result.output + result.stderr
    return result.output


def test_the_preview_shows_every_step_by_its_author_and_writes_nothing(
    cli_env: Path,  # noqa: F811
    seeded: uuid.UUID,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ARGUS_CASE_TEAM__AUTO", "true")  # ARGUS's own verdict (production: off)
    out = ok(_run("case", "team", "preview", "1"))
    assert "incident ACME-IR-" in out
    assert "decision: none (dry run: posting is off)" not in out or "dry run" in out
    assert "dry run" in out
    assert "would" not in out.split("decision:")[0]
    assert "plan " in out
    assert " steps" in out
    assert "alerts are left out: their index is not one of the space's concrete" in out
    assert "attaches" not in out  # none could be attached: their index is the test database's
    lines = [ln for ln in out.split("\n") if "[comment:" in ln or "[open]" in ln or "[file:" in ln]
    assert lines[0].strip().startswith("1. argus-lead opens the case")
    assert "argus-evidence comments (evidence)" in out
    assert "argus-hunter comments (queries)" in out
    assert "argus-reporter uploads" in out
    # AR10: the glance is a part like the others, after the evidence and before the queries, and
    # the dashboard is one of the reporter's files
    assert "argus-visualiser comments (glance)  [comment:glance:1]" in out
    assert out.index("(evidence)") < out.index("(glance)") < out.index("(queries)")
    assert "_dashboard  [file:dashboard]" in out
    assert lines[-1].strip().endswith("[comment:verdict]")
    assert "ARGUS's true positive" not in out  # it is the proposal's: "proposal"

    full = ok(_run("case", "team", "preview", "1", "--text", "--requests"))
    assert "      | ## Evidence" in full
    assert "      | Confirm or reject in a comment." in full
    assert "      | ## Incident at a glance" in full
    # no alert can be attached here (their index is the test database's), so no live chart
    # would draw anything: the glance says so and keeps its lists (P4-F V2)
    assert full.count("      | !{lens{") == 0
    assert "No alert is attached to this case yet, so no live chart is drawn." in full
    assert "no visualiser key" not in full  # a preview reads no key: it says what the plan holds
    assert "POST /s/acme-soc/api/cases (application/json)" in full
    assert "multipart/form-data; boundary=argus-" in full

    assert "no case has been posted" in ok(_run("case", "team", "status"))


def test_a_run_on_a_host_that_is_not_set_up_to_post_refuses_and_says_why(
    cli_env: Path,  # noqa: F811
    seeded: uuid.UUID,
) -> None:
    result = _run("case", "team", "run", "1", "--unattended")
    assert result.exit_code == 2
    err = result.stderr
    assert "cannot post: case_team.post is false" in err
    assert "WC is not switched on" in err
    assert "no key is installed for argus-lead" in err
    assert "argus-visualiser" not in err  # the seventh user is optional: never a reason to stop
    assert "web.public_url is not set" in err


def test_an_unknown_case_is_an_error(
    cli_env: Path,  # noqa: F811
    migrated_engine: AsyncEngine,
) -> None:
    result = _run("case", "team", "preview", "999")
    assert result.exit_code == 1
    assert "no case 999" in result.stderr


def test_status_lists_a_post_and_its_steps(
    cli_env: Path,  # noqa: F811
    seeded: uuid.UUID,
    migrated_engine: AsyncEngine,
) -> None:
    import asyncio

    async def make() -> None:
        async with migrated_engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO case_team_posts (case_id, incident_id, kibana_case_id, opened_at,"
                    " last_version) VALUES (:c, 'ACME-IR-2026-1026-01', 'kid-1', now(), 1)"
                ),
                {"c": seeded},
            )
            await conn.execute(
                text(
                    "INSERT INTO case_team_steps (case_id, gen, seq, key, kind, author, part,"
                    " report_version, text_body, request_hash) VALUES (:c, 1, 1, 'open', 'open',"
                    " 'argus-lead', 'open', 1, 'x', :h)"
                ),
                {"c": seeded, "h": "a" * 64},
            )

    asyncio.run(make())
    out = ok(_run("case", "team", "status", "1"))
    assert "case 1: ACME-IR-2026-1026-01 kibana=kid-1 active" in out
    assert "steps: 1 planned" in out
    assert "read back: not read yet" in out


def test_status_says_what_the_read_back_saw_and_that_a_person_deleted_the_case(
    cli_env: Path,  # noqa: F811
    seeded: uuid.UUID,
    migrated_engine: AsyncEngine,
) -> None:
    """P4-B1: the mirror's row for a case-team case is what ``status`` reports."""
    import asyncio

    async def make() -> None:
        async with migrated_engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO case_team_posts (case_id, incident_id, kibana_case_id, opened_at,"
                    " last_version) VALUES (:c, 'ACME-IR-2026-1026-01', 'kid-1', now(), 1)"
                ),
                {"c": seeded},
            )
            await conn.execute(
                text(
                    "INSERT INTO kibana_mirror (case_id, kibana_case_id, kibana_version, status,"
                    " title, severity, tags, created_by, sync_alerts, unmanaged, kibana_created_at,"
                    " read_at) VALUES (:c, 'kid-1', 'v1', 'closed', 't', 'medium', '{}',"
                    " 'argus-lead', false, '{title}', now(), now())"
                ),
                {"c": seeded},
            )

    asyncio.run(make())
    out = ok(_run("case", "team", "status", "1"))
    assert "read back: Kibana status closed, read " in out
    assert "a person changed title" in out

    async def delete() -> None:
        async with migrated_engine.begin() as conn:
            await conn.execute(text("UPDATE kibana_mirror SET deleted_at = now()"))

    asyncio.run(delete())
    out = ok(_run("case", "team", "status", "1"))
    assert "read back: DELETED in Kibana" in out
    assert "nothing more is posted" in out


def test_a_refresh_of_a_case_that_is_not_in_kibana_says_so_and_plans_nothing(
    cli_env: Path,  # noqa: F811
    seeded: uuid.UUID,
) -> None:
    out = ok(_run("case", "team", "refresh", "1"))
    assert "case 1: refresh" in out
    assert "cannot refresh: the case is not in Kibana" in out
    assert "no case has been posted" in ok(_run("case", "team", "status"))


def test_applying_a_refresh_is_a_persons_decision_at_a_terminal(
    cli_env: Path,  # noqa: F811
    seeded: uuid.UUID,
) -> None:
    result = _run("case", "team", "refresh", "1", "--apply")
    assert result.exit_code == 2
    assert "this is done by a person at a terminal" in result.stderr
