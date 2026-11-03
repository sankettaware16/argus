"""``argus case report`` end to end on a throwaway database (AR7): the report is shown with each
evidence line's query and link, stored as a version when the evidence changed (never with
``--dry-run``), the versions are listed, and ``--pdf`` and ``--csv`` write files that open."""

from __future__ import annotations

import csv
import io
import uuid
from pathlib import Path

import pytest
from pypdf import PdfReader
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
    return case


def ok(result: Result) -> str:
    assert result.exit_code == 0, result.output + result.stderr
    return result.output


def test_the_report_is_shown_stored_once_and_its_files_open(
    cli_env: Path,  # noqa: F811
    seeded: uuid.UUID,
    tmp_path: Path,
) -> None:
    pdf, folder = tmp_path / "r.pdf", tmp_path / "files"

    dry = ok(_run("case", "report", "1", "--dry-run"))
    assert "ACME-IR-" in dry
    assert "SUMMARY" in dry
    assert "EVIDENCE" in dry
    assert "no report yet" in ok(
        _run("case", "report", "1", "--versions")
    )  # a dry run stores nothing

    out = ok(_run("case", "report", "1", "--pdf", str(pdf), "--csv", str(folder)))
    assert "stored as version 1" in out
    for heading in (
        "SUMMARY", "VERDICT", "TIMELINE (IST)", "ACTORS", "AFFECTED ASSETS", "INDICATORS",
        "EVIDENCE", "HYPOTHESES", "RECOMMENDED ACTIONS",
    ):  # fmt: skip
        assert heading in out
    assert "query (esql, acme-logs-squid-*" in out
    assert "link: https://" in out
    assert "a true positive" in out
    assert "category:c2-beacon" in out

    again = ok(_run("case", "report", "1"))
    assert "unchanged: version 1 stands" in again
    listed = ok(_run("case", "report", "1", "--versions"))
    assert listed.startswith("version 1: ")
    assert "UTC" in listed
    assert listed.count("version") == 1  # still one version

    reader = PdfReader(str(pdf))
    assert len(reader.pages) >= 3
    assert "1. Summary" in "\n".join(p.extract_text() for p in reader.pages)
    names = sorted(p.name for p in folder.iterdir())
    assert names[0].endswith("_affected_devices.csv")
    assert names[1].endswith("_indicators.csv")
    raw = (folder / names[1]).read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")
    rows = list(csv.reader(io.StringIO(raw.decode("utf-8-sig"))))
    assert rows[0] == ["indicator", "type", "role", "evidence"]
    assert len(rows) == 6


def test_a_missing_case_is_refused(cli_env: Path, seeded: uuid.UUID) -> None:  # noqa: F811
    gone = _run("case", "report", "9")
    assert gone.exit_code == 1
    assert "no case 9" in gone.stderr
    bad = _run("case", "report", "not-a-case")
    assert bad.exit_code in (1, 2)
    assert "neither a case number nor an id" in bad.stderr
