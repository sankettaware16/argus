"""P4-D1 part 2, step 2 (D-284): the incident ID prefix is ``site.incident_id_prefix``. ACME's is
ACME-IR (every ID, tag and stored row is what it was); the neutral default is IR; the database
check allows any prefix in the same shape (migration 0063)."""

from __future__ import annotations

import importlib.util
import re
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from argus import site
from argus.db.models import CaseTeamPost
from argus.gateway.kibana import models
from argus.incident.build import incident_id
from argus.incident.model import ReportHeader
from argus.site import SiteSettings
from tests.unit.incident import kit

pytestmark = pytest.mark.unit
ACME = SiteSettings(incident_id_prefix="ACME-SOC")
NEUTRAL = SiteSettings()
MIGRATION = Path(__file__).resolve().parents[3] / "src/argus/db/migrations/versions"


def test_acmes_ids_are_what_they_were() -> None:
    facts = kit.amadey()
    assert incident_id(replace(facts, order=3)) == "ACME-IR-2026-1026-03"
    assert site.incident_prefix() == "ACME-IR"
    assert site.incident_id_regex().fullmatch("ACME-IR-2026-1027-01")
    assert not site.incident_id_regex().fullmatch("IR-2026-1027-01")


def test_the_prefix_is_the_sites_and_the_day_is_the_sites_day() -> None:
    facts = kit.amadey()
    with site.using(NEUTRAL):
        assert incident_id(replace(facts, order=3)) == "IR-2026-1026-03"
    with site.using(ACME):
        assert incident_id(replace(facts, order=12)) == "ACME-SOC-2026-1026-12"
    created = facts.case.created_at
    with site.using(SiteSettings(timezone="Pacific/Kiritimati")):  # UTC+14: the day moves on
        day = incident_id(facts).split("-", 1)[1]
        assert day == f"{created.astimezone(site.zone()):%Y-%m%d}-01"


@pytest.mark.parametrize("prefix", ["IR", "ACME-IR", "A", "ACME-SOC", "A" + "B" * 15, "X1-Y2"])
def test_a_prefix_the_database_allows_is_accepted(prefix: str) -> None:
    assert SiteSettings(incident_id_prefix=prefix).incident_id_prefix == prefix


@pytest.mark.parametrize(
    "prefix", ["", "ir", "1R", "-IR", "IR-", "A" + "B" * 16, "I R", "IR_X", "IR\n", "É"]
)
def test_a_prefix_the_database_would_refuse_is_refused(prefix: str) -> None:
    with pytest.raises(ValidationError):
        SiteSettings(incident_id_prefix=prefix)


@pytest.mark.parametrize("prefix", ["IR", "ACME-IR", "A", "A" + "B" * 15])
def test_every_id_made_with_an_accepted_prefix_passes_the_report_and_the_database(
    prefix: str,
) -> None:
    ident = f"{prefix}-2026-1031-07"
    assert re.fullmatch(_database_pattern(), ident)
    ReportHeader(**{**_header_values(), "incident_id": ident})
    with site.using(SiteSettings(incident_id_prefix=prefix)):
        assert site.incident_id_regex().fullmatch(ident)


def test_a_report_header_refuses_what_is_no_incident_id() -> None:
    for bad in ("x", "ir-2026-1026-01", "IR-2026-1026-1", "IR-2026-1026-01x", " IR-2026-1026-01"):
        with pytest.raises(ValidationError):
            ReportHeader(**{**_header_values(), "incident_id": bad})
    ReportHeader(**{**_header_values(), "incident_id": incident_id(kit.amadey())})


def _header_values() -> dict[str, Any]:
    return {
        "incident_id": "IR-2026-1026-01",
        "title": "t",
        "case_number": 1,
        "case_id": "c",
        "case_state": "open",
        "severity": "high",
        "opened_in": "x",
        "detected_by": "y",
        "first_alert_at": None,
        "last_alert_at": None,
    }


def _database_pattern() -> str:
    check = next(
        c
        for c in CaseTeamPost.__table__.constraints
        if getattr(c, "name", None) and str(c.name).endswith("id_valid")
    )
    return re.search(r"'(\^.*\$)'", str(check.sqltext)).group(1)  # type: ignore[union-attr]


def test_the_model_and_the_migration_say_the_same_check() -> None:
    spec = importlib.util.spec_from_file_location(
        "m0063", MIGRATION / "0063_incident_id_any_prefix.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.revision == "0063"
    assert module.down_revision == "0062"
    check = next(
        c
        for c in CaseTeamPost.__table__.constraints
        if getattr(c, "name", None) and str(c.name).endswith("id_valid")
    )
    assert str(check.sqltext) == module.NEW  # one flat comparison, in both
    first = importlib.util.spec_from_file_location("m0053", MIGRATION / "0053_case_team.py")
    assert first is not None
    assert first.loader is not None
    assert module.NEW.removeprefix("incident_id ~ ") in first.loader.get_source("m0053")  # type: ignore[operator]


# --------------------------------------------------------------------------- Kibana tags


def create(prefix_tags: tuple[str, ...]) -> models.TeamCaseCreate:
    return models.TeamCaseCreate(
        title="t",
        description="d",
        tags=prefix_tags,
        severity="high",
    )


def test_a_case_is_opened_with_the_sites_incident_id_first() -> None:
    acme = ("ACME-IR-2026-1027-01", "incident", "source:argus-lead")
    create(acme)
    with pytest.raises(ValidationError, match="incident ID"):
        create(("IR-2026-1027-01", "incident", "source:argus-lead"))
    with site.using(NEUTRAL):
        create(("IR-2026-1027-01", "incident", "source:argus-lead"))
        with pytest.raises(ValidationError, match="incident ID"):
            create(acme)


def test_alerts_are_tagged_with_the_sites_incident_id_or_the_state_tag() -> None:
    models.AlertTagSet(tags_to_add=("ACME-IR-2026-1027-01", "incident:true-positive"))
    with pytest.raises(ValidationError, match="incident ID"):
        models.AlertTagSet(tags_to_add=("IR-2026-1027-01",))
    with pytest.raises(ValidationError, match="incident ID"):
        models.AlertTagSet(tags_to_add=("incident:True",))
    with pytest.raises(ValidationError, match="incident ID"):
        models.AlertTagSet(tags_to_add=("ACME-IR-2026-1027-01", "ACME-IR-2026-1027-01"))
    with site.using(ACME):
        models.AlertTagSet(tags_to_add=("ACME-SOC-2026-1027-01", "incident:under-review"))
        with pytest.raises(ValidationError, match="incident ID"):
            models.AlertTagSet(tags_to_add=("ACME-IR-2026-1027-01",))
