"""Doctor reads the web as its unit runs it: the unit's database role, approval key and
credentials folder (``units.web``), not only the shared ``web`` section, which the web's own
process does not use alone."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus.config.settings import Settings, UnitsSettings, UnitWebSettings, WebSettings
from argus.doctor import as_the_web_runs
from argus.observability.redaction import redact_text

pytestmark = pytest.mark.unit


def test_the_web_units_role_key_and_password_are_the_webs(tmp_path: Path) -> None:
    folder = tmp_path / "creds-web"
    folder.mkdir()
    (folder / "database.api_password").write_text("the-webs-own-password\n")
    key = tmp_path / "approval-signing.key"
    unit = UnitWebSettings(database_role="api", approval_key_file=str(key),
                           credentials=str(folder))  # fmt: skip
    seen = as_the_web_runs(Settings(units=UnitsSettings(web=unit)))
    assert seen.web.database_role == "api"
    assert seen.web.approval_key_file == key
    assert seen.database.api_password is not None
    assert seen.database.api_password.get_secret_value() == "the-webs-own-password"
    assert "the-webs-own-password" not in redact_text("password the-webs-own-password")


def test_the_shared_section_stands_when_the_unit_says_nothing(tmp_path: Path) -> None:
    shared = WebSettings(approval_key_file=tmp_path / "k.key")
    seen = as_the_web_runs(Settings(web=shared))
    assert seen.web.approval_key_file == tmp_path / "k.key"
    assert seen.web.database_role == "app"
    assert seen.database.api_password is None


def test_a_credentials_folder_without_the_password_changes_nothing(tmp_path: Path) -> None:
    unit = UnitWebSettings(credentials=str(tmp_path))
    seen = as_the_web_runs(Settings(units=UnitsSettings(web=unit)))
    assert seen.database.api_password is None
