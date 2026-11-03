"""The case team's settings (AR8, D-195): posting is off by default, the numbers are bounded, the
six keys are secrets that fail closed, class WC needs all six, and ``gate_problems`` says what
stops a live post."""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from argus.caseteam import service
from argus.config.settings import CaseTeamSettings, KibanaSettings, Settings, load_settings
from argus.observability.redaction import clear_registered_secrets

pytestmark = pytest.mark.unit
USERS = ("lead", "evidence", "intel", "responder", "hunter", "reporter")
ALL_KEYS = {f"{u}_api_key": SecretStr(f"Synthetic-Team-{u}") for u in USERS}


def test_the_defaults_post_nothing() -> None:
    t = CaseTeamSettings()
    assert (t.post, t.auto_min_confidence, t.per_day, t.canary) == (False, 0.8, 5, 1)
    assert (t.max_alerts, t.min_update_gap) == (500, timedelta(hours=6))
    assert (t.alerts_per_call, t.alert_pause) == (100, timedelta(seconds=3))  # D-235, D-242
    assert t.keys() == {}
    assert Settings().case_team == t


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("auto_min_confidence", -0.1),
        ("auto_min_confidence", 1.1),
        ("per_day", -1),
        ("per_day", 51),
        ("canary", -1),
        ("max_alerts", 0),
        ("max_alerts", 1_001),
        ("alerts_per_call", 0),
        ("alerts_per_call", 101),
        ("alert_pause", "999ms"),  # under the least courtesy gap (D-242)
        ("alert_pause", "11m"),
        ("look", 0),
        ("min_update_gap", "8d"),
        ("bogus", 1),
    ],
)
def test_the_numbers_are_bounded_and_an_unknown_key_is_an_error(field: str, bad: object) -> None:
    with pytest.raises(ValidationError):
        CaseTeamSettings.model_validate({field: bad})


@pytest.mark.parametrize(
    ("field", "good"),
    [
        ("auto_min_confidence", 0.0),
        ("auto_min_confidence", 1.0),
        ("per_day", 0),
        ("per_day", 50),
        ("canary", 0),
        ("canary", 20),
        ("max_alerts", 1),
        ("max_alerts", 1_000),
        ("alerts_per_call", 1),
        ("alerts_per_call", 100),
        ("alert_pause", "1s"),
        ("alert_pause", "10m"),
    ],
)
def test_the_bounds_are_inclusive(field: str, good: object) -> None:
    CaseTeamSettings.model_validate({field: good})


def test_the_keys_are_secrets_that_never_print() -> None:
    t = CaseTeamSettings(**ALL_KEYS)
    assert set(t.keys()) == {f"argus-{u}" for u in USERS}
    assert "Synthetic-Team-lead" not in repr(t)
    assert "Synthetic-Team-lead" not in str(t.model_dump())
    assert t.keys()["argus-hunter"].get_secret_value() == "Synthetic-Team-hunter"
    empty = CaseTeamSettings(lead_api_key=SecretStr(""))
    assert empty.keys() == {}  # a blank key is no key


def test_class_wc_needs_all_six_users_keys() -> None:
    with pytest.raises(ValidationError, match="write class WC needs the case team's keys"):
        Settings(kibana=KibanaSettings(write_classes=("WC",)))
    partial = dict(ALL_KEYS)
    del partial["intel_api_key"]
    with pytest.raises(ValidationError, match="argus-intel"):
        Settings(
            kibana=KibanaSettings(write_classes=("WC",)), case_team=CaseTeamSettings(**partial)
        )
    ok = Settings(
        kibana=KibanaSettings(write_classes=("WC",)), case_team=CaseTeamSettings(**ALL_KEYS)
    )
    assert "WC" in ok.kibana.write_classes
    Settings(case_team=CaseTeamSettings(**ALL_KEYS))  # keys without the class are fine


def test_a_write_class_that_does_not_exist_is_refused() -> None:
    with pytest.raises(ValidationError):
        KibanaSettings(write_classes=("WX",))  # type: ignore[arg-type]


def test_the_keys_come_from_the_environment_never_the_yaml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clear_registered_secrets()
    config = tmp_path / "argus.yaml"
    config.write_text("case_team:\n  post: true\n  per_day: 3\n", encoding="utf-8")
    monkeypatch.setenv("ARGUS_CASE_TEAM__LEAD_API_KEY", "Synthetic-FromEnv-lead")
    settings = load_settings(config, env_file=tmp_path / ".env")
    assert settings.case_team.post is True
    assert settings.case_team.per_day == 3
    assert settings.case_team.lead_api_key is not None
    assert settings.case_team.lead_api_key.get_secret_value() == "Synthetic-FromEnv-lead"
    assert "Synthetic-FromEnv-lead" in settings.secret_values()  # masked in logs
    clear_registered_secrets()


def test_the_shipped_configuration_posts_nothing() -> None:
    from tests.conftest import REPO_ROOT

    settings = load_settings(
        REPO_ROOT / "config" / "argus.yaml", env_file=Path("/nonexistent/.env")
    )
    assert settings.case_team.post is False
    assert "WC" not in settings.kibana.write_classes


# --------------------------------------------------------------------------- what stops a post


def live() -> Settings:
    from argus.config.settings import WebSettings

    return Settings(
        kibana=KibanaSettings(
            enabled=True,
            url="https://kibana.example:5601",
            write_classes=("WC",),
            reader_api_key=SecretStr("Synthetic-Reader"),
        ),
        case_team=CaseTeamSettings(post=True, keys_expire=date(2027, 10, 1), **ALL_KEYS),
        web=WebSettings(public_url="https://argus.example", allowed_hosts=("argus.example",)),
    )


def test_a_default_host_cannot_post_and_says_why() -> None:
    problems = service.gate_problems(Settings())
    assert any("case_team.post is false" in p for p in problems)
    assert any("kibana.enabled is false" in p for p in problems)
    assert any("WC is not switched on" in p for p in problems)
    assert any("no key is installed for argus-lead" in p for p in problems)
    assert any("web.public_url is not set" in p for p in problems)


def test_a_fully_configured_host_has_only_the_approval_key_to_go() -> None:
    problems = service.gate_problems(live(), now=_now())
    assert problems == ["no approval key is configured: the canary's approval cannot be checked"]
    no_canary = live().model_copy(
        update={"case_team": live().case_team.model_copy(update={"canary": 0})}
    )
    assert service.gate_problems(no_canary, now=_now()) == []


def test_expired_or_unrecorded_expiry_is_a_problem() -> None:
    base = live()
    gone = base.model_copy(
        update={"case_team": base.case_team.model_copy(update={"keys_expire": date(2026, 1, 1)})}
    )
    assert any("expired on 2026-01-01" in p for p in service.gate_problems(gone, now=_now()))
    none = base.model_copy(
        update={"case_team": base.case_team.model_copy(update={"keys_expire": None})}
    )
    assert any("no expiry is recorded" in p for p in service.gate_problems(none, now=_now()))


def test_the_post_config_carries_the_settings_the_poster_reads() -> None:
    config = service.post_config(live(), writer=True)
    assert config.post
    assert config.canary == 1
    assert config.per_day == 5
    assert config.max_alerts == 500
    assert (config.alerts_per_call, config.alert_pause) == (100, timedelta(seconds=3))
    assert config.keys == frozenset(f"argus-{u}" for u in USERS)
    # the web and the preview do not hold the keys (custody): they leave that check to the writer
    assert service.post_config(live()).keys is None
    assert service.post_config(live()).has_key("argus-lead")
    assert not service.post_config(Settings(), writer=True).has_key("argus-lead")
    assert config.kibana_prefixes == ("https://kibana.example:5601",)
    assert config.link_base == "https://argus.example"
    assert config.space == "acme-soc"


def _now():  # type: ignore[no-untyped-def]
    from datetime import UTC, datetime

    return datetime(2026, 10, 29, tzinfo=UTC)


def test_the_lanes_caps_carry_the_teams_call_size_and_pause() -> None:
    from argus.gateway.kibana.service import caps

    base = caps(Settings())
    assert (base.team_alerts_per_call, base.team_alert_gap) == (100, timedelta(seconds=3))
    chosen = caps(Settings(case_team={"alerts_per_call": 10, "alert_pause": "90s"}))
    assert (chosen.team_alerts_per_call, chosen.team_alert_gap) == (10, timedelta(seconds=90))
    assert chosen.alerts_per_call == 5  # the writer's own cap is not the team's
