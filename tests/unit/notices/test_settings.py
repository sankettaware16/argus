"""The notices' settings (Q-H4): off by default, nothing sent without a switch, a recipient and a
relay, every address and the relay checked when the configuration loads, the password a secret."""

from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from argus.config import ConfigError, load_settings
from argus.config.settings import MAX_RECIPIENTS, NoticesSettings, Settings, WebSettings
from argus.notices import run
from argus.observability.redaction import clear_registered_secrets, redact_text
from argus.ops import checks
from tests.conftest import REPO_ROOT

pytestmark = pytest.mark.unit

GOOD = {
    "enabled": True,
    "relay_host": "mail.example.org",
    "relay_from": "argus@example.org",
    "recipients": ("ta@example.org",),
}
NOW = datetime(2026, 10, 26, 6, 0, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    for key in list(os.environ):
        if key.upper().startswith("ARGUS_") or key == "CREDENTIALS_DIRECTORY":
            monkeypatch.delenv(key)
    monkeypatch.chdir(tmp_path)
    clear_registered_secrets()
    yield
    clear_registered_secrets()


def test_notices_are_off_by_default_and_the_shipped_configuration_keeps_them_off() -> None:
    assert NoticesSettings().enabled is False
    assert NoticesSettings().sends is False
    shipped = load_settings(REPO_ROOT / "config" / "argus.yaml", env_file=Path("none.env"))
    assert shipped.notices == NoticesSettings()
    assert shipped.notices.recipients == ()
    assert shipped.notices.relay_host is None


@pytest.mark.parametrize("missing", ["enabled", "recipients", "relay_host", "relay_from"])
def test_nothing_is_sent_without_the_switch_a_recipient_and_the_relay(missing: str) -> None:
    changes = {**GOOD}
    changes[missing] = False if missing == "enabled" else () if missing == "recipients" else None
    assert NoticesSettings(**changes).sends is False
    assert NoticesSettings(**GOOD).sends is True


def test_the_switch_alone_sends_nothing() -> None:
    assert NoticesSettings(enabled=True).sends is False
    assert run.config_of(Settings(notices=NoticesSettings(enabled=True))).why_not is not None


@pytest.mark.parametrize(
    "address",
    ["ta@example.org\r\nBcc: evil@example.org", "ta@example.org, evil@example.org",
     "Name <ta@example.org>", "ta@example.org\x00", "ta", "", " ta@example.org", "tá@example.org"],
)  # fmt: skip
def test_a_hostile_recipient_or_sender_stops_the_configuration(address: str) -> None:
    with pytest.raises(ValidationError):
        NoticesSettings(recipients=(address,))
    with pytest.raises(ValidationError):
        NoticesSettings(relay_from=address)


@pytest.mark.parametrize(
    "host", ["mail example.org", "mail.example.org\r\n", "a" * 300, "x:25", ""]
)
def test_a_hostile_relay_host_stops_the_configuration(host: str) -> None:
    with pytest.raises(ValidationError):
        NoticesSettings(relay_host=host)


def test_recipients_are_named_once_and_there_are_not_too_many() -> None:
    with pytest.raises(ValidationError):
        NoticesSettings(recipients=("a@example.org", "a@example.org"))
    many = tuple(f"u{n}@example.org" for n in range(MAX_RECIPIENTS + 1))
    with pytest.raises(ValidationError):
        NoticesSettings(recipients=many)
    assert len(NoticesSettings(recipients=many[:MAX_RECIPIENTS]).recipients) == MAX_RECIPIENTS


def test_a_login_needs_its_password_and_goes_only_over_tls_or_to_the_loopback() -> None:
    with pytest.raises(ValidationError):
        NoticesSettings(user="argus")
    secret = SecretStr("Synthetic-Relay-11")
    with pytest.raises(ValidationError):
        NoticesSettings(user="argus", password=secret, relay_host="mail.example.org",
                        relay_starttls=False)  # fmt: skip
    NoticesSettings(user="argus", password=secret, relay_host="mail.example.org")
    NoticesSettings(user="argus", password=secret, relay_host="127.0.0.1", relay_starttls=False)
    with pytest.raises(ValidationError):
        NoticesSettings(user="a b", password=secret)
    with pytest.raises(ValidationError):
        NoticesSettings(user="a\r\nb", password=secret)


def test_the_port_is_a_port() -> None:
    for port in (0, 65536, -1):
        with pytest.raises(ValidationError):
            NoticesSettings(relay_port=port)


def test_the_web_address_for_links() -> None:
    web = WebSettings()
    assert NoticesSettings().link_base(web) == web.link_base
    assert NoticesSettings(web_url="https://argus.example.org").link_base(web) == (
        "https://argus.example.org"
    )
    for bad in ("http://argus.example.org", "https://argus.example.org/x", "argus.example.org",
                "https://a.b\r\nX: y"):  # fmt: skip
        with pytest.raises(ValidationError):
            NoticesSettings(web_url=bad)


def test_the_settings_come_from_the_environment_and_a_list_from_a_comma_separated_string(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = tmp_path / "argus.yaml"
    config.write_text("notices:\n  enabled: false\n")
    monkeypatch.setenv("ARGUS_NOTICES__ENABLED", "true")
    monkeypatch.setenv("ARGUS_NOTICES__RELAY_HOST", "mail.example.org")
    monkeypatch.setenv("ARGUS_NOTICES__RELAY_FROM", "argus@example.org")
    monkeypatch.setenv("ARGUS_NOTICES__RECIPIENTS", "ta@example.org, ra@example.org")
    settings = load_settings(config, env_file=tmp_path / "none.env")
    assert settings.notices.sends
    assert settings.notices.recipients == ("ta@example.org", "ra@example.org")
    monkeypatch.setenv("ARGUS_NOTICES__RECIPIENTS", "ta@example.org,evil@example.org\r\nBcc: x")
    with pytest.raises(ConfigError):
        load_settings(config, env_file=tmp_path / "none.env")


def test_the_relay_password_is_a_secret_from_the_environment_and_is_masked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = tmp_path / "argus.yaml"
    config.write_text("")
    monkeypatch.setenv("ARGUS_NOTICES__USER", "argus")
    monkeypatch.setenv("ARGUS_NOTICES__PASSWORD", "Synthetic-Relay-11")
    settings = load_settings(config, env_file=tmp_path / "none.env")
    assert isinstance(settings.notices.password, SecretStr)
    assert "Synthetic-Relay-11" not in repr(settings.notices)
    assert "Synthetic-Relay-11" not in repr(settings)
    assert "Synthetic-Relay-11" in settings.secret_values()
    from argus.observability.redaction import register_secret

    for secret in settings.secret_values():
        register_secret(secret)
    assert "Synthetic-Relay-11" not in redact_text("login failed with Synthetic-Relay-11 for argus")
    wired = settings.notices.model_copy(
        update={"relay_host": "mail.example.org", "relay_from": "argus@example.org"}
    )
    cfg = run.config_of(settings.model_copy(update={"notices": wired}))
    assert cfg.relay is not None
    assert cfg.relay.password == "Synthetic-Relay-11"
    assert "Synthetic-Relay-11" not in repr(cfg)


# --------------------------------------------------------------------------- the doctor


async def test_doctor_says_off_is_a_state() -> None:
    (result,) = await checks.notices_results(Settings(), NOW)
    assert (result.label, result.name) == ("PASS", "notices")
    assert "by your choice" in result.detail


async def test_doctor_warns_when_on_with_no_recipient() -> None:
    settings = Settings(notices=NoticesSettings(**{**GOOD, "recipients": ()}))
    (result,) = await checks.notices_results(settings, NOW)
    assert result.label == "WARN"
    assert "no recipient is named" in result.detail


@pytest.mark.parametrize("missing", ["relay_host", "relay_from"])
async def test_doctor_fails_when_on_with_an_incomplete_relay(missing: str) -> None:
    settings = Settings(notices=NoticesSettings(**{**GOOD, missing: None}))
    (result,) = await checks.notices_results(settings, NOW)
    assert result.label == "FAIL"
    assert "relay is incomplete" in result.detail


async def test_doctor_warns_about_a_password_without_a_user() -> None:
    settings = Settings(notices=NoticesSettings(password=SecretStr("x" * 12)))
    (result,) = await checks.notices_results(settings, NOW)
    assert result.label == "WARN"
    assert "without a user" in result.detail


def test_a_link_address_is_checked_as_the_renderer_checks_it() -> None:
    """Review R8: a web_url or allowed host the renderer would refuse is refused at load."""
    import pytest
    from pydantic import ValidationError

    from argus.config.settings import NoticesSettings, WebSettings

    for bad in ("https://-a", "https://.", "https://a b", "https://x:0"):
        with pytest.raises(ValidationError):
            NoticesSettings(web_url=bad)
    for bad_host in ("argus.example.org:8443", "*.example.org", "-a", ""):
        with pytest.raises(ValidationError, match="allowed_hosts"):
            WebSettings(allowed_hosts=(bad_host,))
    assert NoticesSettings(web_url="https://Argus.Example.org").web_url == (
        "https://argus.example.org"
    )  # the host is lower-cased by the URL parser, as the renderer wants it
    assert WebSettings(allowed_hosts=("10.13.171.247", "argus.acme")).allowed_hosts == (
        "10.13.171.247",
        "argus.acme",
    )
