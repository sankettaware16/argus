"""The Inbox's address (D-052, D-104): the loopback, or the network only with TLS and both
allowlists."""

from __future__ import annotations

from ipaddress import ip_network
from pathlib import Path

import pytest
from pydantic import ValidationError

from argus.config import load_settings
from argus.config.settings import WebSettings

pytestmark = pytest.mark.unit
TLS = {"tls_cert": "data/tls/argus.crt", "tls_key": "data/tls/argus.key"}
LAN = {"host": "0.0.0.0", **TLS, "allowed_hosts": ["10.13.171.247"],  # noqa: S104 - the test
       "allowed_networks": ["10.13.171.0/24"]}  # fmt: skip


def test_the_loopback_by_default_over_http() -> None:
    web = WebSettings()
    assert (web.host, web.port, web.scheme) == ("127.0.0.1", 8765, "http")
    assert (web.tls_cert, web.tls_key, web.allowed_hosts, web.allowed_networks) == (
        None, None, (), (),
    )  # fmt: skip
    assert WebSettings(host="localhost").host == "localhost"


@pytest.mark.parametrize(
    "missing", ["tls_cert", "tls_key", "allowed_hosts", "allowed_networks", "everything"]
)
def test_another_address_needs_tls_and_both_allowlists(missing: str) -> None:
    given = {"host": "0.0.0.0"} if missing == "everything" else {  # noqa: S104
        k: v for k, v in LAN.items() if k != missing
    }  # fmt: skip
    with pytest.raises(ValidationError, match=r"tls_cert and tls_key go together|D-104"):
        WebSettings.model_validate(given)


def test_the_network_with_everything_set() -> None:
    web = WebSettings.model_validate(LAN)
    assert web.scheme == "https"
    assert web.tls_cert == Path("data/tls/argus.crt")
    assert web.allowed_networks == (ip_network("10.13.171.0/24"),)
    loop = WebSettings.model_validate(TLS)  # TLS on the loopback: fine without allowlists
    assert (loop.host, loop.scheme) == ("127.0.0.1", "https")


def test_a_certificate_without_its_key_is_refused() -> None:
    with pytest.raises(ValidationError, match="tls_cert and tls_key go together"):
        WebSettings(tls_cert=Path("c"))
    with pytest.raises(ValidationError, match=r"not a valid|valid IPv4 or IPv6 network"):
        WebSettings.model_validate({**LAN, "allowed_networks": ["campus"]})


def test_the_environment_can_open_it(write_config, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    for key, value in (("HOST", "0.0.0.0"), ("TLS_CERT", "c.crt"), ("TLS_KEY", "c.key"),  # noqa: S104
                       ("ALLOWED_HOSTS", "10.13.171.247, argus.local"),
                       ("ALLOWED_NETWORKS", "10.13.171.0/24,10.13.172.0/24")):  # fmt: skip
        monkeypatch.setenv(f"ARGUS_WEB__{key}", value)
    web = load_settings(write_config(""), env_file=None).web
    assert (web.host, web.scheme) == ("0.0.0.0", "https")  # noqa: S104
    assert web.allowed_hosts == ("10.13.171.247", "argus.local")
    assert web.allowed_networks == (ip_network("10.13.171.0/24"), ip_network("10.13.172.0/24"))
    monkeypatch.delenv("ARGUS_WEB__TLS_CERT")
    monkeypatch.delenv("ARGUS_WEB__TLS_KEY")
    with pytest.raises(Exception, match=r"D-104|tls_cert"):
        load_settings(write_config(""), env_file=None)


def test_sessions_end_after_30_idle_minutes_and_8_hours_by_default() -> None:
    """Plan §7.2, DQ17 (D-110): 30 minutes without a person's own request, 8 hours at most."""
    from datetime import timedelta

    web = WebSettings()
    assert (web.session_idle, web.session_absolute) == (timedelta(minutes=30), timedelta(hours=8))
    assert WebSettings(session_absolute="10m").session_absolute == timedelta(minutes=10)
    for bad in ("9m", "8d"):
        with pytest.raises(ValidationError):
            WebSettings(session_absolute=bad)


@pytest.mark.parametrize(
    ("given", "kept"),
    [
        ("https://localhost", "https://localhost"),
        ("https://LOCALHOST:8443/", "https://localhost:8443"),
        ("http://127.0.0.1:8765", "http://127.0.0.1:8765"),
    ],
)
def test_the_public_url_is_a_scheme_and_a_host(given: str, kept: str) -> None:
    assert WebSettings(public_url=given).public_url == kept


@pytest.mark.parametrize(
    "given",
    [
        "argus.example", "ftp://localhost", "https://user@localhost", "https://u:p@localhost",
        "https://localhost/path", "https://localhost?x=1", "https://localhost#f",
        "https://localhost:0", "https://localhost:99999", " https://localhost",
        "http://10.13.171.247",  # http only on the loopback
        "https://[::1]", "https://bad_host",
    ],
)  # fmt: skip
def test_a_public_url_with_anything_else_is_refused(given: str) -> None:
    with pytest.raises(ValidationError, match="public_url"):
        WebSettings.model_validate({**LAN, "public_url": given})


def test_the_public_url_must_reach_this_server() -> None:
    with pytest.raises(ValidationError, match="allowed_hosts"):
        WebSettings(public_url="https://argus.example")
    named = WebSettings.model_validate({**LAN, "allowed_hosts": ["10.13.171.247", "argus.acme"],
                                        "public_url": "https://argus.acme"})  # fmt: skip
    assert named.link_base == "https://argus.acme"


def test_links_without_a_public_url_use_this_servers_address() -> None:
    assert WebSettings().link_base == "http://127.0.0.1:8765"
    assert WebSettings.model_validate(LAN).link_base == "https://10.13.171.247:8765"
    on_443 = WebSettings.model_validate({**LAN, "port": 8765}).model_copy(update={"port": 443})
    assert on_443.link_base == "https://10.13.171.247"
