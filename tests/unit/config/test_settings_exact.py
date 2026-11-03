"""Every setting's default and every bound, written out (2026-10-21: the mutation run found the
sections added after R1 — the SIEM, its budget and health, assets, web, the off switches — with
their defaults and limits unpinned). The values are the ones the decisions name (D-022 budget,
plan §5.1 health, D-033 CA, D-052/D-104 web, D-056/D-061 switches)."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from argus.config.errors import ConfigError
from argus.config.settings import (
    AssetsSettings,
    EnrichmentSettings,
    ReferenceSettings,
    SiemBudgetSettings,
    SiemHealthSettings,
    SiemSettings,
    WebSettings,
    WritebackSettings,
)

pytestmark = pytest.mark.unit


def ok(model: type[BaseModel], **values: Any) -> None:
    model.model_validate(values)


def bad(model: type[BaseModel], **values: Any) -> None:
    with pytest.raises(ValidationError):
        model.model_validate(values)


def test_the_defaults() -> None:
    b = SiemBudgetSettings()
    assert (b.took_per_minute_ms, b.burst_ms, b.took_per_day_ms) == (3_000, 3_000, 3_600_000)
    assert (b.concurrency, b.heavy_concurrency, b.heavy_per_minute, b.heavy_per_day,
            b.probes_per_minute) == (2, 1, 6, 2_000, 12)  # fmt: skip
    h = SiemHealthSettings()
    assert (h.disk_caution, h.disk_degraded, h.disk_stop, h.heap_caution, h.load_caution) == (
        85.0, 90.0, 95.0, 85.0, 16.0)  # fmt: skip
    assert h.ingest_lag_degraded == timedelta(minutes=15)
    e = SiemSettings()
    assert (e.url, e.ca_file) == (None, Path("data/certs/siem-ca.crt"))
    with pytest.raises(ConfigError, match=r"siem\.url is not configured"):
        e.address()
    assert (e.api_key, e.writer_api_key) == (None, None)
    assert AssetsSettings().map_path == Path("data/assets/asset_map.yaml")
    w = WebSettings()
    assert (w.port, w.session_idle) == (8765, timedelta(minutes=30))  # DQ17 (Q-A1)
    assert (w.session_absolute, w.public_url) == (timedelta(hours=8), None)
    off = (ReferenceSettings().ti_sync, EnrichmentSettings().log_queries,
           EnrichmentSettings().proxy_aggregations, WritebackSettings().enabled)  # fmt: skip
    assert off == (False, False, False, False)  # each needs the user's first run (D-056, D-061)


@pytest.mark.parametrize(
    ("name", "low", "high"),
    [("took_per_minute_ms", 100, 60_000), ("burst_ms", 100, 60_000),
     ("took_per_day_ms", 60_000, 86_400_000), ("concurrency", 1, 4), ("heavy_concurrency", 1, 2),
     ("heavy_per_minute", 1, 60), ("heavy_per_day", 1, 20_000), ("probes_per_minute", 1, 60)],
)  # fmt: skip
def test_the_budget_bounds_are_inclusive(name: str, low: int, high: int) -> None:
    ok(SiemBudgetSettings, **{name: low})
    ok(SiemBudgetSettings, **{name: high})
    bad(SiemBudgetSettings, **{name: low - 1})
    bad(SiemBudgetSettings, **{name: high + 1})


def test_the_health_bounds() -> None:
    # the disk thresholds above 0 and below 100 (stop may be 100), rising
    ok(SiemHealthSettings, disk_caution=0.5, disk_degraded=0.6, disk_stop=0.7)
    bad(SiemHealthSettings, disk_caution=0, disk_degraded=0.6, disk_stop=0.7)
    ok(SiemHealthSettings, disk_caution=99.0, disk_degraded=99.5, disk_stop=100)
    bad(SiemHealthSettings, disk_caution=99.0, disk_degraded=100, disk_stop=100)
    bad(SiemHealthSettings, disk_caution=100, disk_degraded=100, disk_stop=100)
    bad(SiemHealthSettings, disk_caution=99.0, disk_degraded=99.5, disk_stop=100.5)
    bad(SiemHealthSettings, disk_caution=0.5, disk_degraded=0, disk_stop=0.7)
    bad(SiemHealthSettings, disk_caution=0.5, disk_degraded=0.6, disk_stop=0)
    for name, high in (("heap_caution", 100), ("load_caution", 1024)):
        ok(SiemHealthSettings, **{name: 0.5})
        ok(SiemHealthSettings, **{name: high})
        bad(SiemHealthSettings, **{name: 0})
        bad(SiemHealthSettings, **{name: high + 0.5})
    ok(SiemHealthSettings, ingest_lag_degraded="1m")
    ok(SiemHealthSettings, ingest_lag_degraded="24h")
    bad(SiemHealthSettings, ingest_lag_degraded="59s")
    bad(SiemHealthSettings, ingest_lag_degraded="25h")


@pytest.mark.parametrize(
    ("caution", "degraded", "stop"), [(90, 90, 95), (85, 95, 95), (96, 90, 95), (85, 90, 89)]
)
def test_disk_thresholds_must_rise(caution: float, degraded: float, stop: float) -> None:
    with pytest.raises(ValidationError) as raised:
        SiemHealthSettings(disk_caution=caution, disk_degraded=degraded, disk_stop=stop)
    assert raised.value.errors()[0]["msg"] == (
        "Value error, disk thresholds must rise: caution < degraded < stop"
    )


def test_the_siem_address_index_names_and_sources() -> None:
    for url in ("https://elk.example:9200", "https://10.0.0.1", "https://[::1]:9200"):
        assert SiemSettings(url=url).url == url
    for url in ("http://elk.example:9200", "https://elk.example/path", "https://u@elk.example",
                "https://elk.example?x=1", "https://"):  # fmt: skip
        with pytest.raises(ValidationError) as raised:
            SiemSettings(url=url)
        assert raised.value.errors()[0]["msg"] == (
            "Value error, must be https://host[:port] with no path, user or query"
        ), url
    # the host part allows ":" (IPv6), so a port is not checked on its own: a bad one fails at
    # connection time, not here (written down, not changed: R1 behaviour)
    assert SiemSettings(url="https://elk.example:123456").url == "https://elk.example:123456"
    bad(SiemSettings, ti_indices=["x"])  # moved to site.ti_indices (D-283)


def test_the_web_bounds_and_messages() -> None:
    for port in (1024, 65535):
        assert WebSettings(port=port).port == port
    for port in (1023, 65536):
        bad(WebSettings, port=port)
    ok(WebSettings, session_idle="5m")
    ok(WebSettings, session_idle="7d")
    bad(WebSettings, session_idle="4m")
    bad(WebSettings, session_idle="8d")
    with pytest.raises(ValidationError) as raised:
        WebSettings(tls_cert=Path("c"))
    assert raised.value.errors()[0]["msg"] == "Value error, tls_cert and tls_key go together"
    with pytest.raises(ValidationError) as raised:
        WebSettings(host="10.0.0.5")
    assert raised.value.errors()[0]["msg"] == (
        "Value error, the web app listens on the loopback only unless it has TLS (tls_cert,"
        " tls_key), allowed_hosts and allowed_networks (D-104); reviewers can also use an SSH"
        " forward"
    )
