"""Kibana's relative costs on the local tier (Q-A3): loopback only, the calls in order on a
case of their own, every cost a multiple of the baseline."""

from __future__ import annotations

import io
import json
from collections.abc import Iterator
from typing import Any

import httpx
import pytest

from argus.measure import cli, kibana

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "url",
    [
        "https://10.20.60.11:5601",  # the SIEM
        "http://127.0.0.1:55610",
        "https://user:pw@127.0.0.1:55610",
        "https://127.0.0.1:55610/s/x",
        "https://example.org:55610",
        "https://127.0.0.1:99999",
        "ftp://127.0.0.1",
    ],
)
def test_only_a_loopback_https_url_is_accepted(url: str) -> None:
    with pytest.raises(ValueError, match=r"https|local tier|port|give"):
        kibana.loopback_url(url)


def test_loopback_urls_pass() -> None:
    assert kibana.loopback_url("https://127.0.0.1:55610/") == "https://127.0.0.1:55610"
    assert kibana.loopback_url("https://localhost:1") == "https://localhost:1"
    assert kibana.loopback_url("https://[::1]:55610") == "https://[::1]:55610"


class FakeTier:
    """A Kibana that keeps cases and answers like 8.19 does, for the calls measured."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, Any]] = []
        self.cases: dict[str, dict[str, Any]] = {}
        self.fail: str | None = None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        path = request.url.path
        self.calls.append((request.method, path, body))
        assert request.headers["kbn-xsrf"] == "argus-measure"
        if self.fail and self.fail in path and request.method != "GET":
            return httpx.Response(403, json={"error": "Forbidden"})
        if path == "/api/status":
            return httpx.Response(200, json={"status": {"overall": {"level": "available"}}})
        if request.method == "POST" and path.endswith("/api/cases"):
            case_id = f"case-{len(self.cases)}"
            self.cases[case_id] = {"id": case_id, "version": "v1", **body}
            return httpx.Response(200, json=self.cases[case_id])
        if request.method == "POST" and path.endswith("/comments"):
            case_id = path.split("/")[-2]
            self.cases[case_id]["version"] = "v2"
            return httpx.Response(200, json=self.cases[case_id])
        if request.method == "PATCH":
            item = body["cases"][0]
            assert self.cases[item["id"]]["version"] == item["version"]
            self.cases[item["id"]]["version"] = "v3"
            return httpx.Response(200, json=[self.cases[item["id"]]])
        return httpx.Response(200, json={"cases": [], "comments": []})


def ticking(step: float = 0.001) -> Iterator[float]:
    now = 0.0
    while True:
        yield now
        now += step


def run(tier: FakeTier, rounds: int = 3) -> kibana.Measurement:
    clock = ticking()
    with httpx.Client(transport=httpx.MockTransport(tier), base_url="https://127.0.0.1:1") as c:
        return kibana.measure(c, run="r1", rounds=rounds, timer=lambda: next(clock))


def test_the_calls_run_in_order_each_round_on_its_own_case() -> None:
    tier = FakeTier()
    result = run(tier)
    assert len(tier.cases) == 3
    first = [(m, p) for m, p, _ in tier.calls[: len(kibana.CALLS)]]
    assert first == [
        ("GET", "/api/status"),
        ("POST", "/s/acme-soc/api/cases"),
        ("GET", "/s/acme-soc/api/cases/case-0"),
        ("GET", "/s/acme-soc/api/cases/_find"),
        ("POST", "/s/acme-soc/api/cases/case-0/comments"),
        ("GET", "/s/acme-soc/api/cases/case-0/comments/_find"),
        ("PATCH", "/s/acme-soc/api/cases"),
    ]
    patch = tier.calls[6][2]["cases"][0]
    assert patch["version"] == "v2"
    assert "measured" in patch["tags"]
    created = tier.calls[1][2]
    assert created["tags"] == ["argus-measure", "run:r1"]
    assert created["settings"] == {"syncAlerts": False}
    assert {c.name for c in result.costs} == {call.name for call in kibana.CALLS}
    assert all(c.samples == 3 for c in result.costs)


def test_costs_are_relative_to_the_baseline() -> None:
    result = run(FakeTier())
    by_name = {c.name: c for c in result.costs}
    assert by_name["status"].relative_median == 1.0
    assert all(c.relative_median == 1.0 for c in result.costs)  # the fake clock ticks evenly
    text = "\n".join(kibana.lines(result))
    assert "status" not in text.split("\n", 1)[1]  # the baseline itself is not listed
    data = kibana.to_json(result)
    assert data["relative_to"] == "GET /api/status"
    assert all(set(c) == {"name", "kind", "samples", "relative_median", "relative_p95"}
               for c in data["costs"])  # fmt: skip


def test_a_refused_call_stops_the_measurement() -> None:
    tier = FakeTier()
    tier.fail = "/comments"
    with pytest.raises(kibana.TierError, match=r"case\.comment: HTTP 403"):
        run(tier)


def test_fewer_than_three_rounds_or_no_baseline_first_are_refused() -> None:
    with pytest.raises(ValueError, match="at least 3"):
        run(FakeTier(), rounds=2)
    with (
        httpx.Client(transport=httpx.MockTransport(FakeTier())) as c,
        pytest.raises(ValueError, match="baseline"),
    ):
        kibana.measure(c, run="r", calls=kibana.CALLS[1:])


def test_the_command_refuses_siem_before_reading_any_secret(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    monkeypatch.setenv("KIBANA_TIER_DIR", str(tmp_path / "nowhere"))
    assert cli.main(["kibana", "--url", "https://10.20.60.11:5601"], out=io.StringIO()) == 2
    assert cli.main(["kibana"], out=io.StringIO()) == 2  # no tier secrets: nothing sent


def test_the_client_never_follows_redirects_or_the_environment() -> None:
    client = kibana.client("https://127.0.0.1:55610", True, "elastic", "x" * 12)  # type: ignore[arg-type]
    try:
        assert client.follow_redirects is False
        assert client.trust_env is False
        assert str(client.base_url) == "https://127.0.0.1:55610"
    finally:
        client.close()
    with pytest.raises(ValueError, match="local tier only"):
        kibana.client("https://10.20.60.11:5601", True, "elastic", "x")  # type: ignore[arg-type]
