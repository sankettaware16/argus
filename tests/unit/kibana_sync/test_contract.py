"""The read-back's parsers against what Kibana 8.19.12 answered on the local tier: every case,
find page, user action and ``alerts.case_links`` answer recorded in tests/kibana/cassettes
(Q-D1, Q-D2) passes the strict models (plan §5 Q-D3: "live responses checked against the
strict models and cassettes"), and the fake Kibana answers in the same shapes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from argus.kibana_sync.model import parse_action, parse_case, parse_links
from tests.unit.kibana_sync.fake import Clock, FakeKibana

CASSETTES = Path(__file__).resolve().parents[2] / "kibana" / "cassettes"


def _exchanges() -> list[dict[str, Any]]:
    """The exchanges of the cassettes that keep Kibana's answers whole (Q-D2's lane and read
    templates; other tests record reduced answers)."""
    found = []
    whole = [*CASSETTES.glob("lane__*.json"), *CASSETTES.glob("read_templates__*.json")]
    for path in sorted(whole):
        for exchange in json.loads(path.read_text())["exchanges"]:
            if (exchange.get("status") == 200 and exchange.get("method") == "GET") or (
                exchange.get("target") == "es" and exchange.get("path", "").endswith("_search")
            ):
                found.append(exchange)
    return found


def _placeholders(value: Any) -> Any:
    """The cassettes' normalizer writes ``<time>`` for times: a real one in its place."""
    if value == "<time>":
        return "2026-10-23T10:00:00.000Z"
    if isinstance(value, dict):
        return {k: _placeholders(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_placeholders(v) for v in value]
    return value


def test_every_recorded_case_find_page_and_user_action_parses() -> None:
    cases = actions = pages = links = 0
    for exchange in _exchanges():
        answer = _placeholders(exchange["answer"])
        path = exchange["path"]
        if exchange.get("target") == "es":
            body = exchange.get("body") or {}
            if "kibana.alert.case_ids" in json.dumps(body.get("_source", [])):
                hits, _ = parse_links(answer)
                links += len(hits)
            continue
        if path.endswith("/api/cases/_find"):
            pages += 1
            for case in answer["cases"]:
                parse_case(case)
                cases += 1
        elif path.endswith("/user_actions/_find"):
            for item in answer["userActions"]:
                parse_action(item)
                actions += 1
        elif "/api/cases/" in path and path.count("/") == 5 and isinstance(answer, dict):
            if "created_at" in answer:
                parse_case(answer)
                cases += 1
    counts = (cases, pages, actions, links)
    assert min(counts) >= 1, counts
    assert cases >= 5, counts
    assert actions >= 4, counts


@pytest.mark.parametrize("key", ["cases", "page", "per_page", "total"])
def test_the_fake_find_has_kibanas_keys(key: str) -> None:
    recorded = [
        _placeholders(e["answer"])
        for e in _exchanges()
        if e["path"].endswith("/api/cases/_find") and e.get("target") != "es"
    ]
    assert recorded
    assert all(key in page for page in recorded)
    fake = FakeKibana(Clock())
    fake.create()
    answer = fake._find({"page": "1", "perPage": "10"})
    assert key in json.loads(answer.body)


def test_the_fake_case_has_every_key_kibana_answers() -> None:
    recorded = next(
        _placeholders(e["answer"])
        for e in _exchanges()
        if e["path"].endswith("/api/cases/_find") and e["answer"].get("cases")
    )["cases"][0]
    fake = FakeKibana(Clock())
    case = fake.cases[fake.create()]
    assert set(recorded) <= set(case), set(recorded) - set(case)
    recorded_action = next(
        _placeholders(e["answer"])
        for e in _exchanges()
        if e["path"].endswith("/user_actions/_find")
    )["userActions"][0]
    assert set(recorded_action) == set(fake.actions[case["id"]][0])
