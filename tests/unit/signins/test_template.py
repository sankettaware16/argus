"""The sign-in template (AR6, D-216): one request is one daily index and at most 200 addresses,
the gateway's validator accepts exactly it, and nothing else about the contract is loosened."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from argus import site
from argus.config.settings import SIGNIN_ACTIONS, SiemSettings
from argus.gateway import indices
from argus.gateway.errors import (
    PartialResultError,
    SourceMissingError,
    TemplateRejectedError,
)
from argus.gateway.gateway import Gateway, Targets
from argus.gateway.service import targets
from argus.gateway.templates import REGISTRY, Purpose, plan_key
from argus.gateway.validator import FinalRequest, validate
from argus.signins import model as m
from argus.signins.run import preview_gateway
from argus.signins.template import DayParams, SigninsDay
from tests.unit.gateway.fakes import FakeTransport, listing, make, ok
from tests.unit.signins import kit

pytestmark = pytest.mark.unit

NOW = datetime(2026, 10, 29, 6, 0, tzinfo=UTC)
SSO = Targets(log_sources=frozenset({"sso"}))
ADDRESSES = tuple(f"10.1.{i // 250}.{i % 250 + 1}" for i in range(200))


def final(params: DayParams, gateway: Gateway | None = None) -> FinalRequest:
    gw = gateway or preview_gateway(SSO)
    return gw.preview(SigninsDay(), params, deadline=NOW + timedelta(seconds=30), now=NOW)


def test_the_template_is_registered_heavy_and_a_log_search() -> None:
    spec = REGISTRY["signins.day"].spec()
    assert (spec.name, spec.version) == ("signins.day", 1)
    assert spec.cost.value == "heavy"
    assert spec.family.value == "log"
    assert spec.max_agg_depth == 3
    assert spec.max_buckets is not None
    assert spec.max_buckets < 65_536


def test_a_request_is_one_daily_index_whole_day_and_never_two() -> None:
    request = final(kit.params(["10.1.2.3"]))
    assert request.indices == ("acme-logs-sso-2026.10.28",)
    # the same day's end is midnight, which an unpadded window does not carry into the next index
    assert indices.exact_indices("p-", kit.at(0), kit.at(0) + timedelta(days=1)) == (
        "p-2026.10.28",
    )
    # a padded window would have wanted three indices for the same range and been refused
    with pytest.raises(ValueError, match="at most 2"):
        indices.daily_indices("p-", kit.at(0), kit.at(0) + timedelta(days=1))


def test_the_body_filters_by_address_action_and_the_day_and_returns_no_document() -> None:
    body: dict[str, Any] = final(kit.params(["10.1.2.3", "10.1.2.4"])).body
    assert body["size"] == 0
    assert body["track_total_hits"] is False
    clauses = body["query"]["bool"]["filter"]
    assert {"terms": {"source.ip": ["10.1.2.3", "10.1.2.4"]}} in clauses
    assert {"terms": {"event.action.keyword": list(SIGNIN_ACTIONS)}} in clauses
    window = next(c["range"]["@timestamp"] for c in clauses if "range" in c)
    assert window == {"gte": "2026-10-28T00:00:00.000Z", "lt": "2026-10-29T00:00:00.000Z"}
    assert "timeout" in body  # the gateway adds the server-side timeout


def test_the_aggregations_are_the_ones_the_parser_reads() -> None:
    aggs = final(kit.params()).body["aggs"]
    assert set(aggs) == {"ips"}
    assert aggs["ips"]["terms"] == {"field": "source.ip", "size": 1}
    inner = aggs["ips"]["aggs"]
    assert inner["accounts"] == {"cardinality": {"field": "user.name.keyword"}}
    users = inner["users"]
    assert users["terms"] == {"field": "user.name.keyword", "size": m.MAX_USERS}
    assert set(users["aggs"]) == {"first", "last", "outcomes", "agents", "hours"}
    assert users["aggs"]["agents"]["terms"]["size"] == m.MAX_AGENTS
    hours = users["aggs"]["hours"]["date_histogram"]
    assert (hours["fixed_interval"], hours["min_doc_count"]) == ("1h", 1)


def test_two_hundred_addresses_pass_the_validator_with_room_to_spare() -> None:
    request = final(kit.params(ADDRESSES))
    assert len(request.body["query"]["bool"]["filter"][0]["terms"]["source.ip"]) == 200
    assert len(json.dumps(request.body)) < 8_000  # the contract allows 64 KB


def test_more_than_two_hundred_addresses_or_a_repeat_is_refused_before_a_request_exists() -> None:
    more = (*ADDRESSES, "10.9.9.9")
    with pytest.raises(ValidationError):
        kit.params(more)
    with pytest.raises(ValidationError, match="once"):
        kit.params(["10.1.2.3", "10.1.2.3"])
    with pytest.raises(ValidationError):
        kit.params([])


@pytest.mark.parametrize("bad", ["10.1.2", "10.1.2.300", "fe80::1", "010.1.2.3", "10.1.2.3/24", ""])
def test_an_address_is_canonical_ipv4_text(bad: str) -> None:
    with pytest.raises(ValidationError):
        kit.params([bad])


def test_the_end_is_inside_the_day() -> None:
    start = m.day_start(kit.DAY)
    for end in (start, start - timedelta(hours=1), start + timedelta(days=1, seconds=1)):
        with pytest.raises(ValidationError, match="inside the day"):
            kit.params(end=end)
    with pytest.raises(ValidationError):
        kit.params(end=datetime(2026, 10, 28, 12, 0))  # noqa: DTZ001 - no timezone is the point
    assert kit.params(end=start + timedelta(hours=6)).end == start + timedelta(hours=6)


def test_the_addresses_are_kept_sorted_by_value() -> None:
    p = kit.params(["10.1.10.1", "10.1.2.9", "10.1.2.10"])
    assert p.addresses == ("10.1.2.9", "10.1.2.10", "10.1.10.1")
    q = kit.params(["10.1.2.10", "10.1.10.1", "10.1.2.9"])
    plan_a, plan_b = SigninsDay().plan(p), SigninsDay().plan(q)
    assert plan_key(plan_a, p) == plan_key(plan_b, q)  # the same request is the same key


def test_a_request_for_another_day_is_another_key_and_an_exact_window_is_marked() -> None:
    a, b = kit.params(), kit.params(day=date(2026, 10, 27))
    assert plan_key(SigninsDay().plan(a), a) != plan_key(SigninsDay().plan(b), b)
    window = SigninsDay().plan(a).window
    assert window is not None
    assert window.pad is False


def test_the_default_targets_do_not_know_the_sso_source_but_the_settings_do() -> None:
    with pytest.raises(TemplateRejectedError, match="not a log source"):
        final(kit.params(), preview_gateway(Targets()))
    assert "sso" in targets(SiemSettings()).log_sources
    assert "squid" in targets(SiemSettings()).log_sources
    assert "sso" not in site.active().watched_sources  # not watched by health or freshness


def test_the_validator_still_holds_every_other_template_to_the_usual_limits() -> None:
    """The deeper nesting and the larger bucket budget belong to this template's spec alone."""
    request = final(kit.params(ADDRESSES))
    shallow = replace(request.spec, max_agg_depth=None)
    with pytest.raises(TemplateRejectedError, match="nest at most 2"):
        validate(replace(request, spec=shallow))
    two_deep = replace(request.spec, max_buckets=None)
    with pytest.raises(TemplateRejectedError, match="buckets"):
        validate(replace(request, spec=two_deep))


def test_a_changed_body_is_refused_by_the_validator() -> None:
    request = final(kit.params())
    body = json.loads(json.dumps(request.body))
    body["aggs"]["ips"]["aggs"]["users"]["terms"]["field"] = "user.email.keyword"
    with pytest.raises(TemplateRejectedError, match="may not be aggregated"):
        validate(replace(request, body=body))
    body = json.loads(json.dumps(request.body))
    body["query"]["bool"]["filter"].append({"term": {"user.name.keyword": "user01"}})
    with pytest.raises(TemplateRejectedError, match="may not be filtered on"):
        validate(replace(request, body=body))
    body = json.loads(json.dumps(request.body))
    body["size"] = 10
    with pytest.raises(TemplateRejectedError):
        validate(replace(request, body=body))


def test_the_bucket_budget_fits_elasticsearchs_own_limit_for_a_full_batch() -> None:
    """200 addresses, ten accounts each, 3 + 3 + 25 buckets under each (the hours' bound is the
    next midnight, so the validator counts 25): 64,200 at the worst."""
    spec = SigninsDay.spec()
    worst = 200 + 200 * m.MAX_USERS * (1 + 3 + 3 + 25)
    assert worst == 64_200
    assert spec.max_buckets is not None
    assert worst <= spec.max_buckets < 65_536


# ---------------------------------------------------------------- through the gateway


def gateway_for(*replies: Any) -> tuple[Gateway, FakeTransport]:
    transport = FakeTransport()
    transport.on("/_resolve/index", ok(listing("acme-logs-sso-2026.10.28")))
    for reply in replies:
        transport.on("/_search", reply)
    gateway, transport, _, _ = make(transport)
    gateway.targets = SSO
    return gateway, transport


async def test_the_gateway_sends_the_request_to_the_one_index_with_the_forced_parameters() -> None:
    body = kit.answer({"10.1.2.3": [kit.sighting()]})
    gateway, transport = gateway_for(ok(body))
    result = await gateway.run(
        SigninsDay(), kit.params(), purpose=Purpose.INVESTIGATE, component="signins",
        deadline=kit.at(12, day=date(2026, 10, 9)) + timedelta(hours=1),
    )  # fmt: skip
    assert result.indices == ("acme-logs-sso-2026.10.28",)
    (call,) = [c for c in transport.calls if c.path.endswith("/_search")]
    assert call.path == "/acme-logs-sso-2026.10.28/_search"
    assert dict(call.params)["allow_partial_search_results"] == "false"
    assert call.opaque_id == "argus-signins/signins.day@1"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b.update(timed_out=True),
        lambda b: b["_shards"].update(failed=1),
        lambda b: b["_shards"].update(successful=0),
        lambda b: b.update(terminated_early=True),
    ],
    ids=["timed_out", "shard_failed", "no_shard_answered", "terminated_early"],
)
async def test_a_timed_out_or_shard_failed_answer_is_never_data(mutate: Any) -> None:
    body = kit.answer({"10.1.2.3": [kit.sighting()]})
    mutate(body)
    gateway, _ = gateway_for(ok(body))
    with pytest.raises(PartialResultError):
        await gateway.run(
            SigninsDay(), kit.params(), purpose=Purpose.INVESTIGATE, component="signins",
            deadline=kit.at(12, day=date(2026, 10, 9)) + timedelta(hours=1),
        )  # fmt: skip


async def test_a_day_whose_index_is_gone_is_said_not_skipped() -> None:
    transport = FakeTransport()
    transport.on("/_resolve/index", ok(listing("acme-logs-sso-2026.10.28")))
    gateway, transport, _, _ = make(transport)
    gateway.targets = SSO
    old = kit.params(day=date(2026, 10, 3), end=m.day_end(date(2026, 10, 3)))
    with pytest.raises(SourceMissingError) as gone:
        await gateway.run(
            SigninsDay(), old, purpose=Purpose.INVESTIGATE, component="signins",
            deadline=kit.at(12, day=date(2026, 10, 9)) + timedelta(hours=1),
        )  # fmt: skip
    assert gone.value.reason == "source_expired"
    assert not [c for c in transport.calls if c.path.endswith("/_search")]


def test_the_hours_bound_is_the_next_midnight_so_the_last_hour_is_kept() -> None:
    """SIEM, 2026-10-30: a bound of 23:59:59.999 dropped the 23:00 hour and the answer failed."""
    params = DayParams(
        day=date(2026, 10, 29),
        addresses=("10.0.0.7",),
        actions=("user_login_success",),
        end=datetime(2026, 10, 30, tzinfo=UTC),
    )
    body = SigninsDay().build(params).body
    assert body is not None
    hours = body["aggs"]["ips"]["aggs"]["users"]["aggs"]["hours"]["date_histogram"]
    assert hours["hard_bounds"]["max"] == "2026-10-30T00:00:00.000Z"
