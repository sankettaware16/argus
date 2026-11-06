"""Tests written for mutation survivors (D-040) in templates, indices and the breaker: stored
enumeration values pinned, defaults and frozenness checked, boundaries at their exact value."""

from __future__ import annotations

import dataclasses
from datetime import UTC, date, datetime, timedelta
from typing import Any

import pydantic
import pytest

from argus.gateway import breaker as br
from argus.gateway.errors import SourceMissingError
from argus.gateway.indices import pad_only_after, resolve
from argus.gateway.templates import (
    COMPONENT,
    COMPONENTS,
    REGISTRY,
    CostClass,
    Endpoint,
    Family,
    NoParams,
    Params,
    Purpose,
    RequestPlan,
    Spec,
    Template,
    Window,
    register,
)

pytestmark = pytest.mark.unit

T0 = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)
P = "acme-logs-squid-"


# --------------------------------------------------------------------------- templates


def test_stored_enumeration_values_are_pinned() -> None:
    """These strings are written to the request ledger and shown in the UI."""
    assert [e.value for e in Endpoint] == [
        "info", "search", "mget", "node_stats", "index_blocks", "resolve_index", "authenticate",
        "has_privileges", "license", "security_health",  # the last two: Q-D2
        "discover_indices", "field_mapping", "ilm_policies",  # `argus discover` (P4-D1)
    ]  # fmt: skip
    assert [f.value for f in Family] == ["alerts", "log", "ti", "cluster", "discovery"]
    assert [c.value for c in CostClass] == ["probe", "light", "medium", "heavy"]
    assert [p.value for p in Purpose] == [
        "probe", "selftest", "collect", "backfill", "reconcile", "enrich", "writeback",
        # Q-D2: the Phase 3 lanes (plan §7.8)
        "investigate", "freshness", "measure", "identity", "kibana_read", "kibana_write",
        "discover",  # P4-D1
        "check",  # P4-F E3
    ]  # fmt: skip
    assert COMPONENT == {
        Purpose.PROBE: None, Purpose.SELFTEST: None, Purpose.COLLECT: "collector",
        Purpose.BACKFILL: "collector", Purpose.RECONCILE: "collector",
        Purpose.ENRICH: "enrichment", Purpose.WRITEBACK: "writeback",
        Purpose.INVESTIGATE: "investigation", Purpose.FRESHNESS: "freshness",
        Purpose.MEASURE: None, Purpose.IDENTITY: "identity", Purpose.KIBANA_READ: "kibana",
        Purpose.KIBANA_WRITE: "cases", Purpose.DISCOVER: None, Purpose.CHECK: "checking",
    }  # fmt: skip
    assert COMPONENTS == (
        "collector", "enrichment", "kibana", "writeback",
        "investigation", "freshness", "cases", "identity", "checking",
    )  # fmt: skip


class P1(Params):
    n: int


def test_params_are_strict_frozen_and_closed() -> None:
    with pytest.raises(pydantic.ValidationError):
        P1(n="1")  # type: ignore[arg-type]
    with pytest.raises(pydantic.ValidationError):
        P1(n=1, extra=2)  # type: ignore[call-arg]
    params = P1(n=1)
    with pytest.raises(pydantic.ValidationError):
        params.n = 2  # type: ignore[misc]


def test_spec_defaults_and_frozen_dataclasses() -> None:
    spec = Spec("t", 1, Endpoint.INFO, Family.CLUSTER, CostClass.PROBE)
    assert (spec.max_size, spec.allow_pit, spec.whole_documents) == (0, False, False)
    assert spec.url_params == frozenset({"filter_path"})
    assert spec.filter_fields == spec.return_fields == spec.sort_fields == frozenset()
    window = Window("squid", T0, T0)
    plan = RequestPlan(spec)
    for frozen, field in ((spec, "name"), (window, "source"), (plan, "body")):
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(frozen, field, None)


class Bare(Template):
    name = "test.bare"
    version = 1
    endpoint = Endpoint.INFO
    family = Family.CLUSTER
    cost = CostClass.PROBE


def test_template_defaults() -> None:
    spec = Bare.spec()
    assert (spec.max_size, spec.allow_pit, spec.whole_documents) == (0, False, False)
    assert Bare.timeout == timedelta(seconds=10)
    assert Bare().plan(NoParams()) == RequestPlan(spec)
    with pytest.raises(TypeError, match=r"test.bare takes NoParams"):
        Bare().plan(P1(n=1))
    assert Bare.opaque_id("collector") == "argus-collector/test.bare@1"


def test_register() -> None:
    name = "test.register"
    REGISTRY.pop(name, None)
    one: Any = type("One", (Bare,), {"name": name})
    assert register(one) is one
    assert REGISTRY[name] is one
    assert register(one) is one  # the same class again is fine
    two: Any = type("Two", (Bare,), {"name": name})
    with pytest.raises(ValueError, match=r"registered twice"):
        register(two)
    REGISTRY.pop(name)
    for version in (0, -1, "1", 1.0):
        bad: Any = type("Bad", (Bare,), {"name": "test.bad", "version": version})
        with pytest.raises(ValueError, match=r"positive integer version"):
            register(bad)
    assert "test.bad" not in REGISTRY


# --------------------------------------------------------------------------- indices


def test_pad_only_after_is_empty_for_a_window_ending_before_23() -> None:
    assert pad_only_after(P, T0) == frozenset()
    assert pad_only_after(P, T0.replace(hour=22, minute=59)) == frozenset()
    assert pad_only_after(P, T0.replace(hour=23)) == {P + "2026.10.10"}


def test_only_a_missing_optional_day_after_today_is_dropped() -> None:
    today, tomorrow = P + "2026.10.09", P + "2026.10.10"
    wanted = (today, tomorrow)
    assert resolve(wanted, {today}, date(2026, 10, 9), {tomorrow}) == (today,)
    with pytest.raises(SourceMissingError):  # not optional
        resolve(wanted, {today}, date(2026, 10, 9))
    with pytest.raises(SourceMissingError):  # optional but today: it should exist
        resolve((today,), set(), date(2026, 10, 9), {today})


def test_window_errors_name_the_problem() -> None:
    from argus.gateway.indices import daily_indices

    with pytest.raises(ValueError, match=r"^times must be timezone-aware$"):
        daily_indices(P, datetime(2026, 10, 9), T0)  # noqa: DTZ001
    with pytest.raises(ValueError, match=r"^the window ends before it starts$"):
        daily_indices(P, T0, T0 - timedelta(seconds=1))


# --------------------------------------------------------------------------- breaker


def test_breaker_state_is_frozen() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        br.BreakerState().level = 1  # type: ignore[misc]


def test_a_success_exactly_at_the_end_of_the_cooldown_closes() -> None:
    state = br.on_overload(br.BreakerState(), T0)
    end = T0 + timedelta(minutes=5)
    assert br.on_success(state, end - timedelta(microseconds=1)) == state
    assert br.on_success(state, end).open_until is None
