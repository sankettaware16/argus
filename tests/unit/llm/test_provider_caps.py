"""Per-provider paid caps (P4-E2): each paid provider's own monthly and daily cost caps under the
overall ones, its spend in the shared state (settled, rolled over, stored as JSON), the
configuration's rules, and what ``argus llm status``, ``reconcile`` and the doctor show."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from argus.llm import budget
from argus.llm import doctor as llm_doctor
from argus.llm.budget import Ask, Caps, Config, Priority, State
from argus.llm.cli import reconciled_lines, spend_line
from argus.llm.providers import LlmConfig, pinned
from argus.llm.store import Reconciled

pytestmark = pytest.mark.unit
NOW = datetime(2026, 10, 16, 12, 0, 30, tzinfo=UTC)
CAPS = {"a": Caps(0.5, 0.2), "b": Caps(0.6, None), "c": Caps(None, 0.1)}
CONFIG = Config(monthly_cap_usd=1.0, margin=0.8, daily_cap_usd=0.3, caps=CAPS)
EPS = 1e-9  # settling adds and subtracts floats: a few ulps


def ask(provider: str = "a", cost: float = 0.1, priority: Priority = Priority.HIGH) -> Ask:
    return Ask(provider, "m", (), 10, cost, priority)


def admit(state: State, a: Ask, now: datetime = NOW, config: Config = CONFIG) -> State:
    admission, after = budget.admit(state, a, now, config)
    assert admission.ok, admission.why
    return after


# -- admission ---------------------------------------------------------------------------------


def test_a_providers_own_monthly_cap_holds_by_share_until_next_month() -> None:
    config = Config(monthly_cap_usd=10.0, caps={"openai": Caps(monthly_usd=1.0)})
    a = Ask("openai", "m", (), 10, 0.3, Priority.NORMAL)  # NORMAL: 0.8 of $1
    state = admit(admit(State(), a, config=config), a, config=config)
    refused, same = budget.admit(state, a, NOW, config)
    assert refused == budget.Admission(False, datetime(2026, 11, 1, tzinfo=UTC),
                                       "openai: monthly cost cap")  # fmt: skip
    assert same is state
    assert budget.spend(state, NOW, "openai") == pytest.approx((0.6, 0.6))
    assert budget.admit(state, replace(a, priority=Priority.HIGH), NOW, config)[0].ok
    assert budget.admit(state, a, datetime(2026, 11, 1, tzinfo=UTC), config)[0].ok


def test_a_providers_own_daily_cap_holds_until_the_next_day() -> None:
    config = Config(monthly_cap_usd=10.0, daily_cap_usd=5.0, caps={"openai": Caps(None, 0.5)})
    a = Ask("openai", "m", (), 10, 0.2, Priority.NORMAL)  # NORMAL: 0.8 of $0.50
    state = admit(admit(State(), a, config=config), a, config=config)
    refused, _ = budget.admit(state, a, NOW, config)
    assert refused == budget.Admission(False, datetime(2026, 10, 17, tzinfo=UTC),
                                       "openai: daily cost cap")  # fmt: skip
    assert budget.admit(state, a, datetime(2026, 10, 17, tzinfo=UTC), config)[0].ok


def test_a_call_dearer_than_a_providers_own_cap_never_goes_there() -> None:
    for caps, period in ((Caps(0.5, None), "monthly"), (Caps(None, 0.5), "daily")):
        config = Config(monthly_cap_usd=10.0, caps={"openai": caps})
        refused, _ = budget.admit(State(), Ask("openai", "m", (), 10, 0.41, Priority.NORMAL), NOW,
                                  config)  # fmt: skip
        assert refused == budget.Admission(False, None, f"openai: costs more than the {period} cap")
        exactly = Ask("openai", "m", (), 10, 0.4, Priority.NORMAL)
        assert budget.admit(State(), exactly, NOW, config)[0].ok
        other = Ask("anthropic", "m", (), 10, 0.41, Priority.NORMAL)
        assert budget.admit(State(), other, NOW, config)[0].ok


def test_one_providers_cap_leaves_the_other_and_the_overall_cap_holds_both() -> None:
    config = Config(monthly_cap_usd=2.0, caps={"openai": Caps(0.5), "anthropic": Caps(0.5)})
    state = State()
    for _ in range(4):
        state = admit(state, Ask("openai", "m", (), 10, 0.125, Priority.HIGH), config=config)
    one_more = Ask("openai", "m", (), 10, 0.125, Priority.HIGH)
    assert budget.admit(state, one_more, NOW, config)[0].why == "openai: monthly cost cap"
    for _ in range(3):
        state = admit(state, Ask("anthropic", "m", (), 10, 0.125, Priority.HIGH), config=config)
    assert budget.spend(state, NOW) == (0.875, 0.875)
    assert budget.spend(state, NOW, "anthropic") == (0.375, 0.375)
    dearer = Ask("anthropic", "m", (), 10, 0.25, Priority.HIGH)  # its own cap only
    assert budget.admit(state, dearer, NOW, config)[0].why == "anthropic: monthly cost cap"
    both = Config(monthly_cap_usd=1.0, caps=config.caps)
    assert budget.admit(state, dearer, NOW, both)[0].why == (
        "monthly cost cap; anthropic: monthly cost cap"
    )
    overall = Config(monthly_cap_usd=0.9, caps=config.caps)  # under its own, not the overall
    last = Ask("anthropic", "m", (), 10, 0.125, Priority.HIGH)
    assert budget.admit(state, last, NOW, overall)[0].why == "monthly cost cap"


def test_every_cap_that_is_full_is_named_and_the_latest_wait_wins() -> None:
    state = State(month="2026-10", spent_usd=0.95, day="2026-10-16", day_spent_usd=0.25,
                  provider_spent_usd={"a": 0.45}, provider_day_spent_usd={"a": 0.15})  # fmt: skip
    refused, _ = budget.admit(state, ask("a", 0.1), NOW, CONFIG)
    assert refused.why == ("monthly cost cap; daily cost cap; a: monthly cost cap;"
                           " a: daily cost cap")  # fmt: skip
    assert refused.until == datetime(2026, 11, 1, tzinfo=UTC)


def test_free_calls_ignore_every_cost_cap_and_leave_no_spend() -> None:
    full = State(month="2026-10", spent_usd=9.0, day="2026-10-16", day_spent_usd=9.0,
                 provider_spent_usd={"a": 9.0}, provider_day_spent_usd={"a": 9.0})  # fmt: skip
    after = admit(full, ask("a", 0.0))
    assert after.provider_spent_usd == {"a": 9.0}
    assert admit(State(), ask("free", 0.0)).provider_spent_usd == {}
    settled = budget.settle(admit(State(), ask("free", 0.0)), ask("free", 0.0), NOW, 5, 0.0)
    assert (settled.provider_spent_usd, settled.provider_day_spent_usd) == ({}, {})


def test_a_provider_without_caps_of_its_own_is_counted_but_held_only_by_the_overall_cap() -> None:
    state = State()
    for _ in range(2):
        state = admit(state, ask("d", 0.125))
    assert budget.spend(state, NOW, "d") == (0.25, 0.25)
    assert budget.admit(state, ask("d", 0.125), NOW, CONFIG)[0].why == "daily cost cap"


# -- settling and rollover -------------------------------------------------------------------


def test_settling_corrects_the_providers_spend_like_the_overall_one() -> None:
    a = ask("a", 0.1)
    state = budget.settle(admit(State(), a), a, NOW, 10, 0.04)
    assert budget.spend(state, NOW, "a") == pytest.approx((0.04, 0.04))
    assert budget.spend(state, NOW) == pytest.approx((0.04, 0.04))
    nothing = budget.settle(admit(State(), a), a, NOW, 0, 0.0)  # never reached the provider
    assert budget.spend(nothing, NOW, "a") == (0.0, 0.0)


def test_settling_another_days_or_months_call_moves_neither() -> None:
    a = ask("a", 0.1)
    state = admit(State(), a)
    tomorrow = NOW + timedelta(days=1)
    later = admit(state, a, tomorrow)
    settled = budget.settle(later, a, NOW, 10, 0.0)  # yesterday's reservation
    assert settled.provider_day_spent_usd == later.provider_day_spent_usd == {"a": 0.1}
    assert settled.provider_spent_usd == pytest.approx({"a": 0.1})  # still October: corrected
    november = admit(state, a, datetime(2026, 11, 1, tzinfo=UTC))
    moved = budget.settle(november, a, NOW, 10, 0.0)
    assert moved.provider_spent_usd == november.provider_spent_usd == {"a": 0.1}


def test_a_dearer_settlement_never_goes_negative_nor_skips_the_cap() -> None:
    a = ask("a", 0.1)
    state = budget.settle(admit(State(), a), a, NOW, 10, 0.55)  # more than reserved
    assert budget.spend(state, NOW, "a") == pytest.approx((0.55, 0.55))
    refused, _ = budget.admit(state, ask("a", 0.001), NOW, CONFIG)
    assert "a: monthly cost cap" in refused.why
    assert "a: daily cost cap" in refused.why
    zero = budget.settle(State(month="2026-10", day="2026-10-16"), a, NOW, 0, 0.0)
    assert zero.provider_spent_usd == {"a": 0.0}
    assert zero.provider_day_spent_usd == {"a": 0.0}


def test_the_day_resets_a_providers_day_and_the_month_both() -> None:
    a = ask("a", 0.1)
    state = admit(admit(State(), a), ask("b", 0.1))
    tomorrow = NOW + timedelta(days=1)
    assert budget.spend(state, tomorrow, "a") == pytest.approx((0.1, 0.0))
    next_day = admit(state, ask("b", 0.0), tomorrow)  # a free call rolls the day too
    assert next_day.provider_day_spent_usd == {}
    assert next_day.provider_spent_usd == {"a": 0.1, "b": 0.1}
    november = datetime(2026, 11, 1, tzinfo=UTC)
    assert budget.spend(state, november, "a") == (0.0, 0.0)
    rolled = admit(state, ask("b", 0.2), november)
    assert rolled.provider_spent_usd == {"b": 0.2}
    assert rolled.provider_day_spent_usd == {"b": 0.2}
    assert (rolled.month, rolled.spent_usd) == ("2026-11", 0.2)


def test_spend_reads_zero_for_another_month_or_day() -> None:
    state = State(month="2026-10", spent_usd=1.0, day="2026-10-15", day_spent_usd=0.5,
                  provider_spent_usd={"a": 0.7}, provider_day_spent_usd={"a": 0.2})  # fmt: skip
    assert budget.spend(state, NOW) == (1.0, 0.0)
    assert budget.spend(state, NOW, "a") == (0.7, 0.0)
    assert budget.spend(state, NOW, "b") == (0.0, 0.0)
    assert budget.spend(state, NOW - timedelta(days=1), "a") == (0.7, 0.2)


# -- the shared state as JSON ----------------------------------------------------------------


def test_a_state_stored_before_provider_caps_reads_as_no_spend() -> None:
    old = budget.to_json(State(month="2026-10", spent_usd=1.5))
    for key in ("provider_spent_usd", "provider_day_spent_usd"):
        del old[key]
    state = budget.from_json(old)
    assert state == State(month="2026-10", spent_usd=1.5)
    assert budget.spend(state, NOW, "openai") == (0.0, 0.0)
    nulls = {**old, "provider_spent_usd": None, "provider_day_spent_usd": None}
    assert budget.from_json(nulls) == state


spends = st.dictionaries(st.sampled_from(["openai", "anthropic", "a"]),
                         st.floats(0, 100, allow_nan=False, allow_infinity=False))  # fmt: skip


@given(spends, spends, st.floats(0, 100, allow_nan=False))
def test_the_providers_spend_round_trips_through_json(
    month: dict[str, float], day: dict[str, float], spent: float
) -> None:
    state = State(month="2026-10", spent_usd=spent, day="2026-10-16",
                  provider_spent_usd=month, provider_day_spent_usd=day)  # fmt: skip
    data = budget.to_json(state)
    assert budget.from_json(data) == state
    assert data["provider_spent_usd"] == month
    assert data["provider_spent_usd"] is not state.provider_spent_usd  # a copy, never shared


# -- properties ------------------------------------------------------------------------------

PROVIDERS = ["a", "b", "c", "d", "free"]  # a, b, c with their own caps; d with none; free
steps = st.lists(
    st.one_of(
        st.tuples(st.just("ask"), st.sampled_from(PROVIDERS),
                  st.floats(0.001, 0.4, allow_nan=False), st.sampled_from(list(Priority))),
        st.tuples(st.just("settle"), st.integers(0, 50), st.floats(0, 1, allow_nan=False)),
        st.tuples(st.just("step"), st.sampled_from([1, 59, 3600, 6 * 3600, 86_400, 20 * 86_400]),
                  st.just(0.0)),
    ),
    max_size=40,
)  # fmt: skip


def _held(state: State, now: datetime, config: Config) -> None:
    month, day = budget.spend(state, now)
    assert 0.0 <= month <= config.monthly_cap_usd + EPS
    assert config.daily_cap_usd is not None
    assert 0.0 <= day <= config.daily_cap_usd + EPS
    own_month = own_day = 0.0
    for p in PROVIDERS:
        m, d = budget.spend(state, now, p)
        assert m >= 0.0
        assert d >= 0.0
        caps = config.caps.get(p, Caps())
        assert caps.monthly_usd is None or m <= caps.monthly_usd + EPS
        assert caps.daily_usd is None or d <= caps.daily_usd + EPS
        own_month, own_day = own_month + m, own_day + d
    # every paid ask counts once overall and once at its provider
    assert own_month == pytest.approx(month, abs=EPS)
    assert own_day == pytest.approx(day, abs=EPS)


@given(steps)
def test_no_provider_and_no_overall_cap_is_ever_passed(
    plan: list[tuple[Any, ...]],
) -> None:
    state, now = State(), NOW
    pending: list[tuple[Ask, datetime]] = []
    for kind, x, y, *rest in plan:
        if kind == "ask":
            a = ask(x, 0.0 if x == "free" else y, rest[0])
            before = budget.spend(state, now, x)
            admission, after = budget.admit(state, a, now, CONFIG)
            share, caps = CONFIG.shares[a.priority], CONFIG.caps.get(x, Caps())
            if admission.ok:
                pending.append((a, now))
                m, d = budget.spend(after, now, x)
                assert m == pytest.approx(before[0] + a.cost_usd)
                assert caps.monthly_usd is None or m <= caps.monthly_usd * share + EPS
                assert caps.daily_usd is None or d <= caps.daily_usd * share + EPS
            else:
                assert after is state
                assert a.cost_usd > 0  # nothing else here refuses: no limits, no breakers
                never = "costs more than" in admission.why  # checked first: nothing else named
                assert (admission.until is None) == never
                for limit, used, period in ((caps.monthly_usd, before[0], "monthly"),
                                            (caps.daily_usd, before[1], "daily")):  # fmt: skip
                    named = f"{x}: {period} cost cap" in admission.why
                    if limit is None:
                        assert not named
                        continue
                    cap = limit * share
                    assert named == (not never and a.cost_usd <= cap < used + a.cost_usd)
            state = after
        elif kind == "settle" and pending:
            a, at = pending.pop(x % len(pending))
            state = budget.settle(state, a, at, 0, a.cost_usd * y)  # never above the reservation
        elif kind == "step":
            now += timedelta(seconds=x)
        _held(state, now, CONFIG)


@given(st.floats(0.01, 0.1), st.floats(1.0, 20.0), st.sampled_from(["a", "b", "c", "d"]),
       st.floats(0.0001, 0.2))  # fmt: skip
def test_a_dearer_settlement_is_never_negative_and_closes_the_cap_until_it_rolls(
    cost: float, factor: float, provider: str, then: float
) -> None:
    a = ask(provider, cost)
    state = admit(State(), a)
    settled = budget.settle(state, a, NOW, 10, cost * factor)
    month, day = budget.spend(settled, NOW, provider)
    assert month == pytest.approx(cost * factor) == day
    caps = CONFIG.caps.get(provider, Caps())
    refused, _ = budget.admit(settled, ask(provider, then), NOW, CONFIG)
    for limit, used, period in ((caps.monthly_usd, month, "monthly"),
                                (caps.daily_usd, day, "daily")):  # fmt: skip
        if limit is not None and then <= limit and used + then > limit:
            assert not refused.ok
            assert f"{provider}: {period} cost cap" in refused.why
    for limit, used in ((CONFIG.monthly_cap_usd, month), (CONFIG.daily_cap_usd, day)):
        if limit is not None and used + then > limit:
            assert not refused.ok
    november = datetime(2026, 11, 1, tzinfo=UTC)
    assert budget.spend(settled, november, provider) == (0.0, 0.0)
    if then <= 0.1:  # under every cap of its own once the month rolls
        assert budget.admit(settled, ask(provider, then), november, CONFIG)[0].ok
    cheaper = budget.settle(state, a, NOW, 10, 0.0)
    assert budget.spend(cheaper, NOW, provider) == (0.0, 0.0)


# -- configuration ---------------------------------------------------------------------------


def paid(**over: Any) -> dict[str, Any]:
    return {"name": "openai", "base_url": "https://paid.example/v1", "keys": ["PAID_KEY"],
            "models": {"small": {"name": "p", "input_per_m": 1.0, "output_per_m": 2.0}},
            **over}  # fmt: skip


def free(**over: Any) -> dict[str, Any]:
    return {"name": "groq", "base_url": "https://free.example/v1", "keys": ["FREE_KEY"],
            "models": {"small": {"name": "f"}}, **over}  # fmt: skip


def llm(*providers: dict[str, Any], **over: Any) -> LlmConfig:
    return LlmConfig.model_validate({"monthly_cap_usd": 80.0, "daily_cap_usd": 3.0,
                                     "providers": list(providers), **over})  # fmt: skip


def test_the_provider_caps_reach_the_budget() -> None:
    cfg = llm(free(), paid(monthly_cap_usd=40, daily_cap_usd=1.5),
              paid(name="anthropic", monthly_cap_usd=40))  # fmt: skip
    got = cfg.budget_config()
    assert got.caps == {"openai": Caps(40.0, 1.5), "anthropic": Caps(40.0, None)}
    assert (got.monthly_cap_usd, got.daily_cap_usd) == (80.0, 3.0)
    assert llm(paid()).budget_config().caps == {}
    assert pinned(cfg, "openai").budget_config().caps == {"openai": Caps(40.0, 1.5)}
    assert Config().caps == {}


@pytest.mark.parametrize(
    ("over", "message"),
    [
        ({"monthly_cap_usd": 80.01}, "openai: monthly_cap_usd is above the overall"),
        ({"daily_cap_usd": 3.5}, "openai: daily_cap_usd is above the overall"),
        ({"monthly_cap_usd": -1}, "greater than or equal to 0"),
        ({"daily_cap_usd": -0.5}, "greater than or equal to 0"),
    ],
)
def test_a_providers_cap_is_never_above_the_overall_one(over: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        llm(paid(**over))


def test_caps_at_the_overall_ones_or_without_an_overall_daily_cap_are_fine() -> None:
    assert llm(paid(monthly_cap_usd=80, daily_cap_usd=3)).providers[0].daily_cap_usd == 3
    alone = llm(paid(daily_cap_usd=9), daily_cap_usd=None).providers[0]
    assert alone.caps() == Caps(None, 9.0)
    assert llm(paid(monthly_cap_usd=0)).budget_config().caps == {"openai": Caps(0.0, None)}


def test_a_cap_on_a_provider_with_an_unpriced_model_is_refused() -> None:
    # an unpriced model is reserved at $0: its provider's cap would never hold it
    for over in ({"monthly_cap_usd": 10}, {"daily_cap_usd": 1}):
        with pytest.raises(ValidationError, match="needs every model's price"):
            llm(free(**over))
        mixed = paid(models={"small": {"name": "p", "input_per_m": 1.0},
                             "medium": {"name": "q"}}, **over)  # fmt: skip
        with pytest.raises(ValidationError, match="needs every model's price"):
            llm(mixed)
    out_only = paid(models={"small": {"name": "p", "output_per_m": 1.0}}, monthly_cap_usd=1)
    assert llm(out_only).providers[0].paid


def test_paid_means_some_model_has_a_price() -> None:
    cfg = llm(free(), paid())
    assert [p.paid for p in cfg.providers] == [False, True]


# -- what the commands show ------------------------------------------------------------------


def test_status_shows_each_paid_providers_spend_against_its_caps() -> None:
    cfg = llm(free(), paid(monthly_cap_usd=40, daily_cap_usd=1.5), paid(name="anthropic"))
    groq, openai, anthropic = cfg.providers
    state = State(month="2026-10", day="2026-10-16", provider_spent_usd={"openai": 12.3456789},
                  provider_day_spent_usd={"openai": 0.25})  # fmt: skip
    assert spend_line(groq, state, NOW) is None
    assert spend_line(openai, state, NOW) == (
        "    spend: this month $12.345679 of $40.00, today $0.250000 of $1.50"
    )
    assert spend_line(anthropic, state, NOW) == (
        "    spend: this month $0.000000 (the overall cap only),"
        " today $0.000000 (the overall cap only)"
    )
    november = datetime(2026, 11, 1, tzinfo=UTC)
    assert spend_line(openai, state, november) == (
        "    spend: this month $0.000000 of $40.00, today $0.000000 of $1.50"
    )


def test_reconcile_shows_the_overall_and_each_providers_month() -> None:
    done = Reconciled(7.5, 0.875, {"anthropic": (0.0, 0.125), "openai": (7.5, 0.75)})
    assert reconciled_lines(done) == [
        "this month's spend: $7.500000 -> $0.875000 (the ledger's settled costs)",
        "  anthropic: $0.000000 -> $0.125000",
        "  openai: $7.500000 -> $0.750000",
    ]
    assert reconciled_lines(Reconciled(0.0, 0.0, {})) == [
        "this month's spend: $0.000000 -> $0.000000 (the ledger's settled costs)"
    ]


def test_the_doctor_names_a_providers_own_caps() -> None:
    cfg = llm(free(), paid(monthly_cap_usd=40, daily_cap_usd=1.5),
              paid(name="anthropic", monthly_cap_usd=40, enabled=False))  # fmt: skip
    found = llm_doctor.providers_check(cfg, {"PAID_KEY"})
    assert found.detail == ("groq (on, no key), openai (on, key, $40.00 a month, $1.50 a day),"
                            " anthropic (disabled, key, $40.00 a month)")  # fmt: skip
