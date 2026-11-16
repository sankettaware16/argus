"""A task's own settings in config/llm.yaml (``purposes``, D-324): its daily cap of attempts holds
over every provider and is counted per UTC day; its provider list is the only one it goes to, in
that order; a task with no entry goes everywhere as before; a purpose naming an unknown task or
provider is refused when the configuration loads."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from argus.llm.gateway import Call, NoCapacity, Refused
from argus.llm.privacy import Privacy
from argus.llm.providers import DEFAULT_PATH, Tier, load_config, order_for
from argus.llm.wire import LlmReply
from tests.unit.llm.test_gateway import Fake, config, make
from tests.unit.llm.test_privacy import dossier

pytestmark = pytest.mark.unit


def story(privacy: Privacy) -> Call:
    return Call(privacy.request([dossier()]), "Tell the story. Answer in JSON.", "story")


async def test_a_purposes_daily_cap_holds_over_every_provider(privacy: Privacy) -> None:
    cfg = config(purposes={"story": {"calls_per_day": 2}})
    gw, fake, _, clock = make(cfg=cfg)
    call = story(privacy)
    await gw.complete(call)
    await gw.complete(replace(call, avoid=frozenset({"paid"})))  # the free provider: one window
    with pytest.raises(NoCapacity, match="purpose:story: day limit") as caught:
        await gw.complete(call)
    assert caught.value.until == (clock.now + timedelta(days=1)).replace(hour=0, minute=0)
    assert len(fake.sent) == 2
    await gw.complete(Call(call.request, call.instructions, "assess"))  # another task: no cap
    clock.now += timedelta(days=1)
    await gw.complete(call)  # a new UTC day
    assert len(fake.sent) == 4


async def test_a_failed_attempt_counts_against_the_cap(privacy: Privacy) -> None:
    cfg = config(purposes={"story": {"calls_per_day": 1}})
    fake = Fake({"paid": [LlmReply(500, b"{}", 10.0)]})
    gw, fake, _, _ = make(fake, cfg)
    with pytest.raises((NoCapacity, Refused)):
        await gw.complete(story(privacy))  # the paid one fails; the free one is over the cap
    assert [w.provider for w, _ in fake.sent] == ["paid"]


async def test_a_purpose_goes_only_to_its_providers_in_its_order(privacy: Privacy) -> None:
    cfg = config(purposes={"story": {"providers": ["free", "paid"]},
                           "opinion": {"providers": ["paid"]}})  # fmt: skip
    gw, _fake, _, _ = make(cfg=cfg)
    done = await gw.complete(story(privacy))
    assert done.provider == "free"
    opinion = replace(story(privacy), purpose="opinion")
    gw2, fake2, _, _ = make(Fake({"paid": [LlmReply(500, b"{}", 10.0)]}), cfg)
    with pytest.raises((NoCapacity, Refused)):
        await gw2.complete(opinion)
    assert {w.provider for w, _ in fake2.sent} == {"paid"}  # never the free one
    assumed = await make(cfg=cfg)[0].complete(Call(opinion.request, "x", "assess"))
    assert assumed.provider == "paid"  # no entry: the configured order


async def test_a_cap_of_zero_switches_the_task_off(privacy: Privacy) -> None:
    gw, fake, _, _ = make(cfg=config(purposes={"story": {"calls_per_day": 0}}))
    with pytest.raises(NoCapacity):
        await gw.complete(story(privacy))
    assert fake.sent == []


@pytest.mark.parametrize(
    ("purposes", "why"),
    [
        ({"stories": {"calls_per_day": 1}}, "is not a task"),
        ({"story": {"providers": ["nowhere"]}}, "no provider nowhere"),
        ({"story": {"providers": ["paid", "paid"]}}, "named twice"),
        ({"story": {"calls_per_day": -1}}, "greater than or equal"),
        ({"story": {"providers": []}}, "at least 1"),
        ({"story": {"tier": "huge"}}, "small"),
        ({"story": {"cap": 1}}, "Extra inputs"),
    ],
)
def test_a_wrong_purpose_is_refused_on_load(purposes: dict[str, Any], why: str) -> None:
    with pytest.raises(ValidationError, match=why):
        config(purposes=purposes)


def test_the_repositorys_purposes() -> None:
    cfg = load_config(DEFAULT_PATH)
    assert cfg.purposes["story"].calls_per_day == 15
    assert cfg.purposes["story"].tier is Tier.MEDIUM
    assert cfg.purposes["opinion"].calls_per_day == 3
    assert cfg.purposes["opinion"].tier is Tier.LARGE
    assert [p.name for p in order_for(cfg, "story")] == ["openai", "anthropic"]
    assert [p.name for p in order_for(cfg, "assess")] == [p.name for p in cfg.providers]


def test_a_campus_provider_never_serves_a_reading() -> None:
    data = config().model_dump(mode="json")
    local = {
        "name": "local", "trust": "campus", "base_url": "https://127.0.0.1:18443/v1",
        "keys": ["LOCAL_KEY"], "ca_file": "data/tls/x.crt", "tasks": ["story"],
        "models": {"small": {"name": "m", "limits": {"rpd": 10}}},
    }  # fmt: skip
    with pytest.raises(ValidationError, match="never serves story"):
        config(providers=[*data["providers"], local])
