"""Q-F3: nothing goes to a model from here, but a wave dossier is what the decision engine and
the AI investigator read next, so it is rendered through the privacy layer like any dossier:
allowed, no internal address, and different from the dossier before the wave (it is assessed
again)."""

from __future__ import annotations

from typing import Any

import pytest

from argus.assess.runner import view_hash
from argus.context.generic import GenericPack
from argus.context.packs import WavePack
from argus.llm.privacy import Privacy
from tests.unit.investigation.kit import C2, HOST, body, step
from tests.unit.investigation.test_pack import FIVE, beats, pair_ref
from tests.unit.llm.conftest import privacy  # noqa: F401

pytestmark = pytest.mark.unit


def wave_body() -> dict[str, Any]:
    base = body(steps=[step(2, "deferred", ["timeline"])])
    pack = WavePack(GenericPack(), 1)
    ref = pair_ref()
    evidence, snaps = {ref["task_key"]: ref}, {ref["task_key"]: beats(FIVE)}
    context = {"facts": base["facts"], "context": base["context"]}
    signals = pack.signals(context["facts"], context["context"], evidence, snaps)
    derived = [s.as_dict() for s in signals]
    return {
        **base,
        "pack": pack.ident,
        "signals": derived,
        "report": pack.report(context["facts"], context["context"], evidence, derived),
        "evidence": [dict(ref)],
        "wave": {"round": 1, "of": "generic@12", "from": "a" * 64, "asked": [ref["task_key"]]},
    }


def test_a_wave_dossier_renders_without_an_internal_address(privacy: Privacy) -> None:  # noqa: F811
    wave = wave_body()
    request = privacy.request([wave])
    assert not request.failed
    assert request.items
    assert request.validate().allowed
    shown = request.text
    assert HOST not in shown  # the campus host is a pseudonym
    assert "every 5 minutes" in shown or "5 minutes" in shown  # the finding itself is told
    assert C2 in shown or "I1." in shown  # an outside address may stay; nothing internal does


def test_the_wave_dossier_is_a_different_view_from_the_one_before(privacy: Privacy) -> None:  # noqa: F811
    before = body(steps=[step(2, "deferred", ["timeline"])])
    assert view_hash(privacy, wave_body()) != view_hash(privacy, before)
    assert view_hash(privacy, wave_body()) == view_hash(privacy, wave_body())
