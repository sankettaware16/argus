"""Q-F3: a damaged stored body never breaks the ranking or the plan (it ranks what it can read,
and what it cannot is a gap nobody asks about), and a request is never built from nonsense."""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from argus.investigation import catalogue, gaps
from argus.investigation.gaps import Assessed, Profile
from argus.investigation.plan import Caps, candidates, choose
from tests.unit.investigation.kit import ALL_ON, NOW, SQUID, body, step, unknown

pytestmark = pytest.mark.unit

scalars = (
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(max_size=20)
)
anything = st.recursive(
    scalars,
    lambda inner: (
        st.lists(inner, max_size=4) | st.dictionaries(st.text(max_size=8), inner, max_size=4)
    ),
    max_leaves=12,
)
PARTS = ("local_signals", "signals", "report", "evidence", "facts", "context")


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    damage=st.dictionaries(st.sampled_from(PARTS), anything, max_size=4),
    pack=st.dictionaries(
        st.sampled_from(["fields", "ips", "ti", "indices", "steps", "earlier_logs"]),
        anything,
        max_size=3,
    ),
    assessed=st.sampled_from(
        [None, Assessed("true_positive", 0.9), Assessed("benign_expected", 0.1)]
    ),
)
def test_nothing_reads_a_damaged_body_into_a_crash(
    damage: dict[str, Any], pack: dict[str, Any], assessed: Assessed | None
) -> None:  # fmt: skip
    dossier = body([unknown("ti.listed", "timeout")], [step(1, "deferred", ["timeline"])])
    dossier.update(damage)
    ctx = dossier["context"]
    if isinstance(ctx, dict) and isinstance(ctx.get("pack"), dict):
        ctx["pack"].update(pack)
    found = gaps.find(dossier, Profile("threshold", SQUID), assessed)
    assert [g.rank for g in found] == list(range(1, len(found) + 1))
    facts = dossier.get("facts") if isinstance(dossier.get("facts"), dict) else {}
    context = ctx.get("pack") if isinstance(ctx, dict) and isinstance(ctx.get("pack"), dict) else {}
    mat = catalogue.Material(facts, context, NOW, "threshold", None)
    cands = candidates(found, mat, ALL_ON)
    plan = choose(found, cands, {}, {}, Caps(), NOW)
    assert len(plan.sends) <= Caps().requests
