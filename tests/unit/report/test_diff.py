"""Q-F2's gate: "what's new" is a pure diff. ``diff(x, x)`` is empty, the order of the inputs
never matters, and every change it lists is real (in the second view and not the same in the
first)."""

from __future__ import annotations

import random

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.report.diff import GONE, View, diff, eid_order, view
from argus.report.model import Check, Fact, Gap, WhatsNew

pytestmark = pytest.mark.unit

KEYS = st.sampled_from([f"signal:s{n}" for n in range(4)] + [f"step:{n}" for n in range(3)]
                       + [f"obs:E{n}:x" for n in range(3)] + ["alert:severity"])  # fmt: skip
EIDS = st.lists(st.sampled_from(["E1", "E2", "E3", "E10"]), max_size=3, unique=True).map(
    lambda e: tuple(sorted(e, key=eid_order))
)


def _fact(key: str, status: str, sentence: str, eids: tuple[str, ...], logs: bool) -> Fact:
    kind = {"signal": "signal", "step": "step", "obs": "observation", "alert": "alert"}[
        key.split(":", 1)[0]
    ]
    return Fact(key=key, kind=kind, name=key, sentence=sentence, status=status,  # type: ignore[arg-type]
                eids=eids, from_logs=logs)  # fmt: skip


FACTS = st.builds(_fact, KEYS, st.sampled_from(["known", "unknown"]),
                  st.sampled_from(["a", "b", "c"]), EIDS, st.booleans())  # fmt: skip
CHECKS = st.builds(
    lambda e, outcome, why: Check(eid=e, template="t@1", origin="pack", outcome=outcome,
                                  sentence=f"{e} {outcome}", why=why, from_logs=False, line=e),
    st.sampled_from(["E1", "E2", "E3", "E10"]),
    st.sampled_from(["found", "nothing_found", "could_not_tell", "failed", "not_run"]),
    st.sampled_from([None, "w"]),
)  # fmt: skip
GAPS = st.builds(lambda k, why: Gap(key=k, what=k, why=why, who="a person"),
                 KEYS, st.sampled_from(["x", "y"]))  # fmt: skip


def _unique(items: list, attr: str) -> list:  # type: ignore[type-arg]
    seen: dict[str, object] = {}
    for item in items:
        seen.setdefault(getattr(item, attr), item)
    return list(seen.values())


VIEWS = st.builds(
    lambda f, c, g: (_unique(f, "key"), _unique(c, "eid"), _unique(g, "key")),
    st.lists(FACTS, max_size=8), st.lists(CHECKS, max_size=4), st.lists(GAPS, max_size=4),
)  # fmt: skip


def _view(parts: tuple[list, list, list], seed: int = 0) -> View:  # type: ignore[type-arg]
    facts, checks, gaps = (list(p) for p in parts)
    rng = random.Random(seed)
    for p in (facts, checks, gaps):
        rng.shuffle(p)
    return view(facts, checks, gaps)


@given(VIEWS, st.integers(0, 1000))
def test_a_view_against_itself_is_empty(parts: tuple[list, list, list], seed: int) -> None:  # type: ignore[type-arg]
    assert diff(_view(parts, seed), _view(parts, seed + 1)).empty()
    assert diff(_view(parts), _view(parts)) == WhatsNew()


@given(VIEWS, VIEWS, st.integers(0, 1000), st.integers(0, 1000))
def test_the_order_of_the_inputs_never_matters(
    a: tuple[list, list, list],
    b: tuple[list, list, list],
    s1: int,
    s2: int,  # type: ignore[type-arg]
) -> None:
    assert diff(_view(a, s1), _view(b, s2)) == diff(_view(a, s2), _view(b, s1))


@given(VIEWS, VIEWS)
def test_every_change_is_real(a: tuple[list, list, list], b: tuple[list, list, list]) -> None:  # type: ignore[type-arg]
    before, after = _view(a), _view(b)
    new = diff(before, after)
    for f in new.new_facts:
        assert f.key in after.facts
        assert f.key not in before.facts
        assert f.kind in ("observation", "alert")
    for c in new.now_known:
        assert after.facts[c.key].status == "known"
        assert c.key not in before.facts or before.facts[c.key].status != "known"
    for c in new.steps_answered:
        assert after.facts[c.key].status == "known"
        assert after.facts[c.key].kind == "step"
        assert before.facts.get(c.key) != after.facts[c.key]
    for c in new.changed:
        if c.after == GONE:
            assert c.key in before.facts
            assert c.key not in after.facts
        else:
            assert before.facts.get(c.key) not in (None, after.facts[c.key]) or (
                after.facts[c.key].kind == "step"
            )
    assert {g.key for g in new.gaps_closed} == set(before.gaps) - set(after.gaps)
    assert {g.key for g in new.gaps_opened} == set(after.gaps) - set(before.gaps)
    assert all(before.checks.get(c.eid) != c for c in new.checks)
    listed = [c.key for c in (*new.now_known, *new.changed, *new.steps_answered)]
    listed += [f.key for f in new.new_facts]
    assert len(listed) == len(set(listed))  # one change per key
    assert [c.eid for c in new.checks] == sorted((c.eid for c in new.checks), key=eid_order)


def test_the_kinds_of_change() -> None:
    known = Fact(key="signal:a", kind="signal", name="a", sentence="A: 3", status="known",
                 eids=("E2",))  # fmt: skip
    unknown = known.model_copy(update={"status": "unknown", "sentence": "A: could not tell."})
    step = Fact(key="step:1", kind="step", name="step 1", sentence="Step 1, answered: x",
                status="known", eids=("E1",))  # fmt: skip
    obs = Fact(key="obs:E1:x", kind="observation", name="x", sentence="seen", status="known",
               eids=("E1",), from_logs=True)  # fmt: skip
    gap = Gap(key="signal:a", what="A: could not tell.", why="w", who="a person")
    before = view([unknown, step.model_copy(update={"status": "unknown"})], [], [gap])
    after = view([known, step, obs])
    new = diff(before, after)
    assert [c.key for c in new.now_known] == ["signal:a"]
    assert (new.now_known[0].before, new.now_known[0].after) == ("A: could not tell.", "A: 3")
    assert [c.key for c in new.steps_answered] == ["step:1"]
    assert new.new_facts == (obs,)
    assert new.gaps_closed == (gap,)
    assert (new.changed, new.gaps_opened, new.checks) == ((), (), ())
    back = diff(after, before)
    assert [c.key for c in back.changed] == ["obs:E1:x", "signal:a", "step:1"]
    assert back.changed[0].after == GONE
    assert back.gaps_opened == (gap,)
    assert back.changed[1].eids == ("E2",)
    assert back.changed[0].from_logs is True


def test_a_key_given_twice_is_refused() -> None:
    a = Fact(key="signal:a", kind="signal", name="a", sentence="x", status="known")
    assert view([a, a]).facts == {"signal:a": a}  # the same item twice is one
    with pytest.raises(ValueError, match="share the key 'signal:a'"):
        view([a, a.model_copy(update={"sentence": "y"})])


def test_eids_sort_by_number() -> None:
    assert sorted(["E10", "E2", "E1", "Ex"], key=eid_order) == ["E1", "E2", "E10", "Ex"]
