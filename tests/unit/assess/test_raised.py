"""AR2b (D-160, D-164): an investigation whose evidence carries a threat-list hit and another
generic flag is raised into Needs attention; one flag alone is only a flag. The flags are the gold
set's (generic signals, never a rule's name); the words are plain; garbage in a stored row is
never a reason."""

from __future__ import annotations

from typing import Any

from hypothesis import given
from hypothesis import strategies as st

from argus.assess import raised
from argus.evaluation import gold

BEACON = {"name": "proxy.regularity", "status": "known", "value": 0.08}
LISTED = {"name": "ti.listed", "status": "known", "value": 1}
REMOTE = {"name": "ti.listed_remote", "status": "known", "value": 3}
SUCCESS = {"name": "web.successes_after", "status": "known", "value": 12}
PORTS = {"name": "ports.risky", "status": "known", "value": 2}


def test_each_strong_flag_raises_with_its_plain_words() -> None:
    assert raised.flags_of([LISTED], []) == ("on a threat list",)
    assert raised.flags_of([], [REMOTE]) == ("on a threat list",)
    assert raised.flags_of([SUCCESS], None) == ("successful answers after the alert",)
    assert raised.flags_of(None, [BEACON]) == ("regular traffic, like a beacon",)
    assert raised.flags_of([PORTS], []) == ("remote-admin, P2P or anonymizer ports",)


def test_the_amadey_shape_is_raised_as_a_beacon() -> None:
    low = {"name": "proxy.regularity", "status": "known", "value": 0.0}  # proxy regularity 0.0
    assert raised.flags_of([low], []) == ("regular traffic, like a beacon",)
    assert raised.words(raised.flags_of([low], [])) == (
        "ARGUS raised it: regular traffic, like a beacon"
    )  # fmt: skip


def test_nothing_known_or_nothing_above_the_line_raises_nothing() -> None:
    quiet = [
        {"name": "proxy.regularity", "status": "known", "value": 0.9},
        {"name": "proxy.regularity", "status": "unknown", "value": 0.0},
        {"name": "ti.listed", "status": "known", "value": 0},
        {"name": "ports.risky", "status": "missing", "value": 4},
        {"name": "web.successes_after", "status": "known", "value": True},  # a bool is no count
    ]
    assert raised.flags_of(quiet, quiet) == ()
    assert raised.flags_of(None, None) == ()
    assert raised.flags_of("x", {"a": 1}) == ()  # a stored row of the wrong shape


def test_several_flags_are_all_said() -> None:
    both = raised.flags_of([BEACON, LISTED], [PORTS])
    assert both == ("on a threat list", "regular traffic, like a beacon",
                    "remote-admin, P2P or anonymizer ports")  # fmt: skip
    assert raised.words(both) == (
        "ARGUS raised it: on a threat list; regular traffic, like a beacon;"
        " remote-admin, P2P or anonymizer ports"
    )  # fmt: skip


def test_the_reason_of_a_stored_row() -> None:
    both = ["on a threat list", "regular traffic, like a beacon"]
    assert raised.reason(both) == (
        "ARGUS raised it: on a threat list; regular traffic, like a beacon"
    )  # fmt: skip
    assert raised.reason([]) is None
    assert raised.reason(None) is None
    assert raised.reason("regular traffic") is None
    assert raised.reason([3, None, "", "on a threat list", "x"]) == (
        "ARGUS raised it: on a threat list; x"
    )  # fmt: skip


def test_one_flag_alone_or_flags_without_a_threat_list_hit_raise_nothing() -> None:
    # replayed on 21 to 27 Oct: the beacon flag alone came on 302 investigations a day (D-164)
    assert raised.reason(["regular traffic, like a beacon"]) is None
    assert raised.reason(["on a threat list"]) is None
    assert raised.reason(["on a threat list", "on a threat list"]) is None
    assert raised.reason(["regular traffic, like a beacon",
                          "remote-admin, P2P or anonymizer ports"]) is None  # fmt: skip


signal = st.fixed_dictionaries(
    {
        "name": st.sampled_from(["ti.listed", "ti.listed_remote", "web.successes_after",
                                 "proxy.regularity", "ports.risky", "other"]),
        "status": st.sampled_from(["known", "unknown", "missing"]),
        "value": st.one_of(st.none(), st.booleans(), st.integers(-3, 9), st.floats(-1, 2),
                           st.text(max_size=4)),
    }
)  # fmt: skip


@given(st.lists(signal, max_size=8), st.lists(signal, max_size=8))
def test_the_flags_are_the_gold_sets_whatever_the_signals(
    local: list[dict[str, Any]], remote: list[dict[str, Any]]
) -> None:
    found = raised.flags_of(local, remote)
    assert found == gold.flags({"local_signals": local, "signals": remote})
    assert len(found) == len(set(found))  # each at most once
    assert raised.reason(list(found)) == (raised.words(found) if raised.raises(found) else None)


@given(
    st.recursive(
        st.none() | st.booleans() | st.integers() | st.text(max_size=5),
        lambda inner: (
            st.lists(inner, max_size=3) | st.dictionaries(st.text(max_size=3), inner, max_size=3)
        ),
        max_leaves=8,
    )
)
def test_a_row_of_any_shape_never_breaks_the_reason(stored: Any) -> None:
    said = raised.reason(stored)
    assert said is None or said.startswith(raised.PREFIX)
