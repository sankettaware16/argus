"""The incident replay's report (E2): every incident opened on a known incident's objects is a
piece, merged later or not; the measures as they stood when people found it; and the
popularity list as the replay mode knew it. Made-up values only."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from argus.risk import incident_config
from argus.risk.incident_replay import Answers, IncidentReplay
from argus.risk.observe import ObjectRef, Observation
from argus.risk.replay import GroupMeta, Loaded
from argus.risk.replay import Incident as Known

from .conftest import NOW, obs

pytestmark = pytest.mark.unit
LINKING = incident_config.load()
ONE, TWO = ObjectRef("device", "ip:10.2.0.1"), ObjectRef("device", "ip:10.2.0.2")
RARE = "domain:rare-example.org"


@dataclass(frozen=True)
class _Window:
    score: float = 10.0


class _Verdict:
    def __init__(self, *lanes: str) -> None:
        self.lanes = lanes

    def window(self, _: str) -> _Window:
        return _Window()


def scored(*refs: ObjectRef) -> Any:
    return SimpleNamespace(verdicts={r: _Verdict("burst") for r in refs}, factors={})


def seen(ref: ObjectRef, at: datetime, threats: tuple[str, ...] = ()) -> Observation:
    return obs("rule:L1", key=ref.key, hours_ago=(NOW - at).total_seconds() / 3600,
               threats=threats, gid=uuid.uuid4())  # fmt: skip


def loaded_of(rows: list[Observation]) -> Loaded:
    out = Loaded(observations=rows)
    for o in rows:
        out.groups[o.group] = GroupMeta(
            o.group, o.at, o.at, o.at + timedelta(hours=1), o.day, 1, "low", "outbound", 1.0,
            None, (), (), (), (o.object,), o.at,
        )  # fmt: skip
    return out


def test_a_piece_merged_later_still_counts_and_people_saw_two() -> None:
    first, second = seen(ONE, NOW), seen(TWO, NOW + timedelta(hours=5))
    later = NOW + timedelta(hours=8)
    bridge = [seen(ONE, later, (RARE,)), seen(TWO, later, (RARE,))]
    rows = [first, second, *bridge]
    known = {"k": Known("k", {ONE, TWO}, NOW + timedelta(hours=6))}
    start = NOW - timedelta(hours=1)
    replay = IncidentReplay(loaded_of(rows), LINKING, mode="db", known=known, start=start)
    replay(NOW, scored(ONE), [first], True)
    replay(NOW + timedelta(hours=5), scored(TWO), [first, second], True)
    replay(later, scored(ONE, TWO), rows, True)
    assert len([i for i in replay.incidents if i.state == "merged"]) == 1
    row = replay.report(known, [], start)["known"]["k"]
    assert row["incidents"] == 2  # both pieces a person was shown
    assert row["share_in_one_incident"] == 1.0  # one incident in the end
    assert row["at_found_by_people"] == {
        "incidents": 2, "groups": 2, "groups_in_one_incident": 1, "share_in_one_incident": 0.5,
    }  # fmt: skip


def test_found_after_the_last_step_is_measured_at_the_end() -> None:
    first = seen(ONE, NOW)
    known = {"k": Known("k", {ONE}, NOW + timedelta(days=3))}
    replay = IncidentReplay(loaded_of([first]), LINKING, mode="db", known=known)
    replay(NOW, scored(ONE), [first], True)
    row = replay.report(known, [], NOW - timedelta(hours=1))["known"]["k"]
    assert row["at_found_by_people"]["incidents"] == 1
    assert row["at_found_by_people"]["share_in_one_incident"] == 1.0


def test_the_popularity_list_is_the_modes() -> None:
    fetched = NOW
    cached = Answers(domains={
        "popular-example.com": [("found", {"ranked": True}, fetched)],
        "plain-example.com": [("found", {"ranked": False}, fetched)],
        "gone-example.com": [("not_found", {"ranked": True}, fetched)],
    })  # fmt: skip
    db = IncidentReplay(Loaded(), LINKING, mode="db", cached=cached)
    want = frozenset({"domain:popular-example.com"})
    assert db.popular(fetched - timedelta(hours=1)) == frozenset()  # not fetched yet
    assert db.popular(fetched + timedelta(hours=1)) == want
    assert db.popular(fetched + timedelta(days=31)) == frozenset()  # older than the pass reads
    oracle = IncidentReplay(Loaded(), LINKING, mode="oracle", cached=cached)
    assert oracle.popular(fetched - timedelta(days=5)) == want
    blind = IncidentReplay(Loaded(), LINKING, mode="no-vt", cached=cached)
    assert blind.popular(fetched + timedelta(hours=1)) == frozenset()


def test_found_before_the_window_counts_the_warm_ups_alert_groups() -> None:
    first = seen(ONE, NOW)
    start = NOW + timedelta(hours=3)  # the counted window opens after the warm-up step
    known = {"k": Known("k", {ONE}, NOW + timedelta(hours=1))}
    replay = IncidentReplay(loaded_of([first]), LINKING, mode="db", known=known, start=start)
    replay(NOW, scored(ONE), [first], False)
    replay(NOW + timedelta(hours=4), scored(ONE), [first], True)
    row = replay.report(known, [], start)["known"]["k"]
    assert row["at_found_by_people"] == {
        "incidents": 1, "groups": 1, "groups_in_one_incident": 1, "share_in_one_incident": 1.0,
    }  # fmt: skip
