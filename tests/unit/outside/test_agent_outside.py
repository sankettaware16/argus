"""AR3 (D-165): the investigator's two outside tools. Reputation is VirusTotal's; "what is this
server" is Shodan's, then Censys's when Shodan has nothing. An answer is a fact in the item (the
model reads it in the next round and may cite it), a plain sentence among the run's checks, and
a detection blocks a benign proposal like a threat-list hit. Never asked: a campus or private
address, anything the local threat lists already list, anything when the source is off or at its
limit, more than the run's tool allowance. The lookups themselves are faked here (the real
module has its own tests).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from argus.agent import catalogue
from argus.agent.agent import Limits
from argus.agent.catalogue import OutsideAsk, Refusal
from argus.agent.reading import BLOCKED_WORDS
from argus.config.settings import OutsideSettings
from argus.llm.detect import OwnSpace
from argus.llm.privacy import Privacy
from argus.outside import facts
from argus.outside.eligible import Eligibility
from argus.outside.service import BLOCKED, CACHED, FETCHED, OFF, Outcome, Outside
from tests.unit.agent.test_agent import CLASSIFIER, INV, NOW, Model, agent, body, say, token
from tests.unit.agent.test_catalogue import FACTS, reveal
from tests.unit.agent.test_catalogue import NOW as CAT_NOW

VT_BAD = {"malicious": 7, "suspicious": 0, "harmless": 60, "undetected": 27, "engines": 94}
VT_CLEAN = {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 24, "engines": 94}
SERVER = {"ports": [22, 443], "org": "Acme Hosting"}
ASKED = "8.8.8.8"  # a public address the test item shows


class FakeOutside(Outside):
    """Scripted answers by (source, value); records what was asked. No database, no network."""

    def __init__(self, answers: dict[tuple[str, str], Outcome | str] | None = None) -> None:
        settings = OutsideSettings()
        super().__init__(None, settings, None, Eligibility(CLASSIFIER, None))  # type: ignore[arg-type]
        self.answers = answers or {}
        self.asked: list[tuple[str, str, str, str]] = []
        self.campuses: list[OwnSpace | None] = []

    async def lookup(
        self, source: str, kind: str, value: str, *, purpose: str = "agent",
        day_cap: int | None = None, ours: OwnSpace | None = None,
    ) -> Outcome:  # fmt: skip
        self.asked.append((source, kind, value, purpose))
        self.campuses.append(ours)
        got = self.answers.get((source, value))
        if isinstance(got, Outcome):
            return got
        return Outcome(OFF, source, kind, value, reason=f"{facts.NAMES[source]} is off (no key)")

    async def attach(self, conn: Any, investigation_id: Any, body: Any) -> Any:
        return body


def answered(source: str, answer: dict[str, Any], status: str = "found", how: str = FETCHED) -> Any:
    return Outcome(how, source, "ip", ASKED, status, answer)


def reputation(entity: str = ASKED) -> str:
    return say(ask=[{"tool": "outside.reputation", "entity": entity}], cites=["severity high"])


# -- the catalogue ------------------------------------------------------------------------------


def test_reputation_and_server_are_built_for_a_public_address_or_a_name() -> None:
    text = "Entities: ip 8.8.8.8, evil.example"
    rep = catalogue.build("outside.reputation", "8.8.8.8", reveal, FACTS, CAT_NOW, CLASSIFIER, text)
    assert rep == OutsideAsk(("virustotal",), "ip", "8.8.8.8")
    name = catalogue.build("outside.reputation", "I1.SITE_1", reveal, FACTS, CAT_NOW, CLASSIFIER)
    assert name == OutsideAsk(("virustotal",), "domain", "evil.example")
    srv = catalogue.build("outside.server", "I1.IP_2", reveal, FACTS, CAT_NOW, CLASSIFIER)
    assert srv == OutsideAsk(("shodan", "censys"), "ip", "8.8.8.8")


PUBLIC_ONLY = "outside lookups take a public address, never a campus or private one"


@pytest.mark.parametrize(
    ("tool", "entity", "reason"),
    [
        ("outside.reputation", "I1.IP_1", PUBLIC_ONLY),
        ("outside.server", "I1.IP_1", PUBLIC_ONLY),
        ("outside.reputation", "I1.IP_4", PUBLIC_ONLY),
        ("outside.reputation", "I1.IP_3", "not an address"),
        ("outside.server", "I1.SITE_1", "outside.server takes IP, not SITE"),
        ("outside.reputation", "I1.HOST_1", "outside.reputation takes IP or SITE, not HOST"),
    ],
)
def test_an_outside_tool_refuses_what_is_not_external_before_anything_is_asked(
    tool: str, entity: str, reason: str
) -> None:
    got = catalogue.build(tool, entity, reveal, FACTS, CAT_NOW, CLASSIFIER)
    assert got == Refusal(reason)


def test_the_local_threat_lists_settle_an_indicator_they_list() -> None:
    hit = {"kind": "ip", "value": "8.8.8.8", "sources": {"abuse-ioc": {"match": [{"type": "c2"}]},
                                                          "acme": {"no_match": True}}}  # fmt: skip
    miss = {"kind": "ip", "value": "9.9.9.9", "sources": {"abuse-ioc": {"no_match": True}}}
    item = {"context": {"pack": {"ti": {"answers": [hit, miss]}}}}
    assert catalogue.settled(item, "8.8.8.8")
    assert catalogue.settled(item, "8.8.8.8".upper())
    assert not catalogue.settled(item, "9.9.9.9")  # checked and clean: an outside view still adds
    assert not catalogue.settled(item, "1.1.1.1")
    odd = [5, {"value": "8.8.8.8", "sources": 3}]
    for junk in (
        {}, {"context": 5}, {"context": {"pack": {"ti": {"answers": "x"}}}},
        {"context": {"pack": {"ti": {"answers": odd}}}},
    ):  # fmt: skip
        assert not catalogue.settled(junk, "8.8.8.8")


# -- a run --------------------------------------------------------------------------------------


async def test_a_detection_is_a_check_a_cited_fact_and_the_proposal(privacy: Privacy) -> None:
    outside = FakeOutside({("virustotal", ASKED): answered("virustotal", VT_BAD)})
    sentence = "VirusTotal: 7 of 94 engines flag this IP"
    model = Model(reputation(), say(cites=[sentence], reason="VirusTotal flags the server"))
    a = agent(privacy, model, outside=outside)
    got = await a.run(INV, body(), False, False)
    assert got.outcome == "true_positive"  # the answer cited the outside fact, and it was there
    assert outside.asked == [("virustotal", "ip", ASKED, "agent")]
    second = model.calls[1].request.text
    assert "Outside threat intel (looked up for this item's external indicators only):" in second
    assert f"- {sentence} ({ASKED})" in second
    assert "Outside threat intel" not in model.calls[0].request.text  # not before it was asked
    report = got.reasons[-1]
    assert report["checks"] == [
        {"tool": "outside.reputation", "value": ASKED, "result": sentence, "agent": "investigator"}
    ]
    assert got.reasons[-2].endswith("tools: outside.reputation: fetched")
    assert report["answer"]["cites"] == [sentence]


async def test_a_detection_blocks_a_benign_proposal_like_a_threat_list_hit(
    privacy: Privacy,
) -> None:
    low = body(facts={**body()["facts"], "severity": "low"})
    low["signals"] = [{"name": "ti.listed", "status": "known", "value": 0}]
    own = "severity low"
    asks = say(ask=[{"tool": "outside.reputation", "entity": ASKED}], cites=[own],
               outcome="benign_expected")  # fmt: skip
    outside = FakeOutside({("virustotal", ASKED): answered("virustotal", VT_BAD)})
    benign = say(outcome="benign_expected", cites=[own], reason="ordinary")
    got = await agent(privacy, Model(asks, benign), outside=outside).run(INV, low, False, False)
    assert got.outcome is None
    assert got.reasons[1] == "floor: flagged by outside threat intel"
    assert got.reasons[-1]["reading"]["blocked"] == ["flagged by outside threat intel"]
    assert BLOCKED_WORDS["flagged by outside threat intel"] == "outside threat intel flags it"
    clean = FakeOutside({("virustotal", ASKED): answered("virustotal", VT_CLEAN)})
    again = await agent(privacy, Model(asks, benign), outside=clean).run(INV, low, False, False)
    assert again.outcome == "benign_expected"  # a clean answer blocks nothing


@pytest.mark.parametrize("limits", [Limits(calls=1), Limits(rounds=1), Limits(rounds=1, calls=1)])
async def test_a_detection_found_in_the_last_round_still_blocks_a_benign_proposal(
    privacy: Privacy, limits: Limits
) -> None:
    """The run ends when the model has no call left, and the tools of that last round have
    still run: what they found reaches the floor (Q-H1 repro: the same run with calls=1)."""
    low = body(facts={**body()["facts"], "severity": "low"})
    low["signals"] = [{"name": "ti.listed", "status": "known", "value": 0}]
    own = "severity low"
    asks = say(ask=[{"tool": "outside.reputation", "entity": ASKED}], cites=[own],
               outcome="benign_expected")  # fmt: skip
    outside = FakeOutside({("virustotal", ASKED): answered("virustotal", VT_BAD)})
    got = await agent(privacy, Model(asks), outside=outside, limits=limits).run(
        INV, low, False, False
    )
    assert outside.asked == [("virustotal", "ip", ASKED, "agent")]
    assert got.outcome is None
    assert got.reasons[1] == "floor: flagged by outside threat intel"
    assert got.reasons[-1]["reading"]["blocked"] == ["flagged by outside threat intel"]
    clean = FakeOutside({("virustotal", ASKED): answered("virustotal", VT_CLEAN)})
    again = await agent(privacy, Model(asks), outside=clean, limits=limits).run(
        INV, low, False, False
    )
    assert again.outcome == "benign_expected"  # a clean answer blocks nothing


async def test_a_run_out_of_time_reads_the_last_tools_too(privacy: Privacy) -> None:
    low = body(facts={**body()["facts"], "severity": "low"})
    low["signals"] = [{"name": "ti.listed", "status": "known", "value": 0}]
    asks = say(ask=[{"tool": "outside.reputation", "entity": ASKED}], cites=["severity low"],
               outcome="benign_expected")  # fmt: skip
    outside = FakeOutside({("virustotal", ASKED): answered("virustotal", VT_BAD)})
    ticks = iter(range(0, 10_000, 1_000))  # every look at the clock is 1,000 s later
    a = agent(privacy, Model(asks), outside=outside, monotonic=lambda: float(next(ticks)))
    got = await a.run(INV, low, False, False)
    assert got.outcome is None
    assert got.reasons[1] == "floor: flagged by outside threat intel"


async def test_a_server_is_asked_of_shodan_and_censys_only_when_shodan_has_nothing(
    privacy: Privacy,
) -> None:
    ask = say(ask=[{"tool": "outside.server", "entity": ASKED}])
    both = FakeOutside({("shodan", ASKED): answered("shodan", {}, "not_found"),
                        ("censys", ASKED): answered("censys", SERVER)})  # fmt: skip
    got = await agent(privacy, Model(ask, say()), outside=both).run(INV, body(), False, False)
    assert [a[0] for a in both.asked] == ["shodan", "censys"]
    assert [c["result"] for c in got.reasons[-1]["checks"]] == [
        "Shodan: has no record of this IP",
        "Censys: open ports 22, 443; run by Acme Hosting",
    ]
    one = FakeOutside({("shodan", ASKED): answered("shodan", SERVER, how=CACHED),
                       ("censys", ASKED): answered("censys", SERVER)})  # fmt: skip
    got = await agent(privacy, Model(ask, say()), outside=one).run(INV, body(), False, False)
    assert [a[0] for a in one.asked] == ["shodan"]  # Shodan said what it is
    assert len(got.reasons[-1]["checks"]) == 1


async def test_a_source_that_is_off_or_at_its_limit_gives_no_fact_and_is_not_retried(
    privacy: Privacy,
) -> None:
    until = NOW + timedelta(minutes=3)
    why = "VirusTotal is at its limit; it has room again at 12:03 UTC"
    blocked = Outcome(BLOCKED, "virustotal", "ip", ASKED, until=until, reason=why)
    outside = FakeOutside({("virustotal", ASKED): blocked})
    model = Model(reputation(), reputation(), say())
    got = await agent(privacy, model, outside=outside).run(INV, body(), False, False)
    assert len(outside.asked) == 1  # not asked again this run
    (check,) = got.reasons[-1]["checks"]
    assert check["result"] == "VirusTotal is at its limit; it has room again at 12:03 UTC"
    assert all("Outside threat intel" not in c.request.text for c in model.calls)
    off = FakeOutside()
    got = await agent(privacy, Model(reputation(), say()), outside=off).run(
        INV, body(), False, False
    )
    assert got.reasons[-1]["checks"][0]["result"] == "VirusTotal is off (no key)"


async def test_a_campus_address_is_refused_before_any_lookup(privacy: Privacy) -> None:
    host = token(privacy, "10.20.3.4")
    outside = FakeOutside({("virustotal", "10.20.3.4"): answered("virustotal", VT_BAD)})
    model = Model(say(ask=[{"tool": "outside.reputation", "entity": host},
                           {"tool": "outside.server", "entity": host}]), say())  # fmt: skip
    got = await agent(privacy, model, outside=outside).run(INV, body(), False, False)
    assert outside.asked == []
    results = [c["result"] for c in got.reasons[-1]["checks"]]
    assert (
        results
        == ["refused: outside lookups take a public address, never a campus or private one"] * 2
    )


async def test_an_address_the_local_lists_already_list_is_not_sent_anywhere(
    privacy: Privacy,
) -> None:
    item = body()
    item["context"]["pack"]["ti"] = {"answers": [
        {"kind": "ip", "value": ASKED, "sources": {"abuse-ioc": {"match": [{"type": "c2"}]}}}
    ]}  # fmt: skip
    outside = FakeOutside({("virustotal", ASKED): answered("virustotal", VT_BAD)})
    got = await agent(privacy, Model(reputation(), say()), outside=outside).run(
        INV, item, False, False
    )
    assert outside.asked == []
    assert got.reasons[-1]["checks"][0]["result"] == (
        "not asked: the local threat lists already list this"
    )


async def test_only_the_intel_specialist_and_the_investigator_may_ask(privacy: Privacy) -> None:
    outside = FakeOutside({("virustotal", ASKED): answered("virustotal", VT_CLEAN)})
    ask = {"tool": "outside.reputation", "entity": ASKED}
    notes = json.dumps({"notes": "n", "cites": [], "ask": [ask]})
    model = Model(say(consult=["proxy", "intel"]), notes, notes, say(reason="again"), say())
    got = await agent(privacy, model, outside=outside).run(INV, body(), False, False)
    checks = got.reasons[-1]["checks"]
    assert (checks[0]["agent"], checks[0]["result"]) == (
        "proxy", "refused: the proxy specialist may not use outside.reputation",
    )  # fmt: skip
    assert (checks[1]["agent"], checks[1]["result"]) == (
        "intel", "VirusTotal: no engine of 94 flags this IP",
    )  # fmt: skip
    assert len(outside.asked) == 1


async def test_the_tool_allowance_of_a_run_bounds_the_lookups(privacy: Privacy) -> None:
    from argus.agent.agent import Limits

    outside = FakeOutside({("shodan", ASKED): answered("shodan", {}, "not_found"),
                           ("censys", ASKED): answered("censys", {}, "not_found")})  # fmt: skip
    model = Model(say(ask=[{"tool": "outside.server", "entity": ASKED}]), say())
    got = await agent(privacy, model, outside=outside, limits=Limits(tools=1)).run(
        INV, body(), False, False
    )
    assert [a[0] for a in outside.asked] == ["shodan"]  # one tool use, then the allowance is spent
    assert got.reasons[-2].endswith("tools: outside.server: fetched")


async def test_an_agent_with_no_outside_module_refuses_the_tool(privacy: Privacy) -> None:
    got = await agent(privacy, Model(reputation(), say())).run(INV, body(), False, False)
    assert got.reasons[-1]["checks"][0]["result"] == "refused: outside lookups are not set up"


async def test_facts_the_cache_held_before_the_run_are_in_the_first_round(privacy: Privacy) -> None:
    item = body()
    item["outside"] = [facts.fact("virustotal", "ip", ASKED, "found", VT_BAD, 3)]
    model = Model(say())
    got = await agent(privacy, model).run(INV, item, False, False)
    first = model.calls[0].request.text
    assert f"- VirusTotal: 7 of 94 engines flag this IP ({ASKED})" in first
    assert got.outcome == "true_positive"
    benign = body(facts={**body()["facts"], "severity": "low"})
    benign["signals"] = [{"name": "ti.listed", "status": "known", "value": 0}]
    benign["outside"] = item["outside"]
    blocked = await agent(
        privacy, Model(say(outcome="benign_expected", cites=["severity low"]))
    ).run(INV, benign, False, False)
    assert blocked.reasons[1] == "floor: flagged by outside threat intel"


def test_the_clock_the_tests_share() -> None:
    assert datetime(2026, 10, 16, 12, tzinfo=UTC) == NOW


async def test_the_lookup_is_checked_against_the_campus_view_of_the_item(
    privacy: Privacy,
) -> None:
    """The names an item mentions are campus names for it: the lookup gets the request's own
    campus (its host and user names), so a name that holds one is refused there."""
    outside = FakeOutside({("virustotal", ASKED): answered("virustotal", VT_CLEAN)})
    await agent(privacy, Model(reputation(), say()), outside=outside).run(INV, body(), False, False)
    (ours,) = outside.campuses
    assert ours is not None
    assert "tp8" in ours.hosts
    assert "alice" in ours.users  # the item's entities (tests/unit/llm/test_privacy.py)
    mine = Eligibility(CLASSIFIER, ours)
    assert mine.check("domain", "alice.c2.com") == "a campus name"
    assert mine.check("domain", "tp8.c2.com") == "a campus name"
    assert Eligibility(CLASSIFIER, privacy.ours).check("domain", "alice.c2.com") is None
