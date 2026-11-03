"""Q-C2 independent review: unit reproductions (see tests/integration/cases/test_review_c2.py)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from argus.cases import membership, opener
from argus.cases.model import Indicator
from argus.cases.opener import Candidate, Indexed

NOW = datetime(2026, 10, 20, 9, 0, tzinfo=UTC)
INV = [uuid.UUID(int=300 + n) for n in range(12)]


def cand(n: int, *, person: bool = True, ip: str = "10.0.0.1",
         entities: tuple[tuple[str, str], ...] = ()) -> Candidate:  # fmt: skip
    return Candidate(
        "review" if person else "assessment", n, INV[n], person, NOW + timedelta(minutes=n),
        "Rule", "medium", (Indicator("ip", ip, "actor"),), True, frozenset(entities), (),
        {"proxy.regularity": ("known", 0.1)},
    )  # fmt: skip


@pytest.mark.parametrize("person", [True, False], ids=["verdicts", "proposals"])
def test_r5_a_tie_does_not_open_a_new_case_for_every_later_investigation(person: bool) -> None:
    """Two open cases share an actor. The first investigation of that actor joins neither (a tie)
    and opens a new case; the next one then ties among three, and opens a fourth: six
    investigations of one host become six new cases (at most 20 an hour), none ever joined."""
    cases = [
        Indexed(uuid.UUID(int=1), 7, "open", None, set(), {("ip", "10.0.0.1"): "actor"}),
        Indexed(uuid.UUID(int=2), 3, "assigned", None, set(), {("ip", "10.0.0.1"): "actor"}),
    ]
    plan = opener.plan([cand(n, person=person) for n in range(6)], cases, now=NOW,
                       created_last_hour=0)  # fmt: skip
    new_cases = [o for o in plan if o.decision in ("opened", "suspected")]
    assert len(new_cases) <= 1, [(o.decision, o.case_ref) for o in plan]


@pytest.mark.parametrize(
    "body", ["", "# nothing here\n", "version: 1\n", "version: 1\nnetworks: []\ndomains: []\n"]
)
def test_r9_an_empty_shared_infrastructure_list_is_an_error(body: str, tmp_path: Path) -> None:
    """load_shared says a missing or invalid list is an error because the CDN rule would
    silently not apply; an empty one switches the rule off just as silently."""
    path = tmp_path / "shared.yaml"
    path.write_text(body)
    with pytest.raises(Exception, match=r"shared|empty|list"):
        membership.load_shared(path)


# ============================================================================ the fixer's tests

A = uuid.UUID(int=1)
B = uuid.UUID(int=2)
D_ = uuid.UUID(int=4)


def held(ref: uuid.UUID, number: int, ip: str, *, state: str = "open", tie_of=frozenset()):  # type: ignore[no-untyped-def]
    return Indexed(ref, number, state, None, set(), {("ip", ip): "actor"}, tie_of)  # type: ignore[arg-type]


def test_r5_a_proposal_opens_no_case_on_a_tie_and_says_why() -> None:
    cases = [held(A, 7, "10.0.0.1"), held(B, 3, "10.0.0.1")]
    (opening,) = opener.plan([cand(0, person=False)], cases, now=NOW, created_last_hour=0)
    assert opening.decision == "attempt"
    assert "a proposal opens no case on a tie" in opening.reasons[0]
    assert sorted((s.case.number, s.kind) for s in opening.suggested) == [(3, "tie"), (7, "tie")]


def test_r5_the_first_verdict_of_a_tie_opens_a_case_that_remembers_the_tie() -> None:
    cases = [held(A, 7, "10.0.0.1"), held(B, 3, "10.0.0.1")]
    first, second = opener.plan([cand(0, person=True), cand(1, person=True)], cases, now=NOW,
                                created_last_hour=0)  # fmt: skip
    assert (first.decision, first.case_ref) == ("opened", "new:1")
    assert opener.TIE_OPENED in first.reasons
    assert second.decision == "attempt"
    assert "case new:1 was opened by this tie" in second.reasons[0]
    assert sorted(s.case.number for s in second.suggested) == [3, 7, 10**9 + 1]  # each of the three


def test_r5_a_tie_of_the_same_cases_opens_none_even_when_the_case_it_opened_is_not_in_it() -> None:
    """The case the earlier tie opened holds another actor, so the next investigation (reaching
    the same two cases through the C2) ties only A and B: the same tie, so no second case."""
    born = Indexed(uuid.UUID(int=9), 8, "open", None, set(), {("ip", "10.0.0.5"): "actor"},
                   frozenset({A, B}))  # fmt: skip
    cases = [Indexed(A, 7, "open", None, set(), {("ip", "8.8.8.8"): "c2"}),
             Indexed(B, 3, "open", None, set(), {("ip", "8.8.8.8"): "c2"}), born]  # fmt: skip
    entities = (("ip", "8.8.8.8"),)
    (same,) = opener.plan([cand(0, ip="10.0.0.77", entities=entities)], cases, now=NOW,
                          created_last_hour=0)  # fmt: skip
    assert same.decision == "attempt"
    assert same.reasons[0].startswith("case 8 was opened by this tie")


def test_r5_a_different_tie_or_a_closed_tie_born_case_opens_its_own() -> None:
    d = Indexed(D_, 5, "open", None, set(), {("ip", "8.8.8.8"): "c2"})
    cases = [Indexed(A, 7, "open", None, set(), {("ip", "8.8.8.8"): "c2"}),
             Indexed(B, 3, "open", None, set(), {("ip", "8.8.8.8"): "c2"}),
             Indexed(uuid.UUID(int=9), 8, "open", None, set(), {}, frozenset({A, B}))]  # fmt: skip
    entities = (("ip", "8.8.8.8"),)
    ties_d = [*cases, d]  # the same C2 ties A, B and D now: another tie
    (other,) = opener.plan([cand(0, ip="10.0.0.77", entities=entities)], ties_d, now=NOW,
                           created_last_hour=0)  # fmt: skip
    assert other.decision == "opened"
    cases[2].state = "closed"
    (after,) = opener.plan([cand(0, ip="10.0.0.77", entities=entities)], cases, now=NOW,
                           created_last_hour=0)  # fmt: skip
    assert after.decision == "opened"  # the case the tie opened is closed: it blocks nothing


def test_r9_the_shipped_list_loads_from_any_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    loaded = membership.load_shared()
    assert loaded.networks
    assert loaded.domains


def test_r9_a_missing_list_is_a_config_error_naming_the_file(tmp_path: Path) -> None:
    from argus.config.errors import ConfigError

    with pytest.raises(ConfigError, match=r"shared\.yaml is missing"):
        membership.load_shared(tmp_path / "shared.yaml")


def test_r9_one_network_or_one_domain_is_enough(tmp_path: Path) -> None:
    path = tmp_path / "shared.yaml"
    path.write_text("version: 1\nnetworks: ['192.0.2.0/24']\n")
    assert len(membership.load_shared(path).networks) == 1
    path.write_text("version: 1\ndomains: ['example.net']\n")
    assert membership.load_shared(path).domains == frozenset({"example.net"})


def test_r17_the_doctor_loads_the_shared_list(tmp_path: Path) -> None:
    from argus.ops import checks

    good = checks.shared_result()
    assert (good.label, good.name) == ("PASS", "shared infrastructure")
    assert "networks" in good.detail
    path = tmp_path / "empty.yaml"
    path.write_text("# nothing\n")
    bad = checks.shared_result(path)
    assert bad.label == "FAIL"
    assert "lists no network and no domain" in bad.detail
    assert checks.shared_result(tmp_path / "missing.yaml").label == "FAIL"
