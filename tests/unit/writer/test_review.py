"""Q-D4's review (R1, R10): a person's edit that the read-back has not polled yet, invisible
characters, and a person's title. Each test failed on the code the review attacked."""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from argus.cases import kibana as intent
from argus.writer import lookup, plan, render

pytestmark = pytest.mark.unit

CASE = uuid.UUID("3f2a9c1e-5b7d-4e86-9a10-c4d2e8f61b73")
CTX = render.Context("https://argus.example", reference="k")
OPEN_TAGS = ["argus", f"argus:case:{CASE}", "argus:owner:argus", "argus:state:open"]
TAKEN_TAGS = ["argus", f"argus:case:{CASE}", "argus:owner:user-4", "argus:state:assigned"]


def row(op: str, payload: dict[str, Any], *, from_state: str = "open"):  # type: ignore[no-untyped-def]
    return plan.Row(
        1, CASE, 1, 0, "W2" if op != "close" else "W3", op, payload,
        intent.payload_hash(payload), f"{CASE}:v2:0", None, "approved", 0, from_state, "assigned",
    )  # fmt: skip


def live(**over: Any) -> dict[str, Any]:
    case: dict[str, Any] = {
        "id": "kid-1", "version": "WzEsMV0=", "status": "open", "severity": "high",
        "tags": list(OPEN_TAGS), "settings": {"syncAlerts": False},
        "created_by": {"username": "argus"},
    }  # fmt: skip
    case.update(over)
    return case


# --------------------------------------------------------------------------- R10


INVISIBLE = [
    0x00AD, 0x034F, 0x061C, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180B, 0x180E, 0x200B, 0x200E,
    0x202A, 0x202E, 0x2060, 0x2065, 0x2066, 0x2069, 0x206A, 0x206B, 0x206C, 0x206D, 0x206E,
    0x206F, 0x3164, 0xFE00, 0xFE0F, 0xFEFF, 0xFFA0, 0xFFF9, 0xE0001, 0xE0041, 0xE007F, 0xE0100,
]  # fmt: skip


@pytest.mark.parametrize("code", INVISIBLE, ids=lambda c: f"U+{c:04X}")
def test_clean_removes_every_invisible_and_bidirectional_character(code: int) -> None:
    assert render.clean(f"a{chr(code)}b") == "a b"


def test_clean_keeps_what_people_read() -> None:
    assert render.clean("Ünïcödé café 日本語 — ok ✓") == "Ünïcödé café 日本語 — ok ✓"


HOSTILE = "[ARGUS 1] pay‮ https://evil.example/login ​⁦x\U000e0041"


def create_row(title: str) -> plan.Row:
    payload = {
        "title": title, "status": "open", "severity": "high",
        "argus_tags": sorted(OPEN_TAGS), "settings": {"syncAlerts": False},
        "description": {"template": "case_description", "params": {
            "case": str(CASE), "link": f"/go/case/{CASE}", "what": "x", "hosts": [],
            "more_hosts": 0, "indicators": [], "more_indicators": 0, "investigations": 1,
            "first_alert": None, "latest_alert": None}},
    }  # fmt: skip
    return plan.Row(
        1, CASE, 1, 0, "W1", "create", payload, intent.payload_hash(payload), "k", None,
        "planned", 0, None, "open",
    )  # fmt: skip


def test_a_persons_title_is_cleaned_and_defanged_before_it_reaches_kibana() -> None:
    verdict = plan.plan_create(create_row(HOSTILE), CTX)
    assert isinstance(verdict, plan.Send)
    sent = verdict.params.title  # type: ignore[attr-defined]
    assert sent == "[ARGUS 1] pay hxxps://evil[.]example/login x"
    assert verdict.expect["title"] == sent


def test_the_title_is_cut_to_kibanas_limit_after_defanging() -> None:
    long = "[ARGUS 7] " + "a.b " * 60
    sent = plan.kibana_title(long)
    assert len(sent.encode("utf-16-le")) // 2 <= intent.KIBANA_TITLE_LIMIT
    assert sent.endswith("…")
    emoji = plan.kibana_title("[ARGUS 7] " + "\U0001f600" * 100)  # two UTF-16 units each
    assert len(emoji.encode("utf-16-le")) // 2 <= intent.KIBANA_TITLE_LIMIT


def test_the_lookup_recognises_the_case_made_from_a_hostile_title() -> None:
    """The title Kibana holds is the cleaned one; a look that compared the raw title would never
    find a case that landed."""
    row_ = create_row(HOSTILE)
    verdict = plan.plan_create(row_, CTX)
    assert isinstance(verdict, plan.Send)
    wanted = render.description(row_.payload["description"]["params"], CTX)
    made = {
        "created_by": {"username": "argus"}, "title": verdict.params.title,  # type: ignore[attr-defined]
        "severity": "high", "tags": list(row_.payload["argus_tags"]), "description": wanted,
    }  # fmt: skip
    assert lookup.is_ours(made, row_.payload, wanted, "argus")


# --------------------------------------------------------------------------- R1


def seen(
    *, severities: tuple[str, ...] = ("high",), tags: tuple[list[str], ...] = (OPEN_TAGS,)
) -> plan.Seen:
    return plan.Seen.of(severities, tags)


SEVERITY_UP = {"severity": "critical"}


def test_a_severity_a_person_lowered_since_the_last_poll_is_kept() -> None:
    lowered = live(severity="low")  # ARGUS last saw (and set) high
    verdict = plan.plan_change(
        row("update", SEVERITY_UP), lowered, plan.MirrorFacts(), CTX, "argus", seen=seen()
    )
    assert isinstance(verdict, plan.Skip)
    assert "a person changed it" in verdict.reason


def test_a_severity_argus_saw_or_set_is_changed() -> None:
    for known, now in (("high", "high"), ("medium", "medium")):
        verdict = plan.plan_change(
            row("update", SEVERITY_UP),
            live(severity=now),
            plan.MirrorFacts(),
            CTX,
            "argus",
            seen=seen(severities=(known,)),
        )
        assert isinstance(verdict, plan.Send), now
        assert verdict.params.cases[0].severity == "critical"  # type: ignore[attr-defined]


def test_nothing_known_means_nothing_can_be_told_and_the_change_goes() -> None:
    verdict = plan.plan_change(
        row("update", SEVERITY_UP), live(severity="low"), plan.MirrorFacts(), CTX, "argus",
        seen=plan.Seen(),
    )  # fmt: skip
    assert isinstance(verdict, plan.Send)


def test_a_tag_of_arguss_kind_a_person_added_holds_the_write() -> None:
    edited = live(tags=[*OPEN_TAGS, "argus:owner:bob"])
    take = {"status": "in-progress", "argus_tags": sorted(TAKEN_TAGS)}
    verdict = plan.plan_change(
        row("update", take), edited, plan.MirrorFacts(), CTX, "argus", seen=seen()
    )
    assert isinstance(verdict, plan.Hold)
    assert verdict.action == "wait"
    assert "a person changed ARGUS's tags" in verdict.reason


def test_an_arguss_tag_a_person_removed_holds_the_write() -> None:
    edited = live(tags=[t for t in OPEN_TAGS if t != "argus:state:open"])
    take = {"argus_tags": sorted(TAKEN_TAGS)}
    verdict = plan.plan_change(
        row("update", take), edited, plan.MirrorFacts(), CTX, "argus", seen=seen()
    )
    assert isinstance(verdict, plan.Hold)


def test_arguss_own_earlier_tags_and_a_persons_plain_tag_do_not_hold_it() -> None:
    take = {"status": "in-progress", "argus_tags": sorted(TAKEN_TAGS)}
    for tags in (OPEN_TAGS, [*OPEN_TAGS, "team-blue"], TAKEN_TAGS):
        verdict = plan.plan_change(
            row("update", take), live(tags=list(tags)), plan.MirrorFacts(), CTX, "argus",
            seen=seen(),
        )  # fmt: skip
        assert not isinstance(verdict, plan.Hold), tags


def test_the_mirrors_last_poll_counts_as_seen_so_a_polled_edit_is_the_pauses_business() -> None:
    polled = [*OPEN_TAGS, "argus:owner:bob"]
    take = {"argus_tags": sorted(TAKEN_TAGS)}
    verdict = plan.plan_change(
        row("update", take), live(tags=polled), plan.MirrorFacts(), CTX, "argus",
        seen=seen(tags=(OPEN_TAGS, polled)),
    )  # fmt: skip
    assert isinstance(verdict, plan.Send)  # the poll pauses a case a person tagged; no pause here


def test_a_closure_does_not_overwrite_arguss_tags_a_person_changed_either() -> None:
    closed_tags = sorted([*TAKEN_TAGS[:2], "argus:closed", "argus:reason:benign_policy",
                          "argus:state:closed"])  # fmt: skip
    close = {"status": "closed", "argus_tags": closed_tags}
    edited = live(tags=[*OPEN_TAGS, "argus:owner:bob"])
    verdict = plan.plan_change(
        row("close", close), edited, plan.MirrorFacts(), CTX, "argus", seen=seen()
    )
    assert isinstance(verdict, plan.Hold)
    fine = plan.plan_change(row("close", close), live(), plan.MirrorFacts(), CTX, "argus",
                            seen=seen())  # fmt: skip
    assert isinstance(fine, plan.Send)


def test_seen_keeps_only_the_tags_arguss_kind() -> None:
    known = plan.Seen.of(["high", None], [[*OPEN_TAGS, "team-blue"], None, OPEN_TAGS])
    assert known.severities == frozenset({"high"})
    assert known.tags == (
        frozenset(OPEN_TAGS),
    )  # one set: the plain tag is dropped, the repeat merged


# --------------------------------------------------------------------------- R12


def test_the_operator_is_the_person_sudo_was_run_by_under_custody_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A run, a ramp step and a skip record who was at the terminal; the service account the
    process runs as is never that person. Outside custody the operating system's user is."""
    import getpass

    from argus.config.settings import CustodySettings, Settings, operator_of

    monkeypatch.setattr(getpass, "getuser", lambda: "argus-writer")
    under = Settings(custody=CustodySettings(role="writer", operator="asha"))
    assert operator_of(under) == "asha"
    assert operator_of(Settings(custody=CustodySettings(role="writer"))) == "argus-writer"
    # a variable set by hand in the shared layout does not rename a person
    assert operator_of(Settings(custody=CustodySettings(operator="mallory"))) == "argus-writer"


@pytest.mark.parametrize("name", ["a b", "x;rm", "-e", "", "a" * 70, "$(id)", "a\nb"])
def test_the_operators_name_is_a_plain_login_name(name: str) -> None:
    from pydantic import ValidationError

    from argus.config.settings import CustodySettings

    with pytest.raises(ValidationError):
        CustodySettings(role="writer", operator=name)
