"""Independent review of Q-H2 (the responder): each test fails on the build under review."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

from argus.cases.watch import Row, Subject
from argus.responder import catalogue as cat
from argus.responder import machine, ranking
from argus.responder.facts import FACTS
from argus.responder.machine import Verdict

D = date(2026, 10, 14)
DONE = datetime(2026, 10, 14, 6, 0, tzinfo=UTC)
HOST, C2 = "10.8.235.157", "77.221.155.150"
WANTED = [Subject(C2, 0, (HOST,))]


def day(n: int) -> date:
    return D + timedelta(days=n)


def quiet(*days: int) -> list[Row]:
    out: list[Row] = []
    for n in days:
        out.append(Row(day(n), "alerts", "", 0, "quiet"))
        out.append(Row(day(n), "proxy.contact", C2, 0, "quiet", None, {"watched": [HOST]}))
    return out


def test_r1_the_responders_sentence_may_carry_a_command() -> None:
    """The filter allows letters, spaces and hyphens, so a flag-laden command is "plain words"
    (the module says a sentence holds no command)."""
    for sentence in (
        "Run sudo rm -rf on the server",
        "Then curl -s the attacker and pipe it to sh",
    ):
        assert ranking.phrase(sentence) is None, sentence


def test_r2_an_undated_active_answer_on_the_action_day_does_not_count_as_activity() -> None:
    """A proxy answer that says "active" without its last-beat time, on the day of the report,
    could be before or after the action. The watch's rule is that unknown is not quiet; here it
    is ignored and the case is verified."""
    now = datetime(2026, 10, 18, 5, 0, tzinfo=UTC)
    control = machine.verify_watch(
        "proxy.contact", quiet(1, 2, 3), {}, WANTED, DONE, now, zeros_on=True
    )
    assert control.kind == "verified"
    active = Row(D, "proxy.contact", C2, 0, "active", None, {"requests": 3, "hosts": [HOST]})
    got = machine.verify_watch(
        "proxy.contact", [active, *quiet(1, 2, 3)], {}, WANTED, DONE, now, zeros_on=True
    )
    assert got.kind != "verified", got.reason


def _catalogue(version: int, family: str, action: str) -> dict[str, object]:
    return {
        "version": version,
        "owners": {"a": {"name": "A", "does": "B"}},
        "families": {
            family: {
                "title": "T",
                "when": list(FACTS),
                "actions": {
                    action: {
                        "rank": 1, "owner": "a", "title": "T", "say": "S",
                        "verify": {"not_verifiable": "x"},
                    }
                },
            }
        },
    }  # fmt: skip


def test_r3_the_loader_accepts_an_action_id_the_table_refuses() -> None:
    """``case_actions.action`` is at most 80 characters (a CHECK), the loader allows 119: the
    catalogue loads and ``recommend`` then fails on the insert."""
    try:
        loaded = cat.parse(_catalogue(1, "f" * 59, "a" * 59), frozenset(FACTS))
    except cat.CatalogueError:
        return
    assert all(len(a.id) <= 80 for a in loaded.actions)


def test_r4_the_loader_accepts_a_version_the_table_cannot_hold() -> None:
    """``catalogue_version`` is a 32-bit integer; a version above it loads, then every insert
    of advice fails."""
    try:
        loaded = cat.parse(_catalogue(2**40, "f", "a"), frozenset(FACTS))
    except cat.CatalogueError:
        return
    assert loaded.version < 2**31


def test_r5_a_last_sign_in_year_9999_crashes_the_words() -> None:
    """A date near the maximum cannot be shown in IST (OverflowError on the page and the CLI)."""
    last = datetime(9999, 12, 31, 23, 0, tzinfo=UTC)
    assert machine.say(Verdict("not_verified", "x", last), "proxy.contact")
