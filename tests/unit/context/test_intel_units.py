"""R11 review (D-063): ``ti.listed`` is 0 only when every source was checked and fresh and the
indicator list was not cut; the live lookup's matches count; stand-ins by whole words."""

from __future__ import annotations

from typing import Any

import pytest

from argus.context import intel
from argus.context.generic import _stand_in

ABUSE = "abuse-ioc"  # ACME's sources: the site under test names them (tests/conftest.py)
ACME = "acme-threat-intel"

FRESH = {"stale": False}
STALE = {"stale": True}


def answer(value: str, abuse: Any, acme: Any) -> dict[str, Any]:
    return {"value": value, "kind": "ip", "sources": {ABUSE: abuse, ACME: acme}}


def ti(*answers: dict[str, Any], listed: tuple[str, ...] = (), cut: bool = False) -> Any:
    return {
        "values": [["ip", a["value"]] for a in answers],
        "answers": list(answers),
        "listed": list(listed),
        "cut": cut,
    }


def listed(state: Any, evidence: Any = None, snaps: Any = None) -> Any:
    signals = intel.signals(1, state, evidence or {}, snaps or {})
    return next(s for s in signals if s.name == "ti.listed")


def test_zero_only_when_every_source_is_fresh() -> None:
    both = ti(answer("1.2.3.4", {"no_match": FRESH}, {"no_match": FRESH}))
    got = listed(both)
    assert (got.value, got.status, got.completeness) == (0, "known", "exact")
    assert intel.sentence(both, [got.as_dict()]) == (
        "Threat intel: none of 1 on a list. (abuse-ioc: fresh; acme-threat-intel: fresh)"
    )


@pytest.mark.parametrize(
    ("abuse", "acme", "reason"),
    [
        ({"no_match": FRESH}, {"not_checked": FRESH}, "source_not_checked"),
        ({"not_checked": None}, {"no_match": FRESH}, "source_not_checked"),
        ({"no_match": FRESH}, {"no_match": STALE}, "source_stale"),
        ({"no_match": FRESH}, {}, "source_stale"),  # no freshness known: not fresh
        ({"no_match": {}}, {"no_match": FRESH}, "source_stale"),
    ],
)
def test_one_source_not_fresh_is_unknown(abuse: Any, acme: Any, reason: str) -> None:
    state = ti(answer("1.2.3.4", abuse, acme))
    got = listed(state)
    assert (got.status, got.unknown_reason) == ("unknown", reason)
    assert intel.sentence(state, [got.as_dict()]) is None  # the step stays deferred


def test_a_cut_list_is_never_clean_and_a_hit_is_a_lower_bound() -> None:
    clean = ti(answer("1.2.3.4", {"no_match": FRESH}, {"no_match": FRESH}), cut=True)
    assert listed(clean).unknown_reason == "values_cut"
    assert listed(ti(cut=True)).unknown_reason == "values_cut"
    assert listed(ti()).unknown_reason == "no_indicators"
    hit = ti(answer("1.2.3.4", {"match": [{}]}, {"not_checked": FRESH}), listed=("1.2.3.4",),
             cut=True)  # fmt: skip
    got = listed(hit)
    assert (got.value, got.completeness) == (1, "lower_bound")
    assert intel.sentence(hit, [got.as_dict()]).startswith(  # type: ignore[union-attr]
        "Threat intel: at least 1 of 1 on a list (1.2.3.4)."
    )


def remote(status: str = "ok", rows: list[Any] | None = None, **extra: Any) -> tuple[Any, Any]:
    evidence = {"k1": {"task_key": "k1", "status": status, "template": "ti.lookup@1", **extra}}
    return evidence, {"k1": {"rows": rows or []}}


def row(value: str) -> dict[str, Any]:
    return {"_source": {"ioc_type": "ip", "ioc_value": value, "intel_source": "feodo"}}


def test_the_live_lookup_counts_in_the_reputation_answer() -> None:
    state = ti(answer("8.8.8.8", {"no_match": FRESH}, {"not_checked": FRESH}))
    evidence, snaps = remote(rows=[row("8.8.8.8")])
    got = listed(state, evidence, snaps)
    assert (got.value, got.status, got.completeness) == (1, "known", "exact")
    assert intel.sentence(state, [got.as_dict()]) == (
        "Threat intel: 1 of 1 on a list (and 1 from the live lookup)."
        " (abuse-ioc: fresh; acme-threat-intel: not checked)"
    )


def test_a_complete_live_miss_counts_as_checked_with_the_sources_freshness() -> None:
    fresh = ti(answer("8.8.8.8", {"no_match": FRESH}, {"not_checked": FRESH}))
    assert listed(fresh, *remote()).value == 0
    stale = ti(answer("8.8.8.8", {"no_match": FRESH}, {"not_checked": STALE}))
    assert listed(stale, *remote()).unknown_reason == "source_stale"
    unknown_age = ti(answer("8.8.8.8", {"no_match": FRESH}, {"not_checked": None}))
    assert listed(unknown_age, *remote()).unknown_reason == "source_stale"
    partial = remote(truncated=True)
    assert listed(fresh, *partial).unknown_reason == "source_not_checked"
    failed = remote(status="failed")
    assert listed(fresh, *failed).unknown_reason == "source_not_checked"


def test_values_are_cut_when_the_facts_do_not_show_them_all() -> None:
    fields = {"url.original": {"distinct": 9, "top": [["http://a.example/x", 1]]}}
    pairs, cut = intel._values([], fields, None, True)
    assert cut
    assert pairs == [("url", "http://a.example/x")]
    whole = {"url.original": {"distinct": 1, "top": [["http://a.example/x", 1]]}}
    assert intel._values([], whole, None, True)[1] is False
    assert intel._values([], whole, None, False)[1] is True  # not every alert read
    long = {"url.original": {"distinct": 1, "top": [["http://a.example/" + "x" * 90, 1]]}}
    assert intel._values([], long, None, True) == ([], True)  # cut by the facts: cannot match
    many = [("ip", f"8.8.{n // 256}.{n % 256}") for n in range(intel.MAX_VALUES + 1)]
    pairs, cut = intel._values(many, {}, None, True)
    assert (len(pairs), cut) == (intel.MAX_VALUES, True)


@pytest.mark.parametrize(
    ("path", "flat", "expected"),
    [
        ("url.path", ["attempted_paths", "description"], "attempted_paths"),
        ("source.ip", ["description", "report_id"], None),
        ("destination.port", ["report_id", "src_port", "destination_port"], "destination_port"),
        ("destination.port", ["report_id", "src_port"], None),  # the source port is no answer
        ("source.ip", ["source_ip", "destination_ip"], "source_ip"),
        ("ip", ["client_ip"], "client_ip"),
        ("dns.question.name", ["service_name", "rule_name"], None),  # found reviewing
        ("dns.question.name", ["service_name", "question_name"], "question_name"),
        ("destination.ip", ["client_ip"], None),  # a common leaf needs its parent
        ("url.path", ["attempted_paths"], "attempted_paths"),  # an uncommon one does not
    ],
)
def test_stand_ins_match_whole_words(path: str, flat: list[str], expected: str | None) -> None:
    assert _stand_in(path, flat) == expected


def test_web_follow_up_asks_only_for_a_real_address_and_starts_at_the_first_alert() -> None:
    from datetime import UTC, datetime

    from argus.context import web

    now = datetime(2026, 10, 13, 12, tzinfo=UTC)
    facts = {"first_event_at": "2026-10-13T09:50:30+00:00"}
    junk = {"source.ip": {"top": [["x" * 60, 3], ["-", 1]]}}
    assert web.tasks(facts, junk, now) == []  # never a validation error or a junk term
    (task,) = web.tasks(facts, {"source.ip": {"top": [["x", 3], ["203.0.113.9", 1]]}}, now)
    assert task.params.ip == "203.0.113.9"  # type: ignore[attr-defined]
    assert task.params.start == datetime(2026, 10, 13, 9, 50, tzinfo=UTC)  # type: ignore[attr-defined]
    assert task.params.end == datetime(2026, 10, 13, 11, tzinfo=UTC)  # type: ignore[attr-defined]


def test_a_zero_from_a_log_search_is_unknown_until_ingest_is_measured() -> None:
    from argus.context.evidence import SignalValue, from_logs

    def known(value: object) -> SignalValue:
        return SignalValue("x", 1, value, "known", None, "exact", ("k",))

    zero = from_logs(known(0))
    assert (zero.status, zero.unknown_reason, zero.evidence) == (
        "unknown", "ingest_not_verified", ("k",),
    )  # fmt: skip
    assert from_logs(known(0.0)).status == "unknown"
    assert from_logs(known(3)) == known(3)
    assert from_logs(known(False)) == known(False)  # a flag, not a count
    lower = SignalValue("x", 1, 2, "known", None, "lower_bound", ())
    assert from_logs(lower) == lower


def test_which_indicators_are_checked() -> None:
    from argus.assets.classify import IpClassifier

    special = "0.0.0.0"  # noqa: S104 - a special address, not a bind
    entities = [("ip", "8.8.8.8"), ("ip", "10.1.1.1"), ("ip", special), ("ip", "x"),
                ("domain", "Evil.Example."), ("host", "pc1"), ("user", "u")]  # fmt: skip
    fields = {
        "url.original": {"distinct": 1, "top": [["http://a.example/x", 1]]},
        "url.full": {"distinct": 1, "top": [["http://b.example/y", 1]]},
        "file.hash.sha256": {"distinct": 1, "top": [["A" * 64, 1]]},
        "file.hash.sha1": {"distinct": 1, "top": [["b" * 40, 1]]},
        "file.hash.md5": {"distinct": 1, "top": [["c" * 32, 1]]},
        "url.path": {"distinct": 1, "top": [["/z", 1]]},
    }
    pairs, cut = intel._values(entities, fields, IpClassifier(None), True)
    kinds = sorted({k for k, _ in pairs})
    assert kinds == ["domain", "hash", "ip", "url"]
    assert ("ip", "8.8.8.8") in pairs
    assert not any(v in ("10.1.1.1", special, "x") for _, v in pairs)
    assert ("domain", "evil.example") in pairs
    assert len([p for p in pairs if p[0] == "hash"]) == 3
    assert len([p for p in pairs if p[0] == "url"]) == 2
    assert cut is False
    exactly = [("ip", f"8.8.{n // 256}.{n % 256}") for n in range(intel.MAX_VALUES)]
    assert intel._values(exactly, {}, None, True) == (sorted(exactly), False)
    edge = {"url.original": {"distinct": 1, "top": [["http://a.example/" + "x" * 82, 1]]}}
    assert len("http://a.example/" + "x" * 82) == intel.VALUE_CHARS - 1
    assert intel._values([], edge, None, True)[1] is False  # 99 characters: not cut
    assert intel.LOOKUP_VALUES == 50


def test_remote_lookups_ask_only_what_the_cache_has_not_answered() -> None:
    state = ti(
        answer("8.8.8.8", {"no_match": FRESH}, {"not_checked": FRESH}),
        answer("9.9.9.9", {"no_match": FRESH}, {"no_match": FRESH}),
    )
    (task,) = intel.tasks(state)
    assert "8.8.8.8" in task.params.values  # type: ignore[attr-defined]
    assert "9.9.9.9" not in task.params.values  # type: ignore[attr-defined]
    many = ti(*(answer(f"8.8.{n // 256}.{n % 256}", {}, {"not_checked": None})
                for n in range(intel.LOOKUP_VALUES + 1)))  # fmt: skip
    assert len(intel.tasks(many)) == 2
    assert intel.tasks(ti()) == []


def test_sentences_name_up_to_five_and_their_sources() -> None:
    six = [f"8.8.8.{n}" for n in range(6)]
    match = {"match": [{}], "freshness": FRESH}
    state = ti(*(answer(v, match, {"no_match": FRESH}) for v in six), listed=tuple(six))
    got = listed(state)
    assert intel.sentence(state, [got.as_dict()]) == (
        "Threat intel: 6 of 6 on a list (8.8.8.0, 8.8.8.1, 8.8.8.2, 8.8.8.3, 8.8.8.4)."
        " (abuse-ioc: fresh; acme-threat-intel: fresh)"
    )
    assert intel.sentence(ti(), [got.as_dict()]) is None
    assert intel.sentence(state, []) is None


def test_freshness_of_a_match_counts_too() -> None:
    fresh_match = ti(answer("1.2.3.4", {"match": [{}], "freshness": FRESH}, {"no_match": FRESH}))
    assert intel._source_state(fresh_match["answers"], ABUSE) == "fresh"
    stale_match = ti(answer("1.2.3.4", {"match": [{}], "freshness": STALE}, {"no_match": FRESH}))
    assert intel._source_state(stale_match["answers"], ABUSE) == "stale"
    assert intel._source_state([], ABUSE) == "not_checked"
    mixed = [answer("1", {"no_match": FRESH}, {}), answer("2", {"not_checked": FRESH}, {})]
    assert intel._source_state(mixed, ABUSE) == "not_checked"
    assert intel._source_state(mixed, ABUSE, remote_checked=True) == "fresh"


def test_the_web_follow_up_is_asked_once_per_investigation() -> None:
    """D-070: a later run plans the earlier request again, whatever the time now."""
    from datetime import UTC, datetime

    from argus.context import web

    facts = {"first_event_at": "2026-10-13T09:50:30+00:00"}
    fields = {"source.ip": {"top": [["203.0.113.9", 1]]}}
    (first,) = web.tasks(facts, fields, datetime(2026, 10, 13, 12, tzinfo=UTC))
    stored = {"web.followups": first.params.model_dump(mode="json")}
    (later,) = web.tasks(facts, {"source.ip": {"top": [["198.51.100.7", 1]]}},
                         datetime(2026, 10, 14, 12, tzinfo=UTC), stored)  # fmt: skip
    assert later.params == first.params
    assert later.ref()["task_key"] == first.ref()["task_key"]
