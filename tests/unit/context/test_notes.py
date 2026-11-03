"""Runbooks derived from the rules' notes (R10, D-058): every step has exactly one outcome."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.context import notes
from argus.context.display import DIGEST_CHARS, digest, entry, registry, sentence

pytestmark = pytest.mark.unit

NOTE = """### Investigation Steps
1. Identify the internal host (`source.ip`) and owner.
2. Check `destination.ip`, `destination.as.organization.name` and `url.path`.
   A second line of the same step.
3. Reputation-check the IP (AbuseIPDB, VirusTotal).
4. How many internal hosts reach this IP in the last 24h?
5. Volume from one IP = scanner; block the IP.
6. Look at `config.php.bak` and `made.up.field`.

### False positives
1. Not a step.
"""


def test_steps_are_parsed_numbered_and_their_fields_found() -> None:
    steps = notes.steps(NOTE)
    assert [s.number for s in steps] == [1, 2, 3, 4, 5, 6]  # the false positives are not steps
    assert steps[0].fields == ("source.ip",)
    assert steps[1].fields == ("destination.ip", "destination.as.organization.name", "url.path")
    assert "A second line of the same step." in steps[1].text
    assert steps[5].fields == ()  # neither is under a known root
    assert notes.steps(NOTE, frozenset({"made"}))[5].fields == ("made.up.field",)
    assert notes.steps(None) == notes.steps("") == []
    assert [s.number for s in notes.steps("1. a\n2. b")] == [1, 2]  # no header: every item
    restart = "### Investigation Steps\n**Phase 1**\n1. a\n2. b\n**Phase 2**\n1. c"
    assert [s.text for s in notes.steps(restart)] == ["a", "b", "c"]  # numbered in order


def test_every_step_gets_one_outcome() -> None:
    facts = {
        "source.ip": {"distinct": 1, "top": [["10.0.0.1", 3]]},
        "destination.ip": {"distinct": 2, "top": [["1.1.1.1", 2]]},
    }
    got = [notes.outcome(s, facts, owner_known=True) for s in notes.steps(NOTE)]
    assert [o["status"] for o in got] == [
        "answered",
        "unknown",
        "deferred",
        "deferred",
        "manual",
        "manual",
    ]
    assert got[1]["sentence"] == (
        "Could not check: no alert has destination.as.organization.name, url.path."
    )
    assert got[2]["needs"] == ["reputation"]
    assert "a threat-intelligence lookup" in got[2]["sentence"]
    assert got[3]["needs"] == ["prevalence", "log_pivot"]
    assert got[0]["shown"] == ["source.ip"]
    without_owner = notes.outcome(notes.steps("1. Identify the owner.")[0], {})
    assert without_owner["status"] == "manual"
    owner = notes.outcome(notes.steps("1. Identify the owner.")[0], {}, owner_known=True)
    assert owner["status"] == "answered"
    told = notes.outcome(notes.steps(NOTE)[2], facts, {"reputation": "On no list."})
    assert (told["status"], told["sentence"], told["needs"]) == ("answered", "On no list.", [])
    both = notes.outcome(
        notes.steps("1. How many hosts? Reputation?")[0], {}, {"reputation": "On no list."}
    )
    assert both["status"] == "deferred"
    assert both["sentence"].endswith(" On no list.")


ROOTS = [
    "agent", "client", "cloud", "container", "destination", "dns", "ecs", "email", "error",
    "event", "file", "group", "host", "http", "log", "network", "observer", "process",
    "related", "rule", "server", "service", "source", "threat", "tls", "url", "user",
    "user_agent", "vulnerability", "nginx", "squid", "postfix", "kibana",
]  # fmt: skip


@pytest.mark.parametrize("root", ROOTS)
def test_every_known_root_names_a_field(root: str) -> None:
    (step,) = notes.steps(f"1. Check `{root}.name`, `{root}.a.b:value` and `nope.x`.")
    assert step.fields == (f"{root}.name", f"{root}.a.b")
    assert frozenset(ROOTS) == notes.ROOTS


@pytest.mark.parametrize(
    ("text", "needed"),
    [
        ("Check its reputation", ["reputation"]),
        ("Look it up on VirusTotal", ["reputation"]),
        ("AbuseIPDB score", ["reputation"]),
        ("GreyNoise tags", ["reputation"]),
        ("Search threat intel", ["reputation"]),
        ("Search threatintel", ["reputation"]),
        ("Is it an IOC", ["reputation"]),
        ("Is it periodic", ["timeline"]),
        ("What interval", ["timeline"]),
        ("A beacon?", ["timeline"]),
        ("Regular traffic", ["timeline"]),
        ("Its cadence", ["timeline"]),
        ("It calls every 5 minutes", ["timeline"]),
        ("How many hosts", ["prevalence"]),
        ("Distinct sources", ["prevalence"]),
        ("Other internal hosts", ["prevalence"]),
        ("Other hosts", ["prevalence"]),
        ("Fan-out", ["prevalence"]),
        ("The same URL", ["prevalence"]),
        ("The same IP", ["prevalence"]),
        ("Pivot to Discover", ["log_pivot"]),
        ("In the last 24h", ["log_pivot"]),
        ("In the last 6 h", ["log_pivot"]),
        ("Filter the index", ["log_pivot"]),
        ("Read the access log", ["log_pivot"]),
        ("Read the logs", ["log_pivot"]),
        ("Did it answer 200", ["log_pivot"]),
        ("Did it respond", ["log_pivot"]),
        ("The response", ["log_pivot"]),
        ("What it returned", ["log_pivot"]),
        ("Catalogue it", []),
        ("Blogs say", []),
    ],
)
def test_what_a_step_needs(text: str, needed: list[str]) -> None:
    assert notes.needs(text) == needed


def test_exact_sentences_of_each_outcome() -> None:
    facts = {"source.ip": {"distinct": 1, "top": [["10.0.0.1", 3]]},
             "url.path": {"distinct": 1, "top": [["/", 1]]}}  # fmt: skip

    def said(text: str, **kw: object) -> tuple[str, str]:
        out = notes.outcome(notes.steps("1. " + text)[0], facts, **kw)  # type: ignore[arg-type]
        assert set(out) == {"number", "text", "fields", "shown", "status", "sentence", "needs"}
        assert (out["number"], out["text"]) == (1, text)
        return out["status"], out["sentence"]

    assert said("Is it periodic?") == ("deferred", "Not checked yet: needs proxy-log statistics.")
    assert said("Pivot to the logs.") == (
        "deferred", "Not checked yet: needs a search of the web and proxy logs.",
    )  # fmt: skip
    assert said("Reputation? How many hosts?") == (
        "deferred",
        "Not checked yet: needs a threat-intelligence lookup and proxy-log statistics.",
    )
    assert said("Block it.") == ("manual", "For a person to decide or do.")
    assert said("Block `source.ip`.") == ("answered", "Answered from the alerts: see source.ip.")
    assert said("See `source.ip` and `url.path`.") == (
        "answered", "Answered from the alerts: see source.ip, url.path.",
    )  # fmt: skip
    assert said("Who is it?", owner_known=True) == ("answered", "Answered from the alerts.")
    assert said("Think about it.") == ("manual", "No field to check: for a person.")
    out = notes.outcome(notes.steps("1. See `source.ip` and `host.name`.")[0], facts)
    assert out["fields"] == ["source.ip", "host.name"]


def test_long_steps_are_cut_and_notes_hash_as_utf8() -> None:
    (step,) = notes.steps("1. " + "x" * 700)
    assert len(step.text) == notes.STEP_CHARS == 600
    import hashlib

    assert notes.note_hash(None) == notes.note_hash("") == hashlib.sha256(b"").hexdigest()
    assert notes.note_hash("é") == hashlib.sha256("é".encode()).hexdigest()
    with pytest.raises(AttributeError):
        step.text = "changed"  # type: ignore[misc]


@given(st.text(max_size=400))
def test_any_note_parses_and_every_step_has_a_status(note: str) -> None:
    for step in notes.steps(note):
        assert notes.outcome(step, {})["status"] in ("answered", "deferred", "manual", "unknown")
        assert len(step.text) <= notes.STEP_CHARS


def test_the_display_registry_covers_every_signal_and_reads_plainly() -> None:
    names = [
        "alert_count",
        "duplicate_count",
        "late_arrivals",
        "span_minutes",
        "related_investigations",
        "continues_previous_day",
        "entities.ip",
        "entities.domain",
        "steps.answered",
        "steps.deferred",
        "steps.manual",
        "steps.unknown",
    ]
    assert all(entry(n) is not None for n in names), [n for n in names if entry(n) is None]
    assert entry("nope") is None
    assert entry("nope.x") is None
    known = {"name": "alert_count", "status": "known", "value": 5, "completeness": "exact"}
    assert sentence(known) == "Alerts: 5 alerts"
    assert sentence({**known, "completeness": "lower_bound"}) == "Alerts: at least 5 alerts"
    flag = {"name": "continues_previous_day", "status": "known", "value": False}
    assert sentence(flag) == "Continues from yesterday: no"
    lost = {
        "name": "related_investigations",
        "status": "unknown",
        "unknown_reason": "supernode_entities",
    }
    assert sentence(lost) == "Related investigations: could not be told (supernode entities)"
    assert sentence({"name": "x.y", "status": "known", "value": 1}) == "x.y: 1"
    assert set(registry()) >= {"alert_count", "entities.*"}


def test_the_digest_is_bounded_and_deterministic() -> None:
    body = {
        "facts": {"rule_name": "R", "alert_count": 3, "group_key": "k", "severity": "high"},
        "report": {
            "steps": [
                {
                    "number": n,
                    "status": "deferred",
                    "text": "x" * 500,
                    "sentence": "Not checked yet.",
                }
                for n in range(1, 13)
            ]
        },
        "context": {
            "pack": {
                "fields": {f"f{n}.x": {"distinct": 2, "top": [["v" * 90, 1]]} for n in range(30)}
            }
        },
        "local_signals": [{"name": "alert_count", "status": "known", "value": 3}],
    }
    text = digest({"body": body})
    assert len(text) <= DIGEST_CHARS
    assert text == digest(body)
    assert text.startswith("Rule: R\n3 alerts from")
    assert "1. [deferred]" in text
    assert "no investigation steps" in digest({"facts": {}, "report": {"steps": []}})


def test_the_digest_exactly() -> None:
    from argus.context.display import Entry

    entries = {
        "ti.listed": Entry(label="On a list", sentence="{value} listed", how_to_read="h"),
        "entities.*": Entry(label="Distinct {part}", sentence="{value}", how_to_read="h"),
        "nat.hint": Entry(label="NAT", sentence="{value}", how_to_read="h"),
    }
    dossier = {"body": {
        "facts": {"rule_name": "Rule A", "rule_id": "r1", "alert_count": 3,
                  "first_event_at": "2026-10-13T00:00:00+00:00",
                  "last_event_at": "2026-10-13T01:00:00+00:00", "group_key": "source.ip=1",
                  "severity": "high", "risk_score": 73.0},
        "report": {"steps": [{"number": 1, "status": "answered", "text": "x" * 170,
                              "sentence": "Answered from the alerts."}]},
        "context": {"pack": {"fields": {
            f"f{n}": {"distinct": 5, "top": [["a", 3], ["b", 2], ["c", 1], ["d", 1], ["e", 1]]}
            for n in range(13)}}},
        "local_signals": [{"name": "entities.ip", "status": "known", "value": 2}],
        "signals": [
            {"name": "ti.listed", "status": "known", "value": 1, "completeness": "lower_bound"},
            {"name": "nat.hint", "status": "known", "value": True},
            {"name": "nat.hint", "status": "known", "value": False},
            {"name": "ti.listed", "status": "unknown", "unknown_reason": "source_stale"},
            {"name": "ti.listed", "status": "unknown"},
            {"name": "no.entry", "status": "known", "value": 4},
        ],
    }}  # fmt: skip
    lines = digest(dossier, entries).split("\n")
    assert lines[:5] == [
        "Rule: Rule A",
        "3 alerts from 2026-10-13T00:00:00+00:00 to 2026-10-13T01:00:00+00:00 (UTC); key"
        " source.ip=1",
        "Severity high, risk 73.0",
        "What ARGUS checked (the rule's investigation steps):",
        "1. [answered] " + "x" * 160,
    ]
    assert lines[5] == "   Answered from the alerts."
    assert lines[6] == "Key facts:"
    assert lines[7] == "- f0: 5 distinct: a (3), b (2), c (1), d (1)"
    assert lines[18] == "- f11: 5 distinct: a (3), b (2), c (1), d (1)"
    assert lines[19:] == [
        "- Distinct IP addresses: 2",
        "- On a list: at least 1 listed",
        "- NAT: yes",
        "- NAT: no",
        "- On a list: could not be told (source stale)",
        "- On a list: could not be told (unknown)",
        "- no.entry: 4",
    ]
    no_steps = digest({"body": {"facts": {"rule_id": "r9"}, "report": {"steps": []}}}, entries)
    assert no_steps.split("\n")[0] == "Rule: r9"
    assert no_steps.split("\n")[-1] == "The rule's note has no investigation steps."
    bare = digest({"facts": {"rule_id": "r9"}}, entries)
    assert "no investigation steps" not in bare
    exact = {"body": {"facts": {"rule_name": "y" * (DIGEST_CHARS - 6)}}}
    first = digest(exact, entries).split("\n")[0]
    assert len(first) == DIGEST_CHARS
    long = {"body": {"facts": {"rule_name": "y" * DIGEST_CHARS}}}
    out = digest(long, entries)
    assert (len(out), out[-1]) == (DIGEST_CHARS, "…")
    assert DIGEST_CHARS == 4800


@pytest.mark.parametrize(
    ("field", "size"), [("label", 80), ("sentence", 200), ("how_to_read", 300)]
)
def test_registry_entries_are_bounded(field: str, size: int) -> None:
    from pydantic import ValidationError

    from argus.context.display import Entry

    good = {"label": "a", "sentence": "b", "how_to_read": "c"}
    Entry(**{**good, field: "x" * size})
    with pytest.raises(ValidationError):
        Entry(**{**good, field: "x" * (size + 1)})
    with pytest.raises(ValidationError):
        Entry(**{**good, field: ""})
    with pytest.raises(ValidationError):
        Entry(**good, extra="no")  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        Entry(**good).label = "changed"  # type: ignore[misc]


def test_a_pattern_signature_includes_what_the_steps_look_at() -> None:
    """D-072: found reviewing: printer counters and call-backs were one group of 567."""
    from argus.context.display import FEW, signature

    def body(dest: str, src: str, paths: int = 1) -> dict[str, object]:
        return {
            "report": {"steps": [{"number": 1, "status": "deferred",
                                  "fields": ["destination.ip", "source.ip", "url.path"]}]},
            "context": {"pack": {"fields": {
                "destination.ip": {"distinct": 1, "top": [[dest, 3]]},
                "source.ip": {"distinct": 1, "top": [[src, 3]]},
                "url.path": {"distinct": paths, "top": [[f"/p{n}", 1] for n in range(paths)]},
            }}},
            "signals": [{"name": "ti.listed", "status": "known", "value": 0}],
        }  # fmt: skip

    printer, _ = signature("r1", ["source.ip"], body("108.163.133.79", "10.0.0.1"))
    same, common = signature("r1", ["source.ip"], body("108.163.133.79", "10.0.0.2"))
    other, _ = signature("r1", ["source.ip"], body("139.84.211.146", "10.0.0.1"))
    assert printer == same  # the grouping key (source.ip) does not split
    assert printer != other  # what the steps look at does
    assert common == [("destination.ip", ["108.163.133.79"]), ("url.path", ["/p0"])]
    many, shared = signature("r1", ["source.ip"], body("1.1.1.1", "10.0.0.1", paths=FEW + 1))
    assert [f for f, _ in shared] == ["destination.ip"]  # too many values: not a signature
    assert many[:3] == ("r1", ((1, "deferred"),), False)
    listed = body("1.1.1.1", "10.0.0.1")
    listed["signals"] = [{"name": "ti.listed", "status": "known", "value": 2}]
    assert signature("r1", [], listed)[0][2] is True
    assert signature("r1", [], {})[0] == ("r1", (), False, ())
