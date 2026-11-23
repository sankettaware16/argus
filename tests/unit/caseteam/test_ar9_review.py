"""The findings of the adversarial review of AR9 (F1 to F13), each as a test that fails on the
code the review read. The reader here is the guard and the two scans the other text tests use;
the same texts are read by Kibana's own reader in test_kibana_parser.py where it is installed."""

from __future__ import annotations

import itertools
import re
from dataclasses import replace

import markdown_it
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from argus.caseteam import guard, render
from argus.caseteam.render import bold, cell, labelled, row, say, val
from argus.gateway.kibana.models import MAX_TEXT, utf16_len
from argus.incident import build
from argus.incident import model as m
from argus.responder import catalogue as cat
from argus.writer.render import escape, join, pieces, plain
from tests.unit.caseteam import kit as team
from tests.unit.incident import kit

pytestmark = pytest.mark.unit
CATALOGUE = cat.load()
PIPE = "\N{DIVIDES}"


def scanners(count: int = 16) -> m.IncidentReport:
    ctx = kit.ctx(catalogue=CATALOGUE, own_domains=("example.edu",))
    return build.build(kit.scanners(count=count), ctx)


def refused(text: str, allowed: tuple[str, ...] = ()) -> str:
    with pytest.raises(guard.GuardRefusal) as caught:
        guard.check(text, allowed)
    return str(caught.value)


# --------------------------------------------------------------------------- F1: bold and fences


def test_f1_the_evidence_heading_ends_its_bold_before_the_values_it_asked() -> None:
    report = team.amadey()
    asked = "http://198.51.100.7/x**![beacon](http://evil.example/p.png)**"
    line = report.evidence[0].model_copy(update={"asked": (asked,)})
    swapped = report.model_copy(update={"evidence": (line, *report.evidence[1:])})
    text = team.texts(swapped)["comment:evidence:1"]
    heading = next(ln for ln in text.split("\n") if ln.startswith("**E1 · "))
    assert re.match(r"^\*\*E1 · [^`*]+\*\* — ` ", heading), heading
    assert f"` {asked} `" in heading
    guard.check(text, team.CTX.allowed)


def test_f1_bold_is_never_put_around_a_fence() -> None:
    assert bold("E1 · title") == "**E1 · title**"
    assert bold("E1 · ` a ` b") == "E1 · ` a ` b"  # a value inside: no bold at all
    assert labelled("ARGUS's verdict:", "a true positive") == "**ARGUS's verdict: a true positive**"
    assert labelled("ARGUS's verdict:", "see ` x ` now") == "**ARGUS's verdict:** see ` x ` now"


@pytest.mark.parametrize(
    "text",
    [
        "**E1 · title — ` http://x/a**![b](http://evil.example/p.png)** `**",  # the review's repro
        "**a ` b**c ` d**",
        "x __a ` b__c ` d__ y",
        "~~a ` b~~c ` d~~",
        "**a\n` b**c ` d**",  # the paragraph goes on: bold may end on the next line
        "| H | H |\n|---|---|\n| **a ` b**c ` | d** |",
    ],
)
def test_f1_the_guard_refuses_a_code_span_inside_bold_or_strike_through(text: str) -> None:
    assert "bold or strike-through" in refused(text)


@pytest.mark.parametrize(
    "text",
    [
        "**E1 · title** — ` http://x/a**b ` and more",  # the bold ended before the span
        "**A** ` x**y ` **B**",  # a span between two bolds
        "x ` a**b ` y",  # a span with a mark, no bold at all
        "| Hypothesis | Kept? |\n|---|---|\n| ` a ` | **Kept** |",  # one cell each
        "**bold \\*\\* escaped** and ` c `",
    ],
)
def test_f1_the_guard_lets_bold_and_a_span_stand_apart(text: str) -> None:
    guard.check(text, ())


# --------------------------------------------------------------------------- F2: pipes in cells


def test_f2_a_pipe_in_a_value_in_a_cell_is_the_look_alike_never_a_backslash() -> None:
    assert cell(val("a|b")) == "` a" + PIPE + "b `"
    assert cell("plain | pipe") == "plain \\| pipe"
    assert cell("already \\| escaped") == "already \\| escaped"
    assert cell("\\\\|[x]") == "\\\\\\|[x]"  # an escaped backslash, then a real pipe
    assert cell("`` a`|b ``") == "`` a`" + PIPE + "b ``"
    assert cell(cell(val("a|b") + " | " + say("c|d"))) == cell(val("a|b") + " | " + say("c|d"))
    assert row("a", val("b|c"), say("d|e")).count("|") == 4 + 1 + 0 + 1 - 1  # the frame only


def test_f2_the_review_repros_no_longer_split_a_cell() -> None:
    report = team.amadey()
    value = "http://198.51.100.7/a\\\\|[Open the report](http://evil.example/login)"
    mark = report.indicators[0].model_copy(update={"value": value})
    swapped = report.model_copy(update={"indicators": (mark, *report.indicators[1:])})
    description = team.texts(swapped)["open"]
    guard.check(description, team.CTX.allowed)
    line = next(ln for ln in description.split("\n") if ln.startswith("| Indicators |"))
    assert len(guard._cells(line)) == 2
    scan = scanners()
    target = scan.targets[0].model_copy(
        update={"answered": 1, "served": ("/x\\\\|[click](http://evil.example/p)",)}
    )
    bad = scan.model_copy(update={"targets": (target, *scan.targets[1:])})
    devices = team.texts(bad)["comment:devices:1"]
    guard.check(devices, team.CTX.allowed)
    served = next(ln for ln in devices.split("\n") if "[click]" in ln)
    assert len(guard._cells(served)) == 7


def test_f2_the_facts_table_and_the_actions_put_every_sentence_through_cell() -> None:
    report = team.amadey()
    head = report.header.model_copy(update={"detected_by": "Rules: a|b (3 alerts) and ` c|d `"})
    standing = report.summary.model_copy(update={"standing_words": "still going | on"})
    swapped = report.model_copy(update={"header": head, "summary": standing})
    with team.no_check():
        description = team.texts(swapped)["open"]
    guard.check(description, team.CTX.allowed)
    for ln in description.split("\n"):
        if ln.startswith("| Detected by |") or ln.startswith("| Still going on |"):
            assert len(guard._cells(ln)) == 2, ln


@pytest.mark.parametrize(
    "text",
    [
        "| a | b |\n|---|---|\n| 1 | ` x | y ` |",  # a raw pipe in a span splits the cell
        "| a | b |\n|---|---|\n| 1 | 2 | 3 |",
        "| a | b |\n|---|---|\n| 1 |",
        "| a | b |\n|---|---|\n| 1 | 2 |\nnext line | with a pipe",  # read as one more row
        "| a | b |\n|---|---|---|",
        "| a | b |\n|---|---|\n| 1 | \\\\| x |",  # an escaped backslash, then a real pipe
    ],
)
def test_f2_the_guard_refuses_a_table_row_of_another_width(text: str) -> None:
    assert "table" in refused(text)


@pytest.mark.parametrize(
    "text",
    [
        "| a | b |\n|---|---|\n| 1 | 2 |",
        "| a | b |\n|---|---|\n| 1 \\| x | ` y ` |",
        "| | |\n|---|---|\n| k | v |\n\nafter the table | with a pipe",
        "| a | b |\n|:--|--:|\n|  |  |",
    ],
)
def test_f2_the_guard_lets_a_well_formed_table_stand(text: str) -> None:
    guard.check(text, ())


# --------------------------------------------------------------------------- F3: adjacent fences


def test_f3_an_address_with_its_local_part_is_one_code_span() -> None:
    assert say("alice@example.edu signed in from 10.1.2.3") == (
        "` alice@example.edu ` signed in from ` 10.1.2.3 `"
    )
    assert say("mail bob@example.com.") == "mail ` bob@example.com `\\."
    assert plain("a@b.example") == "` a@b.example `"
    assert join([("a@", True), ("b.example", True)]) == "` a@b.example `"
    assert join([("a", True), (" ", False), ("b", True)]) == "` a ` ` b `"
    assert pieces("x a@ y") == [
        ("x", False),
        (" ", False),
        ("a@", True),
        (" ", False),
        ("y", False),
    ]


def test_f3_a_backtick_in_the_value_does_not_unbalance_the_sentence() -> None:
    text = say("a@http://x/a`[click](http://evil.example) tail")
    assert text.count("`") % 2 == 0 or "``" in text
    guard.check(f"x {text} y", ())  # no longer a refusal that holds the step
    assert "[click]" not in guard._scan(text, [])


def code_spans(text: str) -> list[tuple[int, int]]:
    found: list[tuple[int, int]] = []
    i = 0
    while i < len(text):
        if text[i] == "\\":
            i += 2
        elif text[i] == "`":
            end = guard._code_end(text, i)
            if end > 0:
                found.append((i, end))
                i = end
            else:
                while i < len(text) and text[i] == "`":
                    i += 1
        else:
            i += 1
    return found


ALPHA = st.text(alphabet=list("`|*_~\\[]()<>#!@:/.- \t&=ab01"), max_size=10)
ADDRESSES = st.sampled_from(
    [
        "alice@example.edu",
        "bob@example.com",
        "10.1.2.3",
        "a.b.example",
        "/x/y.z",
        "http://h.example/p",
    ]
)


@given(ALPHA, ADDRESSES, ALPHA)
@settings(deadline=None)
def test_f3_a_sentence_around_an_address_has_no_two_spans_side_by_side(
    prefix: str, address: str, suffix: str
) -> None:
    text = say(prefix + address + suffix, 400)
    line = f"x {text} y"
    guard.check(line, ())
    reader = markdown_it.MarkdownIt("commonmark", {"html": True}).enable(["table", "strikethrough"])
    kinds = {child.type for token in reader.parse(line) for child in token.children or []}
    assert kinds <= {"text", "code_inline", "softbreak"}, (line, kinds)
    spans = code_spans(line)
    for (_, ends), (starts, _) in itertools.pairwise(spans):
        assert ends != starts, line
    outside = line
    for start, end in reversed(spans):
        outside = outside[:start] + " " + outside[end:]
    assert "`" not in outside.replace("\\`", "")  # every backtick is in a span or escaped


# --------------------------------------------------------------------------- F11, F13


def test_f11_a_sentence_of_equals_signs_is_fenced_and_the_guard_refuses_an_underline() -> None:
    assert say("===") == "` === `"
    assert plain("=") == "` = `"
    assert escape("====") == "` ==== `"
    assert say("a = b") == "a = b"
    assert "heading underline" in refused("E1 title\n===")
    assert "heading underline" in refused("E1 title\n---")
    guard.check("E1 title\n\n| a |\n|---|\n| 1 |", ())


def test_f13_a_path_is_one_code_span_not_domain_shaped_fragments() -> None:
    assert say("/wp-content/plugins/x/readme.txt") == "` /wp-content/plugins/x/readme.txt `"
    assert say("asked for /admin/login.php?id=1, then left") == (
        "asked for ` /admin/login.php?id=1 `, then left"
    )
    assert say("(/etc/passwd)") == "\\(` /etc/passwd `\\)"
    assert say("example.edu/admin/login.php") == "` example.edu/admin/login.php `"
    assert say("10.1.2.3/24 and 1 / 2 and and/or") == "` 10.1.2.3/24 ` and 1 / 2 and and/or"
    assert say("a / b") == "a / b"


# --------------------------------------------------------------------------- F5: wide tables


def wide_targets(
    count: int, paths: int, width: int, base: m.IncidentReport | None = None
) -> m.IncidentReport:
    base = base or scanners()
    template = base.targets[0]
    rows = tuple(
        template.model_copy(
            update={
                "value": f"site{n}.example.edu",
                "served": tuple(f"/{n}/{k}/" + "p" * (width - 8) for k in range(paths)),
                "answered": paths,
            }
        )
        for n in range(count)
    )
    return base.model_copy(update={"targets": rows, "targets_total": count})


def test_f5_twenty_targets_of_five_long_paths_pass_the_guard_row_by_row() -> None:
    """The review's repro: 20 targets x 5 paths of 185 characters was one unit cut at 17,000
    characters, in the middle of a code span, and the guard refused the whole comment."""
    report = wide_targets(20, 5, 185)
    part = render.devices_part(report)
    rows = [u for u in part.units if u.startswith("| ` site") or "### Campus targets" in u]
    assert len(rows) == 20  # one unit for each target row
    assert sum(utf16_len(u) for u in part.units) > render.MAX_UNIT  # the old unit would be cut
    texts, left = render.comments_of(part)
    assert left == 0
    for body in texts:
        assert utf16_len(body) <= MAX_TEXT
        guard.check(body, ())
    found = [ln for body in texts for ln in body.split("\n") if ln.startswith("| ` site")]
    assert len(found) == 20
    assert all(ln.count("p" * 150) == 5 for ln in found)  # no path is cut


def test_f5_a_comment_that_begins_at_a_later_row_repeats_the_head_of_its_table() -> None:
    report = wide_targets(20, 5, 195, base=wide_actors(scanners(25)))
    part = render.devices_part(report)
    assert sum(utf16_len(u) for u in part.units) > render.SPLIT_AT  # it must split
    texts, left = render.comments_of(part)
    assert left == 0
    assert len(texts) >= 2
    for body in texts:
        guard.check(body, ())
    for body in texts[1:]:
        first = next(ln for ln in body.split("\n") if ln.startswith("|"))
        assert first.startswith(("| Target |", "| Address |")), first
    rows = [ln for body in texts for ln in body.split("\n") if ln.startswith("| ` site")]
    assert len(rows) == 20


def wide_actors(base: m.IncidentReport) -> m.IncidentReport:
    """Every outside actor with a long intel text and five long served paths."""
    long_intel = "VirusTotal: 9 of 94 engines flag this IP; " + "Shodan: open ports 22, 80 " * 12
    actors = tuple(
        a.model_copy(
            update={
                "intel": long_intel[:300],
                "answered": 5,
                "served": tuple(f"/{k}/" + "q" * 180 for k in range(5)),
            }
        )
        for a in base.actors
    )
    return base.model_copy(update={"actors": actors})


def test_f5_twenty_five_actors_of_wide_rows_do_the_same() -> None:
    report = wide_actors(scanners(25))
    texts, left = render.comments_of(render.devices_part(report))
    assert left == 0
    assert len(texts) >= 2
    for body in texts:
        guard.check(body, ())
        assert utf16_len(body) <= MAX_TEXT
    heads = [next(ln for ln in b.split("\n") if ln.startswith("|")) for b in texts[1:]]
    assert all(h.startswith(("| Address |", "| Target |")) for h in heads)


def test_f5_an_update_of_one_row_of_a_later_table_carries_that_tables_head() -> None:
    report = wide_targets(3, 1, 40)
    part = render.devices_part(report)
    last = part.units[2]  # the third target row (unit 0 starts the table)
    assert last.startswith("| ` site2")
    texts, _ = render.comments_of(part, [last])
    assert "| Target | Kind |" in texts[0]
    assert texts[0].index("| Target |") < texts[0].index("site2")


def test_f5_cap_cuts_at_a_line_and_never_inside_a_span_or_a_fence() -> None:
    long_unit = "head\n" + "\n".join(f"| ` {n} " + "x" * 90 + " ` |" for n in range(400))
    capped = render._cap(long_unit)
    assert utf16_len(capped) <= render.MAX_UNIT
    assert capped.endswith("…")
    assert all(ln.startswith("|") or ln in ("head", "…") for ln in capped.split("\n"))
    fenced = "```\n" + "\n".join("y" * 90 for _ in range(400)) + "\n```"
    out = render._cap(fenced)
    assert utf16_len(out) <= render.MAX_UNIT
    assert out.split("\n")[-2] == "```"  # the fence is closed again
    one_line = "see " + " ".join(f"` v{n} `" for n in range(6_000))
    cut = render._cap(one_line)
    assert utf16_len(cut) <= render.MAX_UNIT
    guard.check(cut, ())  # no span is cut open
    astral = "\U0001d11e" * 9_000  # 18,000 UTF-16 units in 9,000 characters
    assert utf16_len(render._cap("a " + astral)) <= render.MAX_UNIT


# --------------------------------------------------------------------------- F8, F9, F10, F12


def test_f8_the_targets_that_were_cut_are_not_said_to_be_in_the_pdf() -> None:
    base = wide_targets(3, 1, 40)
    report = base.model_copy(update={"targets_total": 27})
    texts, _ = render.comments_of(render.devices_part(report))
    body = "\n".join(texts)
    assert "24 more are not listed" in body
    assert "PDF" not in body


def test_f9_the_affected_row_counts_the_actors_not_the_ones_listed() -> None:
    report = scanners(30)
    assert len(report.actors) == 25
    assert report.outsiders_total == 30
    assert "attacked by 30 outside addresses" in render.affected_words(report)
    note = [u for u in render.devices_part(report).units if "outside addresses are shown" in u]
    assert note == ["\n25 of 30 outside addresses are shown; the other 5 are not listed."]
    exact = scanners(16)
    assert exact.outsiders_total == 16
    assert not [u for u in render.devices_part(exact).units if "are shown" in u]


def test_f10_a_person_review_is_said_as_a_review_with_its_outcome() -> None:
    ctx = kit.ctx(catalogue=CATALOGUE, own_domains=("example.edu",))
    for outcome, words in (
        ("true_positive", "a true positive"),
        ("benign_expected", "benign: expected activity"),
        ("rule_false_positive", "a false positive of the rule"),
    ):
        facts = kit.scanners()
        reviewed = replace(
            facts, members=tuple(replace(x, reviewed_outcome=outcome) for x in facts.members)
        )
        report = build.build(reviewed, ctx)
        assert report.verdict.kind == "person"
        assert f"a person reviewed the report ({words})" in report.header.opened_in
        assert "confirmed the report" not in report.header.opened_in


def test_f12_a_count_read_from_a_capped_sample_is_said_as_at_least() -> None:
    assert render._answers(20, ["/.env"], exact=False) == "yes (20+): ` /.env `"
    assert render._answers(2, [], exact=True) == "yes (2)"
    assert render._answers(0, [], exact=False) == "none seen"
    assert render._answers(None, [], exact=False) == "not checked"


def widths_of(body: str) -> list[tuple[int, int]]:
    """(width of the header, width of each row under it) for every table in a text."""
    lines = body.split("\n")
    found: list[tuple[int, int]] = []
    for i, ln in enumerate(lines):
        if re.fullmatch(r"\|[:\-| ]+\|", ln) and i > 0:
            head = len(guard._cells(lines[i - 1]))
            j = i + 1
            while j < len(lines) and lines[j].startswith("| "):
                found.append((head, len(guard._cells(lines[j]))))
                j += 1
    return found


def test_every_row_of_every_comment_has_as_many_cells_as_its_header() -> None:
    for report in (team.amadey(), team.git(), scanners()):
        for body in team.texts(report).values():
            guard.check(body, team.CTX.allowed)
            assert all(head == cells for head, cells in widths_of(body)), body[:80]
