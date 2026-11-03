"""Agents as Markdown (Q-H1): the strict loader. Every refusal with its reason: characters,
layout, the header's YAML subset, fields, the binding (kind, task, output, widening), the pin
(file and prompt, byte for byte) and the enabled version. Then properties: no edited byte of
a pinned file ever loads; any narrowing within the binding loads structurally and any
widening is refused; nothing but AgentError ever comes out of the loader."""

from __future__ import annotations

import os
import re
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from argus.agent import catalogue, loader, registry
from argus.agent.loader import AgentError, load
from argus.agent.registry import BINDINGS, ENABLED, PINS, Kind, Limits, Pin, Trigger
from argus.llm.providers import Tier

FILES = {name: (loader.DIRECTORY / f"{name}.md").read_text(encoding="utf-8") for name in BINDINGS}
FAST = settings(suppress_health_check=[HealthCheck.too_slow], deadline=None)
# The agents agent@1 loads: the coordinator and its specialists. Any other bound agent (the
# responder, Q-H2) is judged by the survey and never refuses these.
FAMILY = sorted({registry.COORDINATOR, *BINDINGS[registry.COORDINATOR].specialists})


def copy(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    for name, text in FILES.items():
        (directory / f"{name}.md").write_text(text, encoding="utf-8")
    return directory


@contextmanager
def agents_dir() -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="argus-agents-") as tmp:
        yield copy(Path(tmp) / "agents")


def header(text: str, field: str, value: str | None) -> str:
    """``text`` with the header line of ``field`` set to ``value`` (None: removed; a field
    not there yet is added before the closing fence)."""
    lines = text.split("\n")
    end = lines.index("---", 1)
    for i in range(1, end):
        if lines[i].startswith(f"{field}:"):
            if value is None:
                del lines[i]
            else:
                lines[i] = f"{field}: {value}"
            return "\n".join(lines)
    assert value is not None, field
    lines.insert(end, f"{field}: {value}")
    return "\n".join(lines)


def refused(directory: Path, name: str, text: str | bytes, **kw: Any) -> str:
    path = directory / f"{name}.md"
    if isinstance(text, bytes):
        path.write_bytes(text)
    else:
        path.write_text(text, encoding="utf-8", newline="")
    with pytest.raises(AgentError) as caught:
        load(directory, **kw)
    return str(caught.value)


def structural(directory: Path) -> loader.Agents:
    return load(directory, pins=None, enabled=None)


# -- the repository's files ---------------------------------------------------------------------


def test_the_repositorys_agents_load_pinned_and_enabled() -> None:
    agents = load()
    assert sorted(agents.by_name) == ["intel", "investigator", "proxy", "web"]
    lead = agents.coordinator
    assert (lead.name, lead.kind, lead.version, lead.task, lead.output, lead.tier) == (
        "investigator", Kind.COORDINATOR, "coordinator@4", "assess.coordinator", "answer@1",
        Tier.MEDIUM,
    )  # fmt: skip
    assert lead.tools == ("proxy.host", "proxy.destination", "web.followups", "ti.lookup",
                          "outside.reputation", "outside.server")  # fmt: skip
    assert lead.specialists == ("web", "proxy", "intel")
    assert lead.triggers == {Trigger.ENGINE_NO_DECISION, Trigger.PERSON_REQUEST}
    assert lead.budget == Limits(rounds=4, tools=12, calls=8, consults=2, seconds=240.0)
    assert isinstance(lead.budget.seconds, float)  # 240, written as an int, is 240.0
    assert list(agents.specialists) == ["web", "proxy", "intel"]
    tools = {"web": ("web.followups",), "proxy": ("proxy.host", "proxy.destination"),
             "intel": ("ti.lookup", "outside.reputation", "outside.server")}  # fmt: skip
    versions = {"web": "specialist@1", "proxy": "specialist@1", "intel": "specialist@2"}
    for name, definition in agents.specialists.items():
        assert definition.kind is Kind.SPECIALIST
        assert (definition.version, definition.task, definition.output) == (
            versions[name], "assess.specialist", "notes@1")  # fmt: skip
        assert definition.tier is Tier.SMALL
        assert definition.tools == tools[name]
        assert definition.specialists == ()
        assert definition.triggers == {Trigger.COORDINATOR_CONSULT}
        assert definition.budget is None
        assert definition.prompt == definition.instructions.replace(
            "{tools}", catalogue.lines(tools[name])
        )
    assert agents.takes(Trigger.ENGINE_NO_DECISION)
    assert agents.takes(Trigger.PERSON_REQUEST)
    assert not agents.takes(Trigger.COORDINATOR_CONSULT)
    for name, definition in agents.by_name.items():
        pin = PINS[name][definition.version]
        assert (definition.file_sha256, definition.prompt_sha256) == (
            pin.file_sha256, pin.prompt_sha256)  # fmt: skip
        assert ENABLED[name] == definition.version


def test_a_definition_and_the_agents_are_values() -> None:
    agents = load()
    with pytest.raises(AttributeError):
        agents.coordinator.version = "coordinator@4"  # type: ignore[misc]
    with pytest.raises(TypeError):
        agents.by_name["web"] = agents.coordinator  # type: ignore[index]
    with pytest.raises(TypeError):
        agents.specialists["dns"] = agents.coordinator  # type: ignore[index]


# -- the directory ------------------------------------------------------------------------------


def test_the_directory_holds_one_file_per_bound_agent(tmp_path: Path) -> None:
    d = copy(tmp_path / "agents")
    (d / ".investigator.md.swp").write_text("x")  # an editor's: left alone
    (d / ".gitkeep").write_text("")
    load(d)
    (d / "README.md").write_text("# agents\n")
    assert refused(d, "README", "# agents\n") == "README.md: code binds no agent 'README'"
    (d / "README.md").unlink()
    (d / "notes.txt").write_text("x")
    with pytest.raises(AgentError, match=r"^notes.txt: not an agent file \(agents/ holds"):
        load(d)
    (d / "notes.txt").unlink()
    (d / "sub.md").mkdir()
    with pytest.raises(AgentError, match=r"sub\.md: must be a regular file, not a link or a dir"):
        load(d)
    (d / "sub.md").rmdir()
    (d / "web.md").unlink()
    with pytest.raises(AgentError, match=r"^no file for the agent web \(web.md\)$"):
        load(d)
    with pytest.raises(AgentError, match=r"^no agents directory "):
        load(tmp_path / "missing")


def test_links_are_refused(tmp_path: Path) -> None:
    d = copy(tmp_path / "agents")
    elsewhere = tmp_path / "elsewhere.md"
    elsewhere.write_text(FILES["web"])
    (d / "web.md").unlink()
    (d / "web.md").symlink_to(elsewhere)
    with pytest.raises(AgentError, match=r"web\.md: must be a regular file, not a link"):
        load(d)
    linked = tmp_path / "linked"
    linked.symlink_to(copy(tmp_path / "real"), target_is_directory=True)
    with pytest.raises(AgentError, match=r"^no agents directory "):
        load(linked)


def test_a_link_made_after_the_listing_is_still_refused(tmp_path: Path) -> None:
    d = copy(tmp_path / "agents")
    target = tmp_path / "t.md"
    target.write_text(FILES["web"])
    (d / "web.md").unlink()
    os.symlink(target, d / "web.md")
    with pytest.raises(AgentError, match=r"web.md: cannot be read \("):
        loader.read(d / "web.md")


# -- characters and layout ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        (lambda t: "\ufeff" + t, "starts with a byte-order mark"),
        (lambda t: t.rstrip("\n"), "does not end with a newline"),
        (lambda t: t + "\n", "ends with a blank line"),
        (lambda t: t.replace("one alert", "one\talert", 1), "line 14 holds U+0009"),
        (lambda t: t.replace("\n", "\r\n"), "line 1 holds U+000D"),
        (lambda t: t.replace("one alert", "one\x00alert", 1), "line 14 holds U+0000"),
        (lambda t: t.replace("one alert", "one\u200balert", 1), "line 14 holds U+200B"),
        (lambda t: t.replace("one alert", "one\u202ealert", 1), "line 14 holds U+202E"),
        (lambda t: t.replace("one alert", "one\u00a0alert", 1), "line 14 holds U+00A0"),
        (lambda t: t.replace("one alert", "one\u2028alert", 1), "line 14 holds U+2028"),
        (lambda t: t.replace("one alert", "one\x85alert", 1), "line 14 holds U+0085"),
        (lambda t: t.replace("one alert", "one\ue000alert", 1), "line 14 holds U+E000"),
        (lambda t: t.replace("kind: coordinator", "kind: coordinator "), "line 3 ends with a"),
        (lambda t: t.replace("SIEM. Internal", "SIEM.  \nInternal"), "line 15 ends with a space"),
    ],
)
def test_only_plain_printable_text(tmp_path: Path, change: Any, reason: str) -> None:
    d = copy(tmp_path / "agents")
    got = refused(d, "investigator", change(FILES["investigator"]))
    assert got.startswith(f"investigator.md: {reason}")


def test_printable_refusals_say_what_is_refused(tmp_path: Path) -> None:
    d = copy(tmp_path / "agents")
    got = refused(d, "web", FILES["web"].replace("web specialist", "web\tspecialist", 1))
    assert got == (
        "web.md: line 12 holds U+0009; agent files are printable ASCII (tabs, carriage"
        " returns, controls and every other character are refused, so nothing in a prompt can"
        " hide from the person who approves it)"
    )


def test_bytes_size_and_encoding(tmp_path: Path) -> None:
    d = copy(tmp_path / "agents")
    assert refused(d, "web", b"\xff" + FILES["web"].encode()) == "web.md: not UTF-8 (byte 0)"
    big = FILES["web"] + "x" * (loader.MAX_BYTES - len(FILES["web"]) + 1) + "\n"
    assert refused(d, "web", big) == "web.md: larger than 64 KiB"
    exact = FILES["web"].rstrip("\n") + "x" * (loader.MAX_BYTES - len(FILES["web"])) + "\n"
    assert len(exact.encode()) == loader.MAX_BYTES
    (d / "web.md").write_text(exact)
    structural(d)  # 64 KiB itself is allowed


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        (lambda t: t[4:], "must start with a '---' line, then the header"),
        (lambda t: "\n" + t, "must start with a '---' line, then the header"),
        (lambda t: t.replace("\n---\nYou", "\nYou", 1), "the header has no closing '---' line"),
        (lambda t: t.split("\n---\n")[0] + "\n---\n", "has no instructions after its header"),
        (lambda t: t.replace("\n---\nYou", "\n---\n\nYou", 1),
         "the instructions start with a blank line (line 14)"),
        (lambda t: t.replace("{tools}", "the tools"),
         "the instructions must hold {tools} exactly once and no other {name} (found 0)"),
        (lambda t: t.replace("{tools}", "{tools}\n{tools}"),
         "the instructions must hold {tools} exactly once and no other {name} (found 2)"),
        (lambda t: t.replace("{tools}", "{tools} {domain} {focus}"),
         "the instructions must hold {tools} exactly once and no other {name} (found 1;"
         " also {domain}, {focus})"),
    ],
)  # fmt: skip
def test_the_layout(tmp_path: Path, change: Any, reason: str) -> None:
    d = copy(tmp_path / "agents")
    assert refused(d, "investigator", change(FILES["investigator"])) == f"investigator.md: {reason}"


def test_json_braces_are_not_placeholders() -> None:
    assert loader.PLACEHOLDER.findall('{"outcome": "x"} {{tools}} {tools}') == [
        "{tools}",
        "{tools}",
    ]
    assert loader.PLACEHOLDER.findall('{"a": 1} { tools } {1x} {}') == []


# -- the header's YAML subset -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("line", "value", "reason"),
    [
        ("tier", "&t medium", "header line 7: anchors and aliases are not allowed"),
        ("output", "*t", "header line 12: anchors and aliases are not allowed"),
        ("tier", "!!str medium", "header line 7: tags are not allowed"),
        ("tier", "! medium", "header line 7: tags are not allowed"),
        ("tools", "!!python/tuple [proxy.host]", "header line 8: tags are not allowed"),
        ("budget", "{rounds: 4, rounds: 3}", "header line 10: the key 'rounds' appears twice"),
        ("budget", "{4: 4}", "header line 10: every key must be a plain name"),
        ("budget", "{a: {b: [c]}}", "header line 10: nesting is too deep"),
        ("tier", "[unclosed", "header line 8: "),
        ("tier", "medium: x", "header line 7: mapping values are not allowed here"),
    ],
)
def test_the_yaml_subset(tmp_path: Path, line: str, value: str, reason: str) -> None:
    d = copy(tmp_path / "agents")
    got = refused(d, "investigator", header(FILES["investigator"], line, value))
    assert got.startswith(f"investigator.md: {reason}")


def test_a_repeated_field_and_a_merge_key(tmp_path: Path) -> None:
    d = copy(tmp_path / "agents")
    text = FILES["investigator"].replace("tier: medium\n", "tier: medium\ntier: small\n")
    assert refused(d, "investigator", text) == (
        "investigator.md: header line 8: the key 'tier' appears twice"
    )
    text = FILES["investigator"].replace("tier: medium\n", "tier: medium\n<<: {tier: small}\n")
    assert refused(d, "investigator", text) == "investigator.md: <<: unknown field"


def test_the_header_is_a_mapping(tmp_path: Path) -> None:
    d = copy(tmp_path / "agents")
    body = FILES["web"].split("\n---\n", 1)[1]
    assert refused(d, "web", "---\n---\n" + body) == "web.md: the header is empty"
    assert refused(d, "web", "---\n- a\n- b\n---\n" + body) == (
        "web.md: the header must be a mapping of fields"
    )
    assert refused(d, "web", "---\nname\n---\n" + body) == (
        "web.md: the header must be a mapping of fields"
    )
    assert refused(d, "web", "---\na: 1\n...\nb: 2\n---\n" + body).startswith("web.md: header")


@pytest.mark.parametrize(
    "value",
    ["yes", "no", "on", "null", "~", "true", "2026-10-23", "0x10", "010", "1_000", ".inf", "4e2"],
)
def test_implicit_types_are_text(value: str) -> None:
    got = loader._Header(f"a: {value}").get_single_data()
    assert got == {"a": value}


def test_plain_decimals_are_numbers() -> None:
    got = loader._Header("a: [0, -3, 12, 4.5, -0.25, 1.0]").get_single_data()
    assert got == {"a": [0, -3, 12, 4.5, -0.25, 1.0]}
    assert [type(v) for v in got["a"]] == [int, int, int, float, float, float]


def test_the_subset_leaves_pyyaml_alone() -> None:
    import yaml

    assert yaml.safe_load("a: yes\nb: 0x10") == {"a": True, "b": 16}
    assert loader._Header.yaml_implicit_resolvers is not yaml.SafeLoader.yaml_implicit_resolvers


# -- fields -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("colour", "blue", "colour: unknown field"),
        ("tools", None, "tools: Field required"),
        ("triggers", None, "triggers: Field required"),
        ("mission", None, "mission: Field required"),
        ("tools", "proxy.host", "tools: Input should be a valid list"),
        ("tools", "[1]", "tools.0: Input should be a valid string"),
        ("triggers", "[]", "triggers: List should have at least 1 item after validation, not 0"),
        ("budget", "{rounds: true, tools: 12, calls: 8, consults: 2, seconds: 240}",
         "budget.rounds: Input should be a valid integer"),
        ("budget", "{rounds: 4.0, tools: 12, calls: 8, consults: 2, seconds: 240}",
         "budget.rounds: Input should be a valid integer"),
        ("budget", "{rounds: 0x4, tools: 12, calls: 8, consults: 2, seconds: 240}",
         "budget.rounds: Input should be a valid integer"),
        ("budget", "{rounds: -1, tools: 12, calls: 8, consults: 2, seconds: 240}",
         "budget.rounds: Input should be greater than or equal to 0"),
        ("budget", "{rounds: 4, tools: 12, calls: 8, consults: 2, seconds: .inf}",
         "budget.seconds: Input should be a valid number"),
        ("budget", "{rounds: 4, tools: 12, calls: 8, consults: 2, seconds: 0}",
         "budget.seconds: Input should be greater than 0"),
        ("budget", "{rounds: 4, tools: 12, calls: 8, consults: 2, seconds: 240, usd: 0.03}",
         "budget.usd: unknown field"),
        ("budget", "{rounds: 4, tools: 12, calls: 8, seconds: 240}",
         "budget.consults: Field required"),
        ("mission", '"' + "m" * 301 + '"', "mission: String should have at most 300 characters"),
    ],
)  # fmt: skip
def test_fields(tmp_path: Path, field: str, value: str | None, reason: str) -> None:
    d = copy(tmp_path / "agents")
    got = refused(d, "investigator", header(FILES["investigator"], field, value))
    assert got == f"investigator.md: {reason}"


def test_at_most_three_field_problems_are_named(tmp_path: Path) -> None:
    d = copy(tmp_path / "agents")
    text = FILES["web"]
    for field in ("a", "b", "c", "d"):
        text = header(text, field, "x")
    assert refused(d, "web", text) == (
        "web.md: a: unknown field; b: unknown field; c: unknown field"
    )


# -- what code binds ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "field", "value", "reason"),
    [
        ("web", "name", "proxy", "says its name is 'proxy': a file is named after its agent"),
        ("investigator", "kind", "specialist",
         "kind 'specialist' is refused: code binds investigator to 'coordinator'"),
        ("web", "kind", "coordinator",
         "kind 'coordinator' is refused: code binds web to 'specialist'"),
        ("investigator", "task", "assess.specialist",
         "task 'assess.specialist' is refused: code binds investigator to 'assess.coordinator'"),
        ("intel", "task", "evaluate",
         "task 'evaluate' is refused: code binds intel to 'assess.specialist'"),
        ("investigator", "output", "answer@2",
         "output 'answer@2' is refused: code binds investigator to 'answer@1'"),
        ("investigator", "version", "specialist@3",
         "version 'specialist@3' is not coordinator@<number>"),
        ("investigator", "version", "coordinator@0", "version 'coordinator@0' is not"),
        ("investigator", "version", "coordinator@3a", "version 'coordinator@3a' is not"),
        ("investigator", "version", "coordinator", "version 'coordinator' is not"),
        ("web", "version", "specialist@1234567", "version 'specialist@1234567' is not"),
    ],
)  # fmt: skip
def test_kind_task_output_and_version_are_bound(
    tmp_path: Path, name: str, field: str, value: str, reason: str
) -> None:
    d = copy(tmp_path / "agents")
    got = refused(d, name, header(FILES[name], field, value))
    assert got.startswith(f"{name}.md: {reason}")


def test_an_unbound_name_is_refused_even_named_after_itself(tmp_path: Path) -> None:
    d = copy(tmp_path / "agents")
    text = header(FILES["web"], "name", "dns")
    (d / "dns.md").write_text(text)
    with pytest.raises(AgentError, match=r"^dns\.md: code binds no agent 'dns'$"):
        load(d)
    with pytest.raises(AgentError, match=r"^dns\.md: code binds no agent 'dns'$"):
        loader.read(d / "dns.md")


@pytest.mark.parametrize(
    ("name", "field", "value", "reason"),
    [
        ("web", "tools", "[web.followups, proxy.host]",
         "tools beyond what code allows web: proxy.host"),
        ("intel", "tools", "[ti.lookup, web.followups, proxy.host]",
         "tools beyond what code allows intel: proxy.host, web.followups"),
        ("investigator", "tools", "[proxy.host, drop.index]",
         "no tool drop.index in the catalogue"),
        ("investigator", "tools", "[ti.lookup, ti.lookup]", "tools lists ti.lookup more than once"),
        ("investigator", "specialists", "[web, dns]", "specialists beyond what code allows"
         " investigator: dns"),
        ("investigator", "specialists", "[web, investigator]", "specialists beyond what code"
         " allows investigator: investigator"),
        ("investigator", "specialists", "[web, web]", "specialists lists web more than once"),
        ("proxy", "specialists", "[intel]", "a specialist consults no one"),
        ("web", "triggers", "[coordinator_consult, person_request]",
         "triggers beyond what code allows web: person_request"),
        ("investigator", "triggers", "[engine_no_decision, coordinator_consult]",
         "triggers beyond what code allows investigator: coordinator_consult"),
        ("investigator", "triggers", "[engine_no_decision, schedule]", "no trigger schedule"),
        ("investigator", "triggers", "[person_request, person_request]",
         "triggers lists person_request more than once"),
        ("investigator", "tier", "large", "tier large is above what code allows investigator"
         " (medium)"),
        ("web", "tier", "medium", "tier medium is above what code allows web (small)"),
        ("web", "tier", "huge", "no tier 'huge' (small, medium or large)"),
        ("investigator", "tier", "MEDIUM", "no tier 'MEDIUM' (small, medium or large)"),
        ("investigator", "budget", "{rounds: 5, tools: 12, calls: 9, consults: 2, seconds: 240.5}",
         "a budget above what code allows investigator: rounds 5 (at most 4), calls 9 (at most"
         " 8), seconds 240.5 (at most 240.0)"),
        ("investigator", "budget", "{rounds: 4, tools: 13, calls: 8, consults: 3, seconds: 240}",
         "a budget above what code allows investigator: tools 13 (at most 12), consults 3 (at"
         " most 2)"),
        ("investigator", "budget", None, "a coordinator needs a budget"),
        ("web", "budget", "{rounds: 1, tools: 1, calls: 1, consults: 0, seconds: 1}",
         "only a coordinator has a budget"),
    ],
)  # fmt: skip
def test_widening_is_refused(
    tmp_path: Path, name: str, field: str, value: str | None, reason: str
) -> None:
    d = copy(tmp_path / "agents")
    assert refused(d, name, header(FILES[name], field, value), pins=None, enabled=None) == (
        f"{name}.md: {reason}"
    )


def test_narrowing_loads_and_renders_the_narrower_prompt(tmp_path: Path) -> None:
    d = copy(tmp_path / "agents")
    text = FILES["investigator"]
    for field, value in (
        ("tools", "[ti.lookup, proxy.host]"),
        ("specialists", "[intel]"),
        ("tier", "small"),
        ("triggers", "[engine_no_decision]"),
        ("budget", "{rounds: 1, tools: 0, calls: 2, consults: 0, seconds: 30.5}"),
    ):
        text = header(text, field, value)  # fmt: skip
    (d / "investigator.md").write_text(text)
    lead = structural(d).coordinator
    assert lead.tools == ("proxy.host", "ti.lookup")  # the catalogue's order
    assert lead.specialists == ("intel",)
    assert lead.tier is Tier.SMALL
    assert lead.triggers == {Trigger.ENGINE_NO_DECISION}
    assert lead.budget == Limits(rounds=1, tools=0, calls=2, consults=0, seconds=30.5)
    assert catalogue.lines(["proxy.host", "ti.lookup"]) in lead.prompt
    assert "web.followups (" not in lead.prompt
    assert not structural(d).takes(Trigger.PERSON_REQUEST)
    assert sorted(structural(d).by_name) == ["intel", "investigator"]  # its family only
    empty = header(FILES["web"], "tools", "[]")
    (d / "web.md").write_text(empty)
    assert loader.read(d / "web.md").tools == ()
    assert "of this item:\n\nAnswer" in loader.read(d / "web.md").prompt


# -- pins and the enabled version ---------------------------------------------------------------


def test_an_unversioned_edit_is_refused(tmp_path: Path) -> None:
    d = copy(tmp_path / "agents")
    text = FILES["investigator"].replace("Ask only for evidence", "Ask only for any evidence")
    got = refused(d, "investigator", text)
    assert re.fullmatch(
        r"investigator.md: is not the file pinned for coordinator@4 \(sha256 [0-9a-f]{12},"
        r" pinned 95984877dfc7\): an edited file needs a new version and its pin",
        got,
    )
    (d / "investigator.md").write_text(FILES["investigator"])
    narrower = header(FILES["web"], "tools", "[]")
    assert refused(d, "web", narrower).startswith("web.md: is not the file pinned for specialist@1")


def test_a_new_version_needs_its_pin_then_its_switch(tmp_path: Path) -> None:
    d = copy(tmp_path / "agents")
    text = header(FILES["investigator"], "version", "coordinator@5")
    assert refused(d, "investigator", text) == (
        "investigator.md: coordinator@5 is not pinned in code (argus.agent.registry.PINS): a"
        " new version needs its pin, and its approval"
    )
    candidate = loader.read(d / "investigator.md")
    pins = {**PINS, "investigator": {**PINS["investigator"], "coordinator@5": Pin(
        candidate.file_sha256, candidate.prompt_sha256, "test")}}  # fmt: skip
    assert refused(d, "investigator", text, pins=pins) == (
        "investigator.md: holds coordinator@5, but investigator runs coordinator@4"
        " (argus.agent.registry.ENABLED)"
    )
    on = load(d, pins=pins, enabled={**ENABLED, "investigator": "coordinator@5"})
    assert on.coordinator.version == "coordinator@5"
    shadow = load(d, pins=pins, enabled=None)  # pinned, not switched on: an evaluation's view
    assert shadow.coordinator.version == "coordinator@5"
    others = {k: v for k, v in ENABLED.items() if k != "investigator"}
    assert refused(d, "investigator", text, pins=pins, enabled=others) == (
        "investigator.md: holds coordinator@5, but investigator runs no version"
        " (argus.agent.registry.ENABLED)"
    )


def test_a_changed_tool_description_needs_a_new_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    d = copy(tmp_path / "agents")
    tool = catalogue.TOOLS["ti.lookup"]
    monkeypatch.setitem(catalogue.TOOLS, "ti.lookup", replace(tool, describe="any lookup"))
    with pytest.raises(AgentError) as caught:
        load(d)  # the coordinator's pin is checked first: its prompt lists every tool
    assert re.fullmatch(
        r"investigator.md: the instructions coordinator@4 gives a model changed \(sha256"
        r" [0-9a-f]{12}, pinned a90ac7cfa898\), so a tool's description changed: that needs a"
        r" new version and its pin",
        str(caught.value),
    )
    with pytest.raises(AgentError) as caught:
        loader.pinned(loader.read(d / "intel.md"))
    assert re.fullmatch(
        r"intel.md: the instructions specialist@2 gives a model changed \(sha256 [0-9a-f]{12},"
        r" pinned f38633018afc\), so a tool's description changed: that needs a new version"
        r" and its pin",
        str(caught.value),
    )
    assert loader.pinned(loader.read(d / "web.md")) is None  # web's prompt lists no ti.lookup


def test_a_coordinator_whose_specialist_is_not_one(tmp_path: Path) -> None:
    d = copy(tmp_path / "agents")
    bindings = {**BINDINGS, "web": replace(BINDINGS["investigator"], specialists=frozenset())}
    text = header(header(FILES["web"], "kind", "coordinator"), "version", "coordinator@1")
    text = header(header(text, "task", "assess.coordinator"), "output", "answer@1")
    text = header(text, "triggers", "[engine_no_decision]")
    text = header(text, "budget", "{rounds: 1, tools: 1, calls: 1, consults: 0, seconds: 1}")
    (d / "web.md").write_text(text)
    with pytest.raises(AgentError, match=r"^investigator.md: web is not a specialist$"):
        load(d, bindings=bindings, pins=None, enabled=None)
    lone = {"investigator": replace(BINDINGS["investigator"], kind=Kind.SPECIALIST)}
    for name in ("web", "proxy", "intel", "responder", "reporter"):
        (d / f"{name}.md").unlink()
    text = FILES["investigator"].replace("kind: coordinator", "kind: specialist")
    text = header(header(text, "version", "specialist@3"), "budget", None)
    text = header(text, "specialists", None)
    (d / "investigator.md").write_text(text)
    nobody = {"investigator": replace(lone["investigator"], budget=None)}
    with pytest.raises(AgentError, match=r"^no coordinator 'investigator'$"):
        load(d, bindings=nobody, pins=None, enabled=None)


def test_the_first_reason_is_the_alphabetically_first_files(tmp_path: Path) -> None:
    d = copy(tmp_path / "agents")
    (d / "web.md").write_text(FILES["web"].replace("{tools}", ""))
    (d / "intel.md").write_text(FILES["intel"].replace("{tools}", ""))
    with pytest.raises(AgentError, match=r"^intel\.md: "):
        load(d)


# -- properties ---------------------------------------------------------------------------------


@FAST
@given(
    name=st.sampled_from(sorted(BINDINGS)),
    data=st.data(),
)
def test_no_edited_byte_of_a_pinned_file_loads(name: str, data: st.DataObject) -> None:
    """Every bound agent's file: agent@1 refuses its own family's edit at load, and the survey
    (doctor's view) refuses any other agent's, which never refuses agent@1 itself."""
    original = FILES[name].encode()
    position = data.draw(st.integers(0, len(original)), label="position")
    kind = data.draw(st.sampled_from(["replace", "insert", "delete"]), label="kind")
    byte = data.draw(st.integers(0, 255), label="byte")
    if kind == "replace":
        position = min(position, len(original) - 1)
        if original[position] == byte:
            byte = (byte + 1) % 256
        edited = original[:position] + bytes([byte]) + original[position + 1 :]
    elif kind == "insert":
        edited = original[:position] + bytes([byte]) + original[position:]
    else:
        position = min(position, len(original) - 1)
        edited = original[:position] + original[position + 1 :]
    assert edited != original
    with agents_dir() as d:
        (d / f"{name}.md").write_bytes(edited)
        if name in FAMILY:
            with pytest.raises(AgentError):
                load(d)
        else:
            load(d)  # not agent@1's: it still runs
            assert isinstance(loader.survey(d)[name], AgentError)


def _subset(
    values: frozenset[str] | frozenset[Trigger], min_size: int = 0
) -> st.SearchStrategy[list[str]]:
    if not values:
        return st.just([])
    return st.lists(st.sampled_from(sorted(str(v) for v in values)), unique=True,
                    min_size=min_size)  # fmt: skip


@FAST
@given(data=st.data())
def test_any_narrowing_loads_and_any_widening_is_refused(data: st.DataObject) -> None:
    name = data.draw(st.sampled_from(sorted(BINDINGS)), label="agent")
    binding = BINDINGS[name]
    tools = data.draw(_subset(binding.tools), label="tools")
    specialists = data.draw(_subset(binding.specialists), label="specialists")
    triggers = data.draw(_subset(binding.triggers, min_size=1), label="triggers")
    tier = data.draw(st.sampled_from(registry.TIERS[: registry.TIERS.index(binding.tier) + 1]))
    text = header(FILES[name], "tools", f"[{', '.join(tools)}]")
    text = header(text, "triggers", f"[{', '.join(triggers)}]")
    text = header(text, "tier", tier.value)
    if binding.kind is Kind.COORDINATOR:
        assert binding.budget is not None
        text = header(text, "specialists", f"[{', '.join(specialists)}]")
        cap = binding.budget
        budget = {
            "rounds": data.draw(st.integers(0, cap.rounds)),
            "tools": data.draw(st.integers(0, cap.tools)),
            "calls": data.draw(st.integers(0, cap.calls)),
            "consults": data.draw(st.integers(0, cap.consults)),
            "seconds": data.draw(st.integers(1, int(cap.seconds))),
        }
        text = header(text, "budget", "{" + ", ".join(f"{k}: {v}" for k, v in budget.items()) + "}")
    widen = data.draw(st.sampled_from(["none", "tool", "trigger", "tier", "budget", "specialist"]))
    reason = None
    if widen == "tool" and binding.tools != set(catalogue.TOOLS):
        extra = data.draw(st.sampled_from(sorted(set(catalogue.TOOLS) - binding.tools)))
        text = header(text, "tools", f"[{', '.join([*tools, extra])}]")
        reason = f"tools beyond what code allows {name}: {extra}"
    elif widen == "trigger":
        extra = data.draw(st.sampled_from(sorted(str(t) for t in set(Trigger) - binding.triggers)))
        text = header(text, "triggers", f"[{', '.join([*triggers, extra])}]")
        reason = f"triggers beyond what code allows {name}: {extra}"
    elif widen == "tier" and binding.tier is not Tier.LARGE:
        above = registry.TIERS[registry.TIERS.index(binding.tier) + 1]
        text = header(text, "tier", above.value)
        reason = f"tier {above.value} is above what code allows {name} ({binding.tier.value})"
    elif widen == "budget" and binding.budget is not None:
        field = data.draw(st.sampled_from(["rounds", "tools", "calls", "consults"]))
        value = getattr(binding.budget, field) + data.draw(st.integers(1, 1000))
        budget[field] = value
        text = header(text, "budget", "{" + ", ".join(f"{k}: {v}" for k, v in budget.items()) + "}")
        reason = "a budget above what code allows"
    elif widen == "specialist":
        extra = data.draw(st.sampled_from(["dns", "mail", "auth", "investigator", "guardian"]))
        if binding.kind is Kind.SPECIALIST:
            text = header(text, "specialists", f"[{extra}]")
            reason = "a specialist consults no one"
        else:
            text = header(text, "specialists", f"[{', '.join([*specialists, extra])}]")
            reason = f"specialists beyond what code allows {name}: {extra}"
    with agents_dir() as d:
        (d / f"{name}.md").write_text(text)
        if name not in FAMILY:  # judged on its own, as doctor does
            got_or_refused = loader.survey(d, pins=None, enabled=None)[name]
            if reason is None:
                assert isinstance(got_or_refused, loader.Definition)
            else:
                assert str(got_or_refused).startswith(f"{name}.md: {reason}")
        elif reason is None:
            got = structural(d).by_name[name]
            assert got.tools == tuple(t for t in catalogue.TOOLS if t in tools)
            assert set(got.triggers) == set(triggers)
            assert got.tier is tier
            if binding.kind is Kind.COORDINATOR:
                assert got.specialists == tuple(specialists)
                assert got.budget == Limits(**{**budget, "seconds": float(budget["seconds"])})
            assert got.prompt == got.instructions.replace("{tools}", catalogue.lines(tools))
            if text != FILES[name]:
                with pytest.raises(AgentError, match="is not the file pinned"):
                    load(d)  # a narrowing is an edit: it needs a new version and its pin
        else:
            with pytest.raises(AgentError) as caught:
                structural(d)
            assert str(caught.value).startswith(f"{name}.md: {reason}")


@FAST
@given(st.binary(max_size=400))
def test_any_bytes_are_refused_with_a_reason(data: bytes) -> None:
    with agents_dir() as d:
        (d / "web.md").write_bytes(data)
        with pytest.raises(AgentError):
            load(d, pins=None, enabled=None)


@FAST
@given(st.text(max_size=300))
def test_any_header_text_loads_or_is_refused_with_a_reason(text: str) -> None:
    body = FILES["web"].split("\n---\n", 1)[1]
    with agents_dir() as d:
        (d / "web.md").write_text(f"---\n{text}\n---\n{body}", encoding="utf-8", newline="")
        with suppress(AgentError):
            structural(d)


@FAST
@given(
    st.permutations(
        [
            "proxy.host",
            "proxy.destination",
            "web.followups",
            "ti.lookup",
            "outside.reputation",
            "outside.server",
        ]
    )
)
def test_the_prompt_does_not_depend_on_the_order_tools_are_listed(order: list[str]) -> None:
    with agents_dir() as d:
        (d / "investigator.md").write_text(
            header(FILES["investigator"], "tools", f"[{', '.join(order)}]")
        )
        got = structural(d).coordinator
        assert got.prompt == load().coordinator.prompt
        assert got.prompt_sha256 == PINS["investigator"]["coordinator@4"].prompt_sha256


def test_every_file_in_the_repository_is_a_bound_agent() -> None:
    names = {p.stem for p in loader.DIRECTORY.iterdir() if not p.name.startswith(".")}
    assert names == set(BINDINGS)
    assert all((loader.DIRECTORY / f"{n}.md").is_file() for n in names)


def test_a_number_too_long_to_be_one_is_text_and_refused(tmp_path: Path) -> None:
    """A plain decimal past Python's int() limit (4,300 digits) must be refused like any
    wrong value, not crash the loader (found while building Q-H1)."""
    assert loader._Header("a: " + "1" * 5000).get_single_data() == {"a": "1" * 5000}
    assert loader._Header("a: " + "1" * 18).get_single_data() == {"a": 10**18 // 9}
    assert loader._Header("a: 1." + "5" * 30).get_single_data() == {"a": "1." + "5" * 30}
    d = copy(tmp_path / "agents")
    budget = "{rounds: " + "1" * 5000 + ", tools: 12, calls: 8, consults: 2, seconds: 240}"
    got = refused(d, "investigator", header(FILES["investigator"], "budget", budget))
    assert got == "investigator.md: budget.rounds: Input should be a valid integer"


@pytest.mark.parametrize("error", [ValueError, TypeError, OverflowError, RecursionError])
def test_any_constructor_failure_is_a_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: type[Exception]
) -> None:
    def fail(self: Any, node: Any, deep: bool = False) -> Any:
        raise error("boom")

    monkeypatch.setattr(loader._Header, "construct_object", fail)  # the subclass only
    d = copy(tmp_path / "agents")
    with pytest.raises(AgentError) as caught:
        load(d, pins=None, enabled=None)
    # the coordinator's file is read first: it names the rest of its family
    assert str(caught.value) == "investigator.md: the header holds a value that cannot be read"


def test_a_fifo_swapped_in_after_the_listing_never_blocks(tmp_path: Path) -> None:
    """A file replaced by a named pipe between the listing and the read must be refused at
    once, not wait for a writer (start-up would hang)."""
    import signal

    d = copy(tmp_path / "agents")
    (d / "web.md").unlink()
    os.mkfifo(d / "web.md")

    def hung(*a: Any) -> None:
        raise TimeoutError("the read blocked")

    previous = signal.signal(signal.SIGALRM, hung)
    signal.alarm(5)
    try:
        with pytest.raises(AgentError, match=r"^web\.md: must be a regular file"):
            loader.read(d / "web.md")
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def test_an_unreadable_directory_is_a_refusal(tmp_path: Path) -> None:
    d = copy(tmp_path / "agents")
    d.chmod(0o000)
    try:
        if os.access(d, os.R_OK):  # running as root: nothing is unreadable
            pytest.skip("root reads everything")
        with pytest.raises(AgentError, match=r"^the agents directory cannot be read \("):
            load(d)
        assert not loader.allows(Trigger.PERSON_REQUEST, d)
    finally:
        d.chmod(0o755)


@pytest.mark.parametrize(
    "char", ["\u2800", "\u3164", "\u115f", "\u0456", "\u00e9", "\u2014", "\u00a7", "e\u0301"]
)
def test_agent_files_are_plain_ascii(tmp_path: Path, char: str) -> None:
    """Printable is not enough: a blank-looking Braille or Hangul filler, a Cyrillic letter
    that looks Latin, or any other non-ASCII character could hide text from the person who
    approves a prompt. Agent files are printable ASCII (found in review, Q-H1)."""
    d = copy(tmp_path / "agents")
    got = refused(d, "web", FILES["web"].replace("web specialist", f"web{char}specialist", 1))
    code = next(c for c in char if not c.isascii())
    assert got == (
        f"web.md: line 12 holds U+{ord(code):04X}; agent files are printable ASCII (tabs,"
        " carriage returns, controls and every other character are refused, so nothing in a"
        " prompt can hide from the person who approves it)"
    )


@pytest.mark.parametrize(
    ("value", "code"),
    [('"a\\u202eb"', "202E"), ('"a\\nb"', "000A"), ('"a\\x00b"', "0000"), ('"a\\tb"', "0009"),
     ('"\\u0456nvestigate"', "0456"), ("|\n  two\n  lines", "000A"), ('"a\\eb"', "001B")],
)  # fmt: skip
def test_an_escape_cannot_put_another_character_in_a_value(
    tmp_path: Path, value: str, code: str
) -> None:
    """The file is ASCII, but YAML's double-quoted escapes (and block scalars) can still make
    a value hold a control, a bidirectional or a look-alike character: values are printable
    ASCII too (found in review, Q-H1)."""
    d = copy(tmp_path / "agents")
    got = refused(d, "web", header(FILES["web"], "mission", value))
    assert got == f"web.md: the header's mission holds U+{code}; values are printable ASCII too"


def test_every_value_and_key_is_checked(tmp_path: Path) -> None:
    d = copy(tmp_path / "agents")
    got = refused(d, "web", header(FILES["web"], "tools", '[web.followups, "a\\u00a0b"]'))
    assert got == "web.md: the header's tools.1 holds U+00A0; values are printable ASCII too"
    text = FILES["investigator"].replace(
        "budget: {rounds: 4,", 'budget: {"r\\u00e9": 1, rounds: 4,'
    )
    got = refused(d, "investigator", text)
    assert got == (
        "investigator.md: the header's budget holds U+00E9 in a key; values are printable ASCII too"
    )


def test_a_yaml_error_without_a_place_or_a_problem(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import yaml

    def bare(self: Any) -> Any:
        raise yaml.YAMLError("no detail")

    monkeypatch.setattr(loader._Header, "get_single_data", bare)
    d = copy(tmp_path / "agents")
    with pytest.raises(AgentError) as caught:
        load(d, pins=None, enabled=None)
    assert str(caught.value) == "investigator.md: header not valid YAML"


# -- found in the independent review (F1, F6, F7) -----------------------------------------------


def _as_root() -> bool:
    return os.geteuid() == 0


@pytest.mark.parametrize(
    ("what", "mode", "reason"),
    [
        ("agents", 0o444, "intel.md: cannot be read (Permission denied)"),
        ("agents", 0o644, "intel.md: cannot be read (Permission denied)"),
        ("agents", 0o111, "the agents directory cannot be read (Permission denied)"),
        ("agents", 0o000, "the agents directory cannot be read (Permission denied)"),
        ("config", 0o600, "the agents directory cannot be read (Permission denied)"),
        ("config", 0o444, "the agents directory cannot be read (Permission denied)"),
        ("config", 0o000, "the agents directory cannot be read (Permission denied)"),
        ("file", 0o000, "web.md: cannot be read (Permission denied)"),
    ],
)
def test_what_cannot_be_searched_or_read_is_a_refusal(
    tmp_path: Path, what: str, mode: int, reason: str
) -> None:
    """An agents directory that can be listed but not searched (``chmod 644``, the usual way
    to make files read-only, applied to the directory), a parent that cannot be searched, or
    an unreadable file: a refusal with the reason, never an OSError (found in review, F1:
    the Inbox's investigation page answered 500 and the commands crashed)."""
    if _as_root():
        pytest.skip("root reads everything")
    d = copy(tmp_path / "config" / "agents")
    target = {"agents": d, "config": d.parent, "file": d / "web.md"}[what]
    target.chmod(mode)
    try:
        with pytest.raises(AgentError) as caught:
            load(d)
        assert str(caught.value) == reason
        assert loader.takes(Trigger.PERSON_REQUEST, d) is None
        assert not loader.allows(Trigger.PERSON_REQUEST, d)
        with pytest.raises(AgentError):
            loader.survey(d) if what != "file" else load(d)
    finally:
        target.chmod(0o644 if what == "file" else 0o755)


def test_any_os_error_out_of_a_load_is_a_no(monkeypatch: pytest.MonkeyPatch) -> None:
    """Whatever the loader meets, a page that asks whether a person may start the agent gets
    an answer, never an exception (defence in depth for F1)."""

    def broken(*a: Any, **kw: Any) -> Any:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(loader, "load", broken)
    assert loader.takes(Trigger.PERSON_REQUEST) is None
    assert loader.allows(Trigger.PERSON_REQUEST) is False


def test_the_read_stops_one_byte_past_the_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A huge file is refused after reading at most MAX_BYTES + 1 bytes, never read whole
    (found in review, F6: a mutant that read everything survived every test)."""
    d = copy(tmp_path / "agents")
    with open(d / "web.md", "r+b") as handle:
        handle.truncate(1 << 30)  # 1 GiB, sparse: nothing is written
    asked: list[int | None] = []
    real = os.fdopen

    class Recording:
        def __init__(self, handle: Any) -> None:
            self.handle = handle

        def read(self, size: int | None = -1) -> bytes:
            asked.append(size)
            if size is None or size < 0 or size > loader.MAX_BYTES + 1:
                raise AssertionError(f"read({size}) of a 1 GiB file")
            data: bytes = self.handle.read(size)
            return data

        def fileno(self) -> int:
            number: int = self.handle.fileno()
            return number

        def __enter__(self) -> Recording:
            return self

        def __exit__(self, *exc: object) -> None:
            self.handle.close()

    monkeypatch.setattr(loader.os, "fdopen", lambda fd, mode: Recording(real(fd, mode)))
    with pytest.raises(AgentError, match=r"^web\.md: larger than 64 KiB$"):
        loader.read(d / "web.md")
    assert asked == [loader.MAX_BYTES + 1]


def other_agent(d: Path, name: str = "dns") -> tuple[dict[str, Any], dict[str, Any]]:
    """A bound, pinned specialist that is not one of the investigator's (a stand-in for an
    agent another component adds, such as Q-H2's responder), with its file in ``d``."""
    bindings = {**BINDINGS, name: BINDINGS["intel"]}
    (d / f"{name}.md").write_text(header(header(FILES["intel"], "name", name),
                                         "version", "specialist@1"))  # fmt: skip
    got = loader.read(d / f"{name}.md", bindings)
    pin = Pin(got.file_sha256, got.prompt_sha256, "q-x9-approved")
    return bindings, {**PINS, name: {"specialist@1": pin}}


@pytest.mark.parametrize(
    ("state", "survey"),
    [
        ("off", "specialist@1"),
        ("left out of ENABLED", "specialist@1"),
        ("another version enabled",
         "dns.md: holds specialist@1, but dns runs specialist@2 (argus.agent.registry.ENABLED)"),
        ("an unversioned edit", "dns.md: is not the file pinned for specialist@1"),
        ("no file", "no file for the agent dns (dns.md)"),
    ],
)  # fmt: skip
def test_another_agent_never_refuses_agent_1(tmp_path: Path, state: str, survey: str) -> None:
    """Agents load by family: agent@1 is the investigator and the specialists its file names.
    Another bound agent that is off (built so, as Q-H2's responder will be), refused or
    missing never refuses agent@1; the survey (doctor's) gives each agent's own state (found
    in review, F7)."""
    d = copy(tmp_path / "agents")
    bindings, pins = other_agent(d)
    enabled: dict[str, str | None] = {**ENABLED, "dns": None}
    if state == "left out of ENABLED":
        enabled = dict(ENABLED)
    elif state == "another version enabled":
        enabled = {**ENABLED, "dns": "specialist@2"}
    elif state == "an unversioned edit":
        edited = header(FILES["intel"].replace("intel", "dns"), "name", "dns")
        (d / "dns.md").write_text(header(edited, "version", "specialist@1"))
    elif state == "no file":
        (d / "dns.md").unlink()
    agents = load(d, bindings=bindings, pins=pins, enabled=enabled)
    assert sorted(agents.by_name) == ["intel", "investigator", "proxy", "web"]
    assert agents.coordinator.version == "coordinator@4"
    found = loader.survey(d, bindings=bindings, pins=pins, enabled=enabled)
    assert sorted(found) == [
        "dns", "intel", "investigator", "proxy", "reporter", "responder", "web",
    ]  # fmt: skip
    for name in ("investigator", "web", "proxy", "intel"):
        assert found[name] == agents.by_name[name]
    dns = found["dns"]
    if isinstance(dns, AgentError):
        assert str(dns).startswith(survey)
    else:
        assert dns.version == survey


def test_an_agent_that_is_off_never_runs(tmp_path: Path) -> None:
    """Off (``ENABLED[name] is None``): its file is checked against its pin, and nothing
    starts it, neither as a coordinator nor as a specialist consulted by one (F7)."""
    d = copy(tmp_path / "agents")
    off = {**ENABLED, "web": None}
    with pytest.raises(AgentError) as caught:
        load(d, enabled=off)
    assert str(caught.value) == (
        "web.md: holds specialist@1, but web is off (argus.agent.registry.ENABLED)"
    )
    checked = loader.survey(d, enabled=off)["web"]
    assert isinstance(checked, loader.Definition)
    assert checked.version == "specialist@1"
    bindings = {**BINDINGS, "hunter": BINDINGS["investigator"]}
    text = header(header(FILES["investigator"], "name", "hunter"), "version", "coordinator@1")
    (d / "hunter.md").write_text(text)
    hunter_off = {**ENABLED, "hunter": None}
    with pytest.raises(AgentError) as caught:
        load(d, coordinator="hunter", bindings=bindings, pins=None, enabled=hunter_off)
    assert str(caught.value) == (
        "hunter.md: holds coordinator@1, but hunter is off (argus.agent.registry.ENABLED)"
    )
    agents = load(d, bindings=bindings, pins=None, enabled=hunter_off)
    assert agents.coordinator.name == "investigator"
    on = load(d, coordinator="hunter", bindings=bindings, pins=None,
              enabled={**ENABLED, "hunter": "coordinator@1"})  # fmt: skip
    assert (on.lead, on.coordinator.name) == ("hunter", "hunter")
    assert list(on.specialists) == ["web", "proxy", "intel"]
    with pytest.raises(AgentError, match=r"^no coordinator 'web'$"):
        load(d, coordinator="web", bindings=bindings, pins=None, enabled=None)
    with pytest.raises(AgentError, match=r"^no file for the agent nobody \(nobody\.md\)$"):
        load(d, coordinator="nobody", bindings=bindings, pins=None, enabled=None)


def test_a_family_needs_only_its_own_files(tmp_path: Path) -> None:
    """An investigator narrowed to two specialists runs without the third's file (F7)."""
    d = copy(tmp_path / "agents")
    (d / "investigator.md").write_text(header(FILES["investigator"], "specialists", "[web, proxy]"))
    (d / "intel.md").unlink()
    agents = load(d, pins=None, enabled=None)
    assert sorted(agents.by_name) == ["investigator", "proxy", "web"]
    assert list(agents.specialists) == ["web", "proxy"]
    found = loader.survey(d, pins=None, enabled=None)
    assert str(found["intel"]) == "no file for the agent intel (intel.md)"


def test_the_survey_names_every_file_and_every_bound_agent(tmp_path: Path) -> None:
    """Doctor's view: a stray file code binds no agent to is named with its reason, beside
    each bound agent's own state, in name order."""
    d = copy(tmp_path / "agents")
    (d / "README.md").write_text("# agents\n")
    (d / "web.md").write_text(header(FILES["web"], "tier", "large"))
    found = loader.survey(d)
    assert list(found) == [
        "README", "intel", "investigator", "proxy", "reporter", "responder", "web",
    ]  # fmt: skip
    assert str(found["README"]) == "README.md: code binds no agent 'README'"
    assert str(found["web"]) == "web.md: tier large is above what code allows web (small)"
    assert isinstance(found["investigator"], loader.Definition)
    with pytest.raises(AgentError, match=r"^README\.md: code binds no agent 'README'$"):
        load(d)  # a stray file refuses agent@1 too: someone's mistake to see
    unpinned = loader.survey(d, pins=None, enabled=None)
    assert isinstance(unpinned["intel"], loader.Definition)
    edited = FILES["intel"].replace("intel specialist", "intel  specialist")
    (d / "intel.md").write_text(edited)
    assert str(loader.survey(d)["intel"]).startswith("intel.md: is not the file pinned")
    assert isinstance(loader.survey(d, pins=None)["intel"], loader.Definition)
    with pytest.raises(AgentError, match=r"^no agents directory "):
        loader.survey(tmp_path / "nowhere")


def test_takes_gives_the_agents_that_take_the_trigger(tmp_path: Path) -> None:
    got = loader.takes(Trigger.PERSON_REQUEST)
    assert got is not None
    assert got.coordinator.version == "coordinator@4"
    assert got == load()
    assert loader.takes(Trigger.COORDINATOR_CONSULT) is None
    d = copy(tmp_path / "agents")
    narrowed = header(FILES["investigator"], "triggers", "[engine_no_decision]")
    (d / "investigator.md").write_text(narrowed)
    assert loader.takes(Trigger.ENGINE_NO_DECISION, d, pins=None, enabled=None) is not None
    assert loader.takes(Trigger.PERSON_REQUEST, d, pins=None, enabled=None) is None
    assert loader.allows(Trigger.ENGINE_NO_DECISION, d, pins=None, enabled=None)
    assert not loader.allows(Trigger.PERSON_REQUEST, d, pins=None, enabled=None)


def test_the_agents_value_and_its_summary() -> None:
    agents = load()
    assert agents.lead == "investigator" == registry.COORDINATOR
    assert loader.Agents(agents.by_name) == agents
    assert (
        agents.summary()
        == "investigator coordinator@4; web, proxy specialist@1; intel specialist@2"
    )
    alone = loader.Agents({"investigator": replace(agents.coordinator, specialists=())})
    assert alone.summary() == "investigator coordinator@4; no specialists"


def test_an_io_error_while_reading_is_a_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    d = copy(tmp_path / "agents")
    real = os.fstat

    def failing(fd: int) -> Any:
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(loader.os, "fstat", failing)
    with pytest.raises(AgentError, match=r"^web\.md: cannot be read \(Input/output error\)$"):
        loader.read(d / "web.md")
    monkeypatch.setattr(loader.os, "fstat", real)
    assert loader.read(d / "web.md").name == "web"


def test_a_path_through_a_file_is_no_agents_directory(tmp_path: Path) -> None:
    (tmp_path / "afile").write_text("x")
    with pytest.raises(AgentError, match=r"^no agents directory .*afile/agents$"):
        load(tmp_path / "afile" / "agents")
    (tmp_path / "agents").write_text("x")  # a file where the directory should be
    with pytest.raises(AgentError, match=r"^no agents directory .*/agents$"):
        load(tmp_path / "agents")


# -- second review (R1, R2, R5) -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "shown"),
    [
        (b"investigator\xe9.md", "investigator\\xe9.md"),  # a byte that is not UTF-8
        ("café.md".encode(), "caf\\xc3\\xa9.md"),  # UTF-8, but not ASCII
        (b"a\rb.md", "a\\x0db.md"),
        (b"a\nb.md", "a\\x0ab.md"),
        (b"a\x1b[2Kb.md", "a\\x1b[2Kb.md"),
        (b"a\x7fb.md", "a\\x7fb.md"),
        (b"backup\xff", "backup\\xff"),  # not .md either
    ],
)
def test_a_reason_names_any_file_in_printable_ascii(tmp_path: Path, raw: bytes, shown: str) -> None:
    """R1 (second review): a stray file named with bytes that are not UTF-8, or with a
    carriage return, is refused like any stray file, and the reason names it in printable
    ASCII (each other byte as \\xNN, as ``ls -b`` does): a page encodes it, a terminal prints
    it on one line, and nothing in a name can overwrite what doctor printed before it."""
    d = copy(tmp_path / "agents")
    with open(os.path.join(os.fsencode(d), raw), "wb") as f:
        f.write(b"x\n")
    with pytest.raises(AgentError) as caught:
        load(d)
    why = str(caught.value)
    assert why.startswith(f"{shown}: ")
    assert why.isascii()
    assert why.isprintable()
    assert caught.value.args == (why,)
    if raw.endswith(b".md"):
        found = loader.survey(d)
        assert str(next(v for k, v in found.items() if k not in BINDINGS)) == why
    else:  # not <name>.md: the listing itself is refused
        with pytest.raises(AgentError, match=re.escape(why)):
            loader.survey(d)


@given(st.text())
def test_shown_is_printable_ascii_and_leaves_printable_ascii_alone(text: str) -> None:
    got = loader.shown(text)
    assert got.isascii()
    assert got.isprintable() or got == ""
    if text.isascii() and text.isprintable():
        assert got == text
    assert str(AgentError(text)) == got


def test_shown_writes_each_byte_of_a_character() -> None:
    assert loader.shown("a\tb") == "a\\x09b"
    assert loader.shown("é€") == "\\xc3\\xa9\\xe2\\x82\\xac"
    assert loader.shown("\udce9\udc80\udcff") == "\\xe9\\x80\\xff"  # os.fsdecode's bytes
    assert loader.shown("\ud800") == "\\xed\\xa0\\x80"  # a lone surrogate of another kind
    assert loader.shown(" ~") == " ~"


def test_a_file_of_one_newline_ends_with_a_blank_line(tmp_path: Path) -> None:
    """The blank-line rule holds for a file that is nothing but a newline (a mutant that
    skipped it gave the same refusal with another reason)."""
    d = copy(tmp_path / "agents")
    assert refused(d, "web", b"\n") == "web.md: ends with a blank line"
    assert refused(d, "web", b"\n\n") == "web.md: ends with a blank line"


def test_an_agent_switched_off_in_code_is_its_own_refusal(tmp_path: Path) -> None:
    """R2 (second review): an agent switched off in code (``ENABLED[name] is None``) is
    refused as AgentOffError, so the health page can say "switched off" rather than "its files
    are refused". Another enabled version, a missing entry and an edited file are not."""
    d = copy(tmp_path / "agents")
    for name in ("investigator", "web"):
        with pytest.raises(
            loader.AgentOffError, match=rf"^{name}\.md: holds \S+, but {name} is off"
        ):
            load(d, enabled={**ENABLED, name: None})
    for enabled in ({**ENABLED, "web": "specialist@2"},
                    {k: v for k, v in ENABLED.items() if k != "web"}):  # fmt: skip
        with pytest.raises(AgentError) as caught:
            load(d, enabled=enabled)
        assert not isinstance(caught.value, loader.AgentOffError)
    (d / "investigator.md").write_text(FILES["investigator"].replace("lead", "chief", 1))
    with pytest.raises(AgentError) as caught:  # an edited file of an agent off: refused first
        load(d, enabled={**ENABLED, "investigator": None})
    assert not isinstance(caught.value, loader.AgentOffError)
    assert "is not the file pinned" in str(caught.value)


def test_the_pin_covers_the_template_not_the_site_words() -> None:
    """The prompt a model reads says the site's words; the pinned hash does not change with
    them (D-289): the same on ACME's site and the neutral one, and the prompts do differ."""
    from argus import site

    acme = load()
    with site.using(site.SiteSettings()):
        neutral = load()  # also passes the pin check: no AgentError
    for name in acme.by_name:
        a, b = acme.by_name[name], neutral.by_name[name]
        assert a.prompt_sha256 == b.prompt_sha256 == PINS[name][a.version].prompt_sha256
    assert acme.by_name["investigator"].prompt != neutral.by_name["investigator"].prompt
