"""Agents as Markdown files (Q-H1, plan §7.6): ``config/agents/<name>.md``, read strictly and
checked against what code allows (``argus.agent.registry``) when a process starts.

A file is a header between two ``---`` lines, then the instructions::

    ---
    name: investigator
    kind: coordinator
    version: coordinator@3
    ...
    ---
    You are the lead security analyst ...
    {tools}
    ...

The header is a strict subset of YAML: plain decimal numbers, text, lists and one level of
mapping (``budget``); no anchors, aliases, tags, merge keys, duplicate keys or other implicit
types (``yes``, ``null``, dates, ``0x10`` are text, which no field accepts). The instructions
are plain text with ``{tools}`` exactly once, where ARGUS writes one line per tool the agent
may use; they are what the model is given, byte for byte. The file is printable ASCII (no
tab, carriage return, control or other character: a look-alike letter or a blank-looking
one could hide text from the person approving a prompt), no line ends with a space, and it
ends with one newline.

Each file is refused, with the reason, when it names an agent code does not bind, changes a
bound kind, task or output, widens a bound set or cap, carries a version code has not pinned,
differs from its pin by a byte (the file, or the instructions with its tools' lines in), or
is not the enabled version (an agent may also be off). A coordinator loads with the
specialists its file names, and only their files decide whether it runs; ``survey`` gives
every agent's own state. Nothing here sends anything anywhere.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from types import MappingProxyType
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from yaml.nodes import MappingNode, Node, ScalarNode

from argus import site
from argus.agent import catalogue
from argus.agent.registry import (
    BINDINGS,
    COORDINATOR,
    ENABLED,
    PINS,
    TIERS,
    Binding,
    Kind,
    Limits,
    Pin,
    Trigger,
)
from argus.llm.providers import Tier

ROOT = Path(__file__).resolve().parents[3]
DIRECTORY = ROOT / "config" / "agents"
MAX_BYTES = 64 * 1024  # a prompt is a few KiB
MAX_DEPTH = 4  # the header, budget, a list, a value
FENCE = "---"
TOOLS = "{tools}"
# The words a pin's hash is made in: the prompt a model reads carries the site's words (a tool's
# line says "a campus host"), but what is approved is the template, so the hash is taken with
# these fixed words, the ones the pins were made with (only the tools' lines have any, and they
# name no more than the word for the own network), whatever the site is.
PIN_WORDS = site.SiteSettings(own_network_noun="campus")
PLACEHOLDER = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*\}")
VERSION = re.compile(r"([a-z]+)@[1-9][0-9]{0,5}")  # <kind>@<number>
_STR = "tag:yaml.org,2002:str"


def shown(text: str) -> str:
    """``text`` as printable ASCII: every other byte as ``\\xNN`` (a file name's own bytes for
    one that is not UTF-8, as ``ls -b`` shows them), so a reason can be sent as UTF-8, printed
    on one line, and nothing in a file's name can move a terminal's cursor."""
    out = []
    for char in text:
        if " " <= char <= "~":
            out.append(char)
        elif "\udc80" <= char <= "\udcff":  # a byte os.fsdecode could not decode
            out.append(f"\\x{ord(char) - 0xDC00:02x}")
        else:
            out += [f"\\x{byte:02x}" for byte in char.encode("utf-8", "surrogatepass")]
    return "".join(out)


class AgentError(Exception):
    """An agent file ARGUS refuses to run, and why (in printable ASCII: a reason names files,
    and their names can hold any byte but ``/``)."""

    def __init__(self, reason: str) -> None:
        super().__init__(shown(reason))


class AgentOffError(AgentError):
    """An agent switched off in code (``ENABLED[name] is None``): nothing wrong with its file."""


class _Header(yaml.SafeLoader):
    """A YAML subset: plain decimal ints and floats, everything else plain is text; no anchors,
    aliases, tags or duplicate keys; mapping keys are text; a depth cap."""

    def __init__(self, stream: str) -> None:
        self._depth = 0
        super().__init__(stream)

    def compose_node(self, parent: Node | None, index: Any) -> Node | None:
        event = self.peek_event()  # type: ignore[no-untyped-call]
        if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None) is not None:
            raise _Refused("anchors and aliases are not allowed", event)
        if getattr(event, "tag", None) is not None:
            raise _Refused("tags are not allowed", event)
        self._depth += 1
        try:
            if self._depth > MAX_DEPTH:
                raise _Refused("nesting is too deep", event)
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen: set[str] = set()
        for key, _ in node.value:
            if not isinstance(key, ScalarNode) or key.tag != _STR:
                raise _Refused("every key must be a plain name", key)
            if key.value in seen:
                raise _Refused(f"the key {key.value!r} appears twice", key)
            seen.add(key.value)
        return super().construct_mapping(node, deep=deep)


# Its own table (SafeLoader's is left as it is): plain decimals of at most 18 digits a side are
# numbers, anything longer is text (int() refuses over 4,300 digits), and so is every other form.
_Header.yaml_implicit_resolvers = {}
_Header.add_implicit_resolver(
    "tag:yaml.org,2002:int", re.compile(r"^-?(?:0|[1-9][0-9]{0,17})$"), list("-0123456789")
)
_Header.add_implicit_resolver(
    "tag:yaml.org,2002:float",
    re.compile(r"^-?(?:0|[1-9][0-9]{0,17})\.[0-9]{1,18}$"),
    list("-0123456789"),
)


class _Refused(yaml.YAMLError):
    def __init__(self, problem: str, at: Any) -> None:
        mark = getattr(at, "start_mark", None)
        super().__init__(problem)
        self.problem = problem
        self.line = mark.line + 1 if mark is not None else None


class _Budget(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    rounds: int = Field(ge=0)
    tools: int = Field(ge=0)
    calls: int = Field(ge=0)
    consults: int = Field(ge=0)
    seconds: float = Field(gt=0, allow_inf_nan=False)


class _Front(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    name: str = Field(min_length=1, max_length=32)
    kind: str = Field(min_length=1, max_length=32)
    version: str = Field(min_length=1, max_length=40)
    mission: str = Field(min_length=1, max_length=300)
    task: str = Field(min_length=1, max_length=64)
    tier: str = Field(min_length=1, max_length=16)
    tools: list[str] = Field(max_length=32)
    specialists: list[str] = Field(default_factory=list, max_length=16)
    budget: _Budget | None = None
    triggers: list[str] = Field(min_length=1, max_length=8)
    output: str = Field(min_length=1, max_length=32)


@dataclass(frozen=True)
class Definition:
    """One agent as its file says and code allows."""

    name: str
    kind: Kind
    version: str
    mission: str
    task: str
    output: str
    tier: Tier
    tools: tuple[str, ...]  # in the catalogue's order
    specialists: tuple[str, ...]  # in the file's order
    triggers: frozenset[Trigger]
    budget: Limits | None
    instructions: str  # the body, with {tools}
    prompt: str  # what a model is given before any history: the tools' lines in
    file_sha256: str
    prompt_sha256: str  # of the prompt in the pin words (``PIN_WORDS``), whatever the site is


@dataclass(frozen=True)
class Agents:
    """A coordinator and the specialists its file names, loaded and checked."""

    by_name: Mapping[str, Definition]
    lead: str = COORDINATOR  # the coordinator's name

    @property
    def coordinator(self) -> Definition:
        return self.by_name[self.lead]

    @property
    def specialists(self) -> Mapping[str, Definition]:
        """The coordinator's specialists, in its file's order."""
        lead = self.coordinator
        return MappingProxyType({name: self.by_name[name] for name in lead.specialists})

    def takes(self, trigger: Trigger) -> bool:
        """The coordinator may be started by ``trigger``."""
        return trigger in self.coordinator.triggers

    def summary(self) -> str:
        """Who runs, in which version: ``investigator coordinator@3; web, proxy, intel
        specialist@1`` (specialists sharing a version are named together)."""
        by_version: dict[str, list[str]] = {}
        for name, definition in self.specialists.items():
            by_version.setdefault(definition.version, []).append(name)
        specialists = "; ".join(f"{', '.join(n)} {v}" for v, n in by_version.items())
        lead = self.coordinator
        return f"{lead.name} {lead.version}; {specialists or 'no specialists'}"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read(path: Path) -> bytes:
    """The file's bytes, at most MAX_BYTES + 1. Whatever the path is by now (the listing may
    be stale), only a regular file is read: a link is refused when opened, and a pipe or a
    device is opened without waiting and refused."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise AgentError(f"{path.name}: cannot be read ({exc.strerror or exc})") from None
    with os.fdopen(fd, "rb") as handle:
        try:
            mode = os.fstat(handle.fileno()).st_mode
            if stat.S_ISREG(mode):
                return handle.read(MAX_BYTES + 1)
        except OSError as exc:  # an I/O error, a file system gone
            raise AgentError(f"{path.name}: cannot be read ({exc.strerror or exc})") from None
    raise AgentError(f"{path.name}: must be a regular file, not a link or a directory")


def _lines(name: str, data: bytes) -> list[str]:
    """The file's lines, once every rule about characters holds."""
    if len(data) > MAX_BYTES:
        raise AgentError(f"{name}: larger than {MAX_BYTES // 1024} KiB")
    if data.startswith(b"\xef\xbb\xbf"):
        raise AgentError(f"{name}: starts with a byte-order mark")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AgentError(f"{name}: not UTF-8 (byte {exc.start})") from None
    if not text.endswith("\n"):
        raise AgentError(f"{name}: does not end with a newline")
    lines = text.split("\n")[:-1]
    if lines and not lines[-1]:
        raise AgentError(f"{name}: ends with a blank line")
    for number, line in enumerate(lines, 1):
        bad = _odd(line)
        if bad is not None:
            raise AgentError(
                f"{name}: line {number} holds U+{ord(bad):04X}; agent files are printable"
                " ASCII (tabs, carriage returns, controls and every other character are"
                " refused, so nothing in a prompt can hide from the person who approves it)"
            )
        if line.endswith(" "):
            raise AgentError(f"{name}: line {number} ends with a space")
    return lines


def _split(name: str, lines: list[str]) -> tuple[str, str]:
    """(the header's YAML, the instructions)."""
    if not lines or lines[0] != FENCE:
        raise AgentError(f"{name}: must start with a '---' line, then the header")
    try:
        end = lines.index(FENCE, 1)
    except ValueError:
        raise AgentError(f"{name}: the header has no closing '---' line") from None
    body = lines[end + 1 :]
    if not body:
        raise AgentError(f"{name}: has no instructions after its header")
    if not body[0]:
        raise AgentError(f"{name}: the instructions start with a blank line (line {end + 2})")
    instructions = "\n".join(body)
    found = PLACEHOLDER.findall(instructions)
    if found != [TOOLS]:
        others = sorted({f for f in found if f != TOOLS})
        raise AgentError(
            f"{name}: the instructions must hold {TOOLS} exactly once and no other"
            f" {{name}} (found {found.count(TOOLS)}"
            + (f"; also {', '.join(others)}" if others else "")
            + ")"
        )
    return "\n".join(lines[1:end]), instructions


def _header(name: str, text: str) -> dict[str, Any]:
    if not text.strip():
        raise AgentError(f"{name}: the header is empty")
    loader = _Header(text)
    try:
        data = loader.get_single_data()
    except _Refused as exc:
        where = f"line {exc.line + 1}: " if exc.line is not None else ""
        raise AgentError(f"{name}: header {where}{exc.problem}") from None
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f"line {mark.line + 2}: " if mark is not None else ""
        problem = getattr(exc, "problem", None) or "not valid YAML"
        raise AgentError(f"{name}: header {where}{problem}") from None
    except (ValueError, TypeError, OverflowError, RecursionError):  # a constructor's own refusal
        raise AgentError(f"{name}: the header holds a value that cannot be read") from None
    finally:
        loader.dispose()
    if not isinstance(data, dict):
        raise AgentError(f"{name}: the header must be a mapping of fields")
    _ascii(name, data)
    return data


def _odd(text: str) -> str | None:
    return next((c for c in text if not (c.isascii() and c.isprintable())), None)


def _ascii(name: str, value: Any, where: str = "") -> None:
    """Every key and value printable ASCII: the file is, but a double-quoted escape or a block
    scalar can still put another character in a value."""
    if isinstance(value, dict):
        for key, item in value.items():
            bad = _odd(str(key))
            if bad is not None:
                at = f"the header's {where}" if where else "the header"
                raise AgentError(
                    f"{name}: {at} holds U+{ord(bad):04X} in a key; values are printable ASCII too"
                )
            _ascii(name, item, f"{where}.{key}" if where else str(key))
    elif isinstance(value, list):
        for i, item in enumerate(value):
            _ascii(name, item, f"{where}.{i}")
    elif isinstance(value, str):
        bad = _odd(value)
        if bad is not None:
            raise AgentError(
                f"{name}: the header's {where} holds U+{ord(bad):04X}; values are printable"
                " ASCII too"
            )


def _front(name: str, data: dict[str, Any]) -> _Front:
    try:
        return _Front.model_validate(data)
    except ValidationError as exc:
        problems = []
        for error in exc.errors()[:3]:
            field = ".".join(str(part) for part in error["loc"])
            message = "unknown field" if error["type"] == "extra_forbidden" else error["msg"]
            problems.append(f"{field}: {message}")
        raise AgentError(f"{name}: {'; '.join(problems)}") from None


def _once(name: str, field: str, values: list[str]) -> None:
    twice = sorted({v for v in values if values.count(v) > 1})
    if twice:
        raise AgentError(f"{name}: {field} lists {', '.join(twice)} more than once")


def _bound(name: str, front: _Front, binding: Binding) -> tuple[Tier, frozenset[Trigger]]:
    """The file within what code binds: the same kind, task and output; tools, specialists,
    triggers, tier and budget no wider than the binding's."""
    agent = front.name
    for field in ("kind", "task", "output"):
        said, bound = getattr(front, field), str(getattr(binding, field))
        if said != bound:
            raise AgentError(
                f"{name}: {field} {said!r} is refused: code binds {agent} to {bound!r}"
            )
    version = VERSION.fullmatch(front.version)
    if version is None or version.group(1) != binding.kind:
        raise AgentError(f"{name}: version {front.version!r} is not {binding.kind}@<number>")
    for field, values in (("tools", front.tools), ("specialists", front.specialists),
                          ("triggers", front.triggers)):  # fmt: skip
        _once(name, field, values)
    unknown = sorted(set(front.tools) - set(catalogue.TOOLS))
    if unknown:
        raise AgentError(f"{name}: no tool {', '.join(unknown)} in the catalogue")
    wider = sorted(set(front.tools) - binding.tools)
    if wider:
        raise AgentError(f"{name}: tools beyond what code allows {agent}: {', '.join(wider)}")
    if front.specialists and binding.kind is Kind.SPECIALIST:
        raise AgentError(f"{name}: a specialist consults no one")
    wider = sorted(set(front.specialists) - binding.specialists)
    if wider:
        raise AgentError(f"{name}: specialists beyond what code allows {agent}: {', '.join(wider)}")
    known = {t.value for t in Trigger}
    unknown = sorted(set(front.triggers) - known)
    if unknown:
        raise AgentError(f"{name}: no trigger {', '.join(unknown)}")
    triggers = frozenset(Trigger(t) for t in front.triggers)
    wider = sorted(t.value for t in triggers - binding.triggers)
    if wider:
        raise AgentError(f"{name}: triggers beyond what code allows {agent}: {', '.join(wider)}")
    if front.tier not in {t.value for t in TIERS}:
        raise AgentError(f"{name}: no tier {front.tier!r} (small, medium or large)")
    tier = Tier(front.tier)
    if TIERS.index(tier) > TIERS.index(binding.tier):
        raise AgentError(
            f"{name}: tier {tier.value} is above what code allows {agent} ({binding.tier.value})"
        )
    if binding.budget is None:
        if front.budget is not None:
            raise AgentError(f"{name}: only a coordinator has a budget")
    elif front.budget is None:
        raise AgentError(f"{name}: a coordinator needs a budget")
    else:
        cap = asdict(binding.budget)
        over = [f"{k} {v} (at most {cap[k]})" for k, v in front.budget.model_dump().items()
                if v > cap[k]]  # fmt: skip
        if over:
            raise AgentError(f"{name}: a budget above what code allows {agent}: {', '.join(over)}")
    return tier, triggers


def read(path: Path, bindings: Mapping[str, Binding] = BINDINGS) -> Definition:
    """One file, checked on its own: its characters, its header and its instructions against
    the binding of the agent it names (not yet its pin)."""
    name = path.name
    data = _read(path)
    header, instructions = _split(name, _lines(name, data))
    front = _front(name, _header(name, header))
    if front.name != path.stem:
        raise AgentError(
            f"{name}: says its name is {front.name!r}: a file is named after its agent"
        )
    binding = bindings.get(front.name)
    if binding is None:
        raise AgentError(f"{name}: code binds no agent {front.name!r}")
    tier, triggers = _bound(name, front, binding)
    tools = tuple(t for t in catalogue.TOOLS if t in front.tools)
    prompt = instructions.replace(TOOLS, catalogue.lines(tools))
    with site.using(PIN_WORDS):  # the template's hash does not depend on the site's words
        pinned_prompt = instructions.replace(TOOLS, catalogue.lines(tools))
    budget = None
    if front.budget is not None:
        values = front.budget.model_dump()
        budget = Limits(**{f.name: values[f.name] for f in fields(Limits)})
    return Definition(
        name=front.name,
        kind=binding.kind,
        version=front.version,
        mission=front.mission,
        task=front.task,
        output=front.output,
        tier=tier,
        tools=tools,
        specialists=tuple(front.specialists),
        triggers=triggers,
        budget=budget,
        instructions=instructions,
        prompt=prompt,
        file_sha256=_sha(data),
        prompt_sha256=_sha(pinned_prompt.encode("utf-8")),
    )


def _files(directory: Path) -> dict[str, Path]:
    """``<name>.md`` per agent; hidden files are left alone, anything else is refused. What
    cannot be searched or read (a mode, an owner) is a refusal with the reason, never an
    OSError."""
    try:
        mode = os.lstat(directory).st_mode
    except (FileNotFoundError, NotADirectoryError):
        raise AgentError(f"no agents directory {directory}") from None
    except OSError as exc:
        raise AgentError(f"the agents directory cannot be read ({exc.strerror or exc})") from None
    if not stat.S_ISDIR(mode):  # a link to a directory included
        raise AgentError(f"no agents directory {directory}")
    try:
        entries = sorted(directory.iterdir())
    except OSError as exc:
        raise AgentError(f"the agents directory cannot be read ({exc.strerror or exc})") from None
    found: dict[str, Path] = {}
    for path in entries:
        if path.name.startswith("."):
            continue
        if path.suffix != ".md":
            raise AgentError(f"{path.name}: not an agent file ({directory.name}/ holds <name>.md)")
        try:
            mode = os.lstat(path).st_mode
        except OSError as exc:
            raise AgentError(f"{path.name}: cannot be read ({exc.strerror or exc})") from None
        if not stat.S_ISREG(mode):
            raise AgentError(f"{path.name}: must be a regular file, not a link or a directory")
        found[path.stem] = path
    return found


def pinned(definition: Definition, pins: Mapping[str, Mapping[str, Pin]] = PINS) -> None:
    """``definition`` is a version code pinned, to the byte."""
    name, version = f"{definition.name}.md", definition.version
    pin = pins.get(definition.name, {}).get(version)
    if pin is None:
        raise AgentError(
            f"{name}: {version} is not pinned in code (argus.agent.registry.PINS): a new version"
            " needs its pin, and its approval"
        )
    if definition.file_sha256 != pin.file_sha256:
        raise AgentError(
            f"{name}: is not the file pinned for {version} (sha256 {definition.file_sha256[:12]},"
            f" pinned {pin.file_sha256[:12]}): an edited file needs a new version and its pin"
        )
    if definition.prompt_sha256 != pin.prompt_sha256:
        raise AgentError(
            f"{name}: the instructions {version} gives a model changed (sha256"
            f" {definition.prompt_sha256[:12]}, pinned {pin.prompt_sha256[:12]}), so a tool's"
            " description changed: that needs a new version and its pin"
        )


def _runs(definition: Definition, enabled: Mapping[str, str | None]) -> None:
    """``definition`` is the version its agent runs: refused when the agent is off (None)
    or runs another version (or none: no entry)."""
    name = definition.name
    if name in enabled and enabled[name] is None:
        raise AgentOffError(
            f"{name}.md: holds {definition.version}, but {name} is off"
            " (argus.agent.registry.ENABLED)"
        )
    if enabled.get(name) != definition.version:
        raise AgentError(
            f"{name}.md: holds {definition.version}, but {name} runs"
            f" {enabled.get(name) or 'no version'} (argus.agent.registry.ENABLED)"
        )


def _unbound(found: Mapping[str, Path], bindings: Mapping[str, Binding]) -> None:
    unbound = sorted(set(found) - set(bindings))
    if unbound:
        raise AgentError(f"{found[unbound[0]].name}: code binds no agent '{unbound[0]}'")


def _file(found: Mapping[str, Path], name: str) -> Path:
    if name not in found:
        raise AgentError(f"no file for the agent {name} ({name}.md)")
    return found[name]


def load(
    directory: Path | None = None,
    *,
    coordinator: str = COORDINATOR,
    bindings: Mapping[str, Binding] = BINDINGS,
    pins: Mapping[str, Mapping[str, Pin]] | None = PINS,
    enabled: Mapping[str, str | None] | None = ENABLED,
) -> Agents:
    """The ``coordinator`` and the specialists its file names, from ``directory``
    (``DIRECTORY``), checked: each file on its own, then its pin (unless ``pins`` is None),
    then that it is the enabled version (unless ``enabled`` is None: an evaluation's view of
    a pinned version not switched on), then that each specialist is one. Raises AgentError
    with the first reason found.

    Only this family's files decide: another bound agent that is off, refused or missing
    (``survey`` gives its state) never refuses it. A file code binds no agent to is refused
    (a stray file in the directory is someone's mistake to see)."""
    found = _files(DIRECTORY if directory is None else directory)
    _unbound(found, bindings)
    lead = read(_file(found, coordinator), bindings)
    if lead.kind is not Kind.COORDINATOR:
        raise AgentError(f"no coordinator {coordinator!r}")
    family = {coordinator: lead}
    for name in sorted(lead.specialists):
        family[name] = read(_file(found, name), bindings)
    for definition in family.values():  # the coordinator, then its specialists by name
        if pins is not None:
            pinned(definition, pins)
        if enabled is not None:
            _runs(definition, enabled)
    for name in lead.specialists:
        if family[name].kind is not Kind.SPECIALIST:
            raise AgentError(f"{coordinator}.md: {name} is not a specialist")
    return Agents(MappingProxyType(family), coordinator)


def survey(
    directory: Path | None = None,
    *,
    bindings: Mapping[str, Binding] = BINDINGS,
    pins: Mapping[str, Mapping[str, Pin]] | None = PINS,
    enabled: Mapping[str, str | None] | None = ENABLED,
) -> dict[str, Definition | AgentError]:
    """Each agent's own state, for doctor: every bound agent, and every file code binds no
    agent to, by name: its definition (read, pinned; off is a state, not a refusal) or why
    it is refused. Raises AgentError when the directory itself cannot be listed."""
    found = _files(DIRECTORY if directory is None else directory)
    out: dict[str, Definition | AgentError] = {}
    for name in sorted(set(bindings) | set(found)):
        try:
            if name not in bindings:
                _unbound({name: found[name]}, bindings)
            definition = read(_file(found, name), bindings)
            if pins is not None:
                pinned(definition, pins)
            if enabled is not None and enabled.get(name) is not None:
                _runs(definition, enabled)
            out[name] = definition
        except AgentError as exc:
            out[name] = exc
    return out


def takes(
    trigger: Trigger,
    directory: Path | None = None,
    *,
    pins: Mapping[str, Mapping[str, Pin]] | None = PINS,
    enabled: Mapping[str, str | None] | None = ENABLED,
) -> Agents | None:
    """The agents, when they load (pinned and enabled, by default) and ``trigger`` may start
    the coordinator; None on any refusal and on any error reading them (a page asking for
    the agent says it is not available, and nothing is queued)."""
    try:
        agents = load(directory, pins=pins, enabled=enabled)
    except (AgentError, OSError):
        return None
    return agents if agents.takes(trigger) else None


def allows(
    trigger: Trigger,
    directory: Path | None = None,
    *,
    pins: Mapping[str, Mapping[str, Pin]] | None = PINS,
    enabled: Mapping[str, str | None] | None = ENABLED,
) -> bool:
    """``takes`` as a yes or no."""
    return takes(trigger, directory, pins=pins, enabled=enabled) is not None
