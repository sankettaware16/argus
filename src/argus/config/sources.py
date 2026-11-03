"""Where configuration comes from: the YAML file, the ``.env`` file, the environment and systemd's
credential directory. Each is read into a :class:`Layer` (settings-shaped data, the origin of each
value and the problems found); problems are collected so one report lists every mistake, and an
unreadable file raises :class:`ConfigError`. Names that are not settings are errors, messages
never hold values, and work is bounded by limits on file size, nesting, keys and ``${VAR}``
expansion."""

from __future__ import annotations

import codecs
import difflib
import io
import json
import os
import re
import stat
from collections.abc import Hashable, Mapping
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, NamedTuple, get_args

import yaml
from dotenv.parser import Binding, parse_stream
from pydantic import BaseModel, SecretStr
from yaml.error import Mark, MarkedYAMLError
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode
from yaml.reader import ReaderError

from argus.config.errors import ConfigError, safe, show_name

CONFIG_ENV_VAR = "ARGUS_CONFIG"
CREDENTIALS_ENV_VAR = "CREDENTIALS_DIRECTORY"  # set by systemd for a unit with LoadCredential=
ENV_PREFIX = "ARGUS_"
ENV_NESTED_DELIMITER = "__"

MAX_FILE_BYTES = 1024 * 1024  # config files are a few KiB
MAX_YAML_NESTING = 32  # settings are two levels deep; the YAML composer recurses per level
MAX_YAML_KEYS = 10_000  # in one file, counting each key a merge copies: `<<: [*a, *a, ...]`
MAX_YAML_INT_CHARS = 4300  # CPython's int() limit; PyYAML's base-60 (1:30:00) parsing is quadratic
MAX_ENV_LINE_CHARS = 16 * 1024  # a token or a key written on one line is a few KiB
MAX_ENV_BLANKS = 256  # in a row on one line; python-dotenv's time is quadratic in their number
MAX_ENV_EXPANDED_CHARS = 4 * MAX_FILE_BYTES  # all .env values together, ${VAR} expanded
_MAX_SUGGESTIONS = 50  # "did you mean" is worked out for this many unknown names per source
MAX_CREDENTIALS = 64  # a unit loads a handful; a directory with more is not a credential directory
# A credential named section.key sets that secret setting; a name with any other character
# (web-tls.key, llm-api-keys.env) is a file that a setting or the LLM gateway names by its path.
CREDENTIAL_SETTING = re.compile(r"[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*")

_LINE_BREAK = re.compile(r"\r\n|\n|\r")  # python-dotenv's line breaks too
_LINE_BREAK_BYTES = re.compile(rb"\r\n|\n|\r")
_SPACE = re.compile(r"\s")
# Found in linear time: a match can only start where a line, or a run of blanks, starts.
_LONG_ENV_LINE = re.compile(rf"(?<![^\r\n])[^\r\n]{{{MAX_ENV_LINE_CHARS + 1}}}")
_LONG_ENV_BLANKS = re.compile(rf"(?<![^\S\r\n])[^\S\r\n]{{{MAX_ENV_BLANKS + 1}}}")
_REFERENCE_END = re.compile(r"[}:]")
_YAML_LINE_BREAK = re.compile(r"\r\n|[\r\n\x85\u2028\u2029]")  # YAML 1.1 line breaks
_MERGE_TAG = "tag:yaml.org,2002:merge"
_VALUE_TAG = "tag:yaml.org,2002:value"
_INT_TAG = "tag:yaml.org,2002:int"
_STR_TAG = "tag:yaml.org,2002:str"
_TAG_NAMES = {
    "tag:yaml.org,2002:bool": "true/false value",
    "tag:yaml.org,2002:float": "number",
    _INT_TAG: "integer",
    "tag:yaml.org,2002:null": "null",
    "tag:yaml.org,2002:timestamp": "date",
}
# PyYAML quotes user text in some messages: tag, tag handle, alias and anchor names. Those can be
# a value: an unquoted value starting with '!' is read as a tag, one starting with '*' as an
# alias. A quoted fragment is shown only when it is one character or the name of a YAML token
# ("expected <block end>, but found '<scalar>'"); everything else is hidden.
_QUOTED = re.compile(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"")
_ONE_CHARACTER = re.compile(r"\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|\\U[0-9a-f]{8}|\\.|[^\\]")
_TOKEN_NAMES = frozenset(
    {
        "<alias>",
        "<anchor>",
        "<block end>",
        "<block mapping start>",
        "<block sequence start>",
        "<directive>",
        "<document end>",
        "<document start>",
        "<scalar>",
        "<stream end>",
        "<stream start>",
        "<tag>",
    }
)
_QUOTE_HINTS = (
    ("constructor for the tag", "!"),
    ("tag handle", "!"),
    ("undefined alias", "*"),
    ("duplicate anchor", "&"),
)
# What PyYAML's scalar constructors raise for a value their tag cannot build, e.g. int('5d').
_CONSTRUCTOR_FAILURES = (ValueError, TypeError, KeyError, AttributeError, IndexError, OverflowError)


class _StrictYAMLError(MarkedYAMLError):
    """A problem found by ARGUS's own YAML checks; its text never contains user values."""

    def __init__(self, problem: str, mark: Mark | None) -> None:
        super().__init__(problem=problem, problem_mark=mark)


@dataclass
class Layer:
    """What one source contributes to the settings."""

    data: dict[str, Any] = field(default_factory=dict)
    """Settings shaped like the model, e.g. ``{"history": {"window": "30d"}}``."""
    origins: dict[tuple[str, ...], str] = field(default_factory=dict)
    """Where each setting path is set, e.g. ``ARGUS_HISTORY__WINDOW in .env line 3``."""
    problems: list[str] = field(default_factory=list)
    """Readable problems, safe to print."""


class _Variable(NamedTuple):
    name: str
    value: str
    origin: str
    problem: str | None = None  # already known to be unusable; reported in variable order


def section_model(model: type[BaseModel], name: str) -> type[BaseModel] | None:
    """The model of section ``name`` (e.g. ``HistorySettings``), or None for any other name."""
    info = model.model_fields.get(name)
    annotation = None if info is None else info.annotation
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return annotation
    return None


# --------------------------------------------------------------------------- files


def _read_capped(path: Path, kind: str) -> bytes | None:
    """The content of a regular file of at most MAX_FILE_BYTES, or None if there is no file.
    Anything but a regular file is refused before a byte is read: a FIFO or /dev/stdin would wait
    forever and /dev/zero never ends. O_NONBLOCK stops the open from waiting for a FIFO's writer,
    O_NOCTTY stops a terminal from becoming ARGUS's controlling terminal."""
    where = safe(path)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _unreadable(kind, where, exc) from None
    try:
        mode = os.fstat(descriptor).st_mode
        if not stat.S_ISREG(mode):
            what = "it is a directory" if stat.S_ISDIR(mode) else "it is not a regular file"
            raise ConfigError(f"cannot read {kind} {where}: {what}")
        os.set_blocking(descriptor, True)
        with open(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise _unreadable(kind, where, exc) from None
    finally:
        os.close(descriptor)
    if len(raw) > MAX_FILE_BYTES:
        limit = MAX_FILE_BYTES // 1024
        raise ConfigError(f"{kind} {where} is larger than {limit} KiB; is it the right file?")
    return raw


def _unreadable(kind: str, where: str, exc: OSError) -> ConfigError:
    reason = safe(exc.strerror or type(exc).__name__)
    return ConfigError(f"cannot read {kind} {where}: {reason}")


def _decode(raw: bytes, what: str) -> str:
    body = raw.removeprefix(codecs.BOM_UTF8)
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError as exc:
        line = len(_LINE_BREAK_BYTES.findall(body, 0, exc.start)) + 1
        raise ConfigError(f"{what} is not UTF-8 text (line {line}); save it as UTF-8") from None


def _kind(value: object) -> str:
    if isinstance(value, bool):
        return "true/false"
    if isinstance(value, int | float):
        return "a number"
    if isinstance(value, str):
        return "text"
    if isinstance(value, list):
        return "a list"
    if isinstance(value, dict):
        return "a mapping"
    if isinstance(value, date):
        return "a date"
    return type(value).__name__


# --------------------------------------------------------------------------- YAML


class _ConfigLoader(yaml.SafeLoader):
    """``yaml.SafeLoader`` with the strictness a config file needs: a repeated key is an error
    (``<<`` merges still work); keys are their literal text (``on:`` and ``1:`` are names, not a
    bool or an int); a value its tag cannot build is a YAML error with a position; and work is
    bounded before it is done (nesting, key count including merged copies, integer length)."""

    def __init__(self, stream: str) -> None:
        self._depth = 0
        self._keys = 0  # keys of the mappings flattened so far, merged copies included
        self._flattened: set[int] = set()  # ids of the mappings whose merges are applied
        super().__init__(stream)

    def compose_node(self, parent: Node | None, index: int) -> Node | None:
        self._depth += 1
        try:
            if self._depth > MAX_YAML_NESTING:
                problem = f"nesting is deeper than {MAX_YAML_NESTING} levels"
                event = self.peek_event()  # type: ignore[no-untyped-call]  # untyped in the stubs
                raise _StrictYAMLError(problem, event.start_mark)
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1

    def construct_document(self, node: Node) -> Any:
        _reject_duplicate_keys(node)
        return super().construct_document(node)

    def construct_object(self, node: Node, deep: bool = False) -> Any:
        try:
            return super().construct_object(node, deep=deep)
        except yaml.YAMLError:
            raise
        except _CONSTRUCTOR_FAILURES:
            kind = _TAG_NAMES.get(node.tag, "value for its tag")
            problem = f"this is not a valid {kind} (quote it if it is meant as text)"
            raise _StrictYAMLError(problem, node.start_mark) from None

    def flatten_mapping(self, node: MappingNode) -> None:
        """Apply the mapping's ``<<`` merges as PyYAML does (merged keys first, so the mapping's
        own keys win; the first listed mapping wins), counting keys before copying them: each
        mapping is flattened once, a merge never copies past MAX_YAML_KEYS."""
        if id(node) in self._flattened:
            return
        self._flattened.add(id(node))
        merges: list[tuple[Node, Node]] = []
        own: list[tuple[Node, Node]] = []
        for key_node, value_node in node.value:
            if key_node.tag == _MERGE_TAG:
                merges.append((key_node, value_node))
                continue
            if key_node.tag == _VALUE_TAG:  # as PyYAML: a '=' key is plain text
                key_node.tag = _STR_TAG
            own.append((key_node, value_node))
        self._count_keys(len(own), node.start_mark)
        node.value = own  # before merging: a mapping can merge itself (or an ancestor)
        merged: list[tuple[Node, Node]] = []
        for key_node, value_node in merges:
            sources = _merge_sources(value_node)
            for source in sources:
                self.flatten_mapping(source)
            for source in reversed(sources):  # later entries win, so the first listed goes last
                self._count_keys(len(source.value), key_node.start_mark)
                merged.extend(source.value)
        if merged:
            node.value = merged + own

    def _count_keys(self, count: int, mark: Mark) -> None:
        self._keys += count
        if self._keys > MAX_YAML_KEYS:
            problem = f"more than {MAX_YAML_KEYS} keys, counting the keys that '<<' merges copy"
            raise _StrictYAMLError(problem, mark)

    def _construct_int(self, node: ScalarNode) -> int:
        if isinstance(node.value, str) and len(node.value) > MAX_YAML_INT_CHARS:
            problem = f"an integer of more than {MAX_YAML_INT_CHARS} characters is not supported"
            raise _StrictYAMLError(problem, node.start_mark)
        return self.construct_yaml_int(node)

    def construct_mapping(self, node: Node, deep: bool = False) -> dict[Hashable, Any]:
        if not isinstance(node, MappingNode):
            raise _StrictYAMLError("expected a mapping here", node.start_mark)
        self.flatten_mapping(node)
        mapping: dict[Hashable, Any] = {}
        for key_node, value_node in node.value:
            if not isinstance(key_node, ScalarNode):
                raise _StrictYAMLError("a key must be plain text", key_node.start_mark)
            mapping[key_node.value] = self.construct_object(value_node, deep=deep)
        return mapping


# Registered on the subclass only: add_constructor copies the table before changing it.
_ConfigLoader.add_constructor(_INT_TAG, _ConfigLoader._construct_int)


def _merge_sources(value_node: Node) -> list[MappingNode]:
    if isinstance(value_node, MappingNode):
        return [value_node]
    if not isinstance(value_node, SequenceNode):
        raise _StrictYAMLError("'<<' merges a mapping or a list of mappings", value_node.start_mark)
    for item in value_node.value:
        if not isinstance(item, MappingNode):
            raise _StrictYAMLError("'<<' merges only mappings; this is not one", item.start_mark)
    return list(value_node.value)


def _reject_duplicate_keys(root: Node) -> None:
    """Raise on a key repeated within one mapping. Runs before merges are applied."""
    pending = [root]
    visited: set[int] = set()
    while pending:
        node = pending.pop()
        if id(node) in visited:  # aliases share nodes; each is checked once
            continue
        visited.add(id(node))
        if isinstance(node, SequenceNode):
            pending.extend(node.value)
        elif isinstance(node, MappingNode):
            first: dict[str, Node] = {}
            for key_node, value_node in node.value:
                pending.append(value_node)
                if key_node.tag == _MERGE_TAG or not isinstance(key_node, ScalarNode):
                    continue
                earlier = first.get(key_node.value)
                if earlier is None:
                    first[key_node.value] = key_node
                    continue
                # Compared by text: a key repeated through an alias (`*k :`) is the same node.
                if earlier is key_node:
                    where = "repeated in this mapping through an alias"
                else:
                    where = f"first on line {earlier.start_mark.line + 1}"
                problem = f"duplicate key {key_node.value!a} ({where})"
                raise _StrictYAMLError(problem, key_node.start_mark)


def _shown(fragment: str) -> bool:
    return fragment in _TOKEN_NAMES or _ONE_CHARACTER.fullmatch(fragment) is not None


def _without_library_text(part: str) -> str:
    """PyYAML appends the text of a library exception to "failed to ..." (decoding !!binary,
    say), and that text can quote the value (``'ascii' codec can't encode character '\\xe9'
    in position 3``) or garble the quote pairing _scrub relies on: keep only PyYAML's own
    words."""
    return part.partition(": ")[0] if part.startswith("failed to ") else part


def _scrub(detail: str) -> str:
    """A PyYAML message without the user text it quotes, plus a hint where that text came from."""
    scrubbed = _QUOTED.sub(
        lambda match: match[0] if _shown(match[0][1:-1]) else "(not shown)", detail
    )
    if _VALUE_TAG in detail or _MERGE_TAG in detail:  # a bare '=' or '<<' is read as a tag
        return f"{scrubbed}; a value that is just '=' or '<<' must be quoted"
    for phrase, char in _QUOTE_HINTS:
        if phrase in detail:
            return f"{scrubbed}; a value that starts with {char!r} must be quoted"
    return scrubbed


def _text_position(text: str, index: int) -> tuple[int, int]:
    breaks = list(_YAML_LINE_BREAK.finditer(text, 0, index))
    line_start = breaks[-1].end() if breaks else 0
    return len(breaks) + 1, index - line_start + 1


def _yaml_error(where: str, exc: Exception, text: str) -> ConfigError:
    """A positioned message for a YAML error. Never includes the offending text itself."""
    line = column = None
    detail = ""
    if isinstance(exc, ReaderError):  # an unprintable character; ReaderError has no mark
        if isinstance(exc.position, int):
            line, column = _text_position(text, exc.position)
        if isinstance(exc.character, int):
            detail = f"unprintable character U+{exc.character:04X} is not allowed"
    elif isinstance(exc, MarkedYAMLError):
        mark = exc.problem_mark or exc.context_mark
        if mark is not None:
            line, column = mark.line + 1, mark.column + 1
        parts = [part for part in (exc.context, exc.problem) if part]
        if not isinstance(exc, _StrictYAMLError):
            parts = [_without_library_text(part) for part in parts]
        detail = ", ".join(parts)
        if not isinstance(exc, _StrictYAMLError):
            detail = _scrub(detail)
    elif isinstance(exc, RecursionError):
        detail = "nesting is too deep"
    message = f"config file {where} is not valid YAML"
    if line is not None:
        message += f" (line {line}, column {column})"
    return ConfigError(f"{message}: {safe(detail)}" if detail else message)


def read_yaml_file(path: Path) -> tuple[dict[str, Any], Node | None]:
    """Parse the YAML config file: its top-level mapping and the composed node tree."""
    where = safe(path)
    raw = _read_capped(path, "config file")
    if raw is None:
        raise ConfigError(f"config file not found: {where}")
    text = _decode(raw, f"config file {where}")
    loader: _ConfigLoader | None = None
    try:
        loader = _ConfigLoader(text)
        root = loader.get_single_node()
        data = None if root is None else loader.construct_document(root)
    except (yaml.YAMLError, RecursionError) as exc:  # constructor failures are YAML errors by now
        raise _yaml_error(where, exc, text) from None
    finally:
        if loader is not None:
            loader.dispose()
    if data is None:  # an empty file, or only comments
        return {}, None
    if not isinstance(data, dict):
        raise ConfigError(
            f"config file {where} must contain a mapping of settings at the top level,"
            f" not {_kind(data)}"
        )
    return data, root


def _key_lines(root: Node | None, model: type[BaseModel]) -> dict[tuple[str, ...], int]:
    lines: dict[tuple[str, ...], int] = {}
    if not isinstance(root, MappingNode):
        return lines
    for key_node, value_node in root.value:  # merges are applied: later pairs win, as in data
        name = key_node.value
        lines[(name,)] = key_node.start_mark.line + 1
        if section_model(model, name) is not None and isinstance(value_node, MappingNode):
            for sub_node, _ in value_node.value:
                lines[(name, sub_node.value)] = sub_node.start_mark.line + 1
    return lines


def yaml_layer(path: Path, model: type[BaseModel]) -> Layer:
    """The YAML config file as a layer. Raises ConfigError if it cannot be read or parsed."""
    data, root = read_yaml_file(path)
    short = safe(path.name)  # the report header names the full path
    layer = Layer(data=data)
    for key, line in _key_lines(root, model).items():
        layer.origins[key] = f"{short} line {line}"
    for name in list(data):
        section = section_model(model, name)
        if section is None:
            continue
        value = data[name]
        if value is None:  # an empty section, e.g. every key commented out: the defaults
            del data[name]
        elif isinstance(value, dict):
            _protect_secrets(section, value)
        else:
            # Checked here, not by validation: a higher source setting any key of this section
            # (.env always sets the database password) would silently replace the bad value.
            origin = layer.origins.get((name,))
            layer.problems.append(
                f"{show_name(name)}: must be a section of indented 'key: value' lines,"
                f" not {_kind(value)}" + (f" [{origin}]" if origin else "")
            )
            del data[name]
    return layer


# --------------------------------------------------------------------------- environment, .env


def _is_argus_name(name: str) -> bool:
    head = name[: len(ENV_PREFIX)]
    return head.isascii() and head.upper() == ENV_PREFIX


def _binding_line(binding: Binding) -> int:
    """Line of the binding's first character (python-dotenv counts from preceding blank lines)."""
    text = binding.original.string
    leading = text[: len(text) - len(text.lstrip())]
    return binding.original.line + len(_LINE_BREAK.findall(leading))


_MAX_LISTED_LINES = 20


def _line_list(lines: list[int]) -> str:
    """Like "line 3" or "lines 3, 7 and 9"; beyond 20, the first 20 and how many more (a file
    of broken lines must not make a message as big as itself)."""
    if len(lines) == 1:
        return f"line {lines[0]}"
    if len(lines) > _MAX_LISTED_LINES:
        shown = ", ".join(map(str, lines[:_MAX_LISTED_LINES]))
        return f"lines {shown} and {len(lines) - _MAX_LISTED_LINES} more"
    return f"lines {', '.join(map(str, lines[:-1]))} and {lines[-1]}"


def _json_object(text: str) -> dict[str, Any] | None:
    try:
        value = json.loads(text)
    except (ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def _is_secret(annotation: object) -> bool:
    return annotation is SecretStr or SecretStr in get_args(annotation)


def _protect_secrets(section: type[BaseModel], values: dict[str, Any]) -> None:
    """Wrap secret values in SecretStr as soon as they are read, so no repr can show them."""
    for key, value in values.items():
        info = section.model_fields.get(key)
        if info is not None and isinstance(value, str) and _is_secret(info.annotation):
            values[key] = SecretStr(value)


def _variable_names(model: type[BaseModel]) -> list[str]:
    names = [CONFIG_ENV_VAR]
    for name in model.model_fields:
        names.append(f"{ENV_PREFIX}{name.upper()}")
        section = section_model(model, name)
        if section is not None:
            prefix = f"{ENV_PREFIX}{name.upper()}{ENV_NESTED_DELIMITER}"
            names.extend(f"{prefix}{key.upper()}" for key in section.model_fields)
    return names


def _unknown_variable(variable: _Variable, names: list[str], *, suggest: bool) -> str:
    close = []
    if suggest:
        close = difflib.get_close_matches(variable.name.upper(), names, n=1, cutoff=0.8)
    if close:
        hint = f"; did you mean {close[0]}?"
        if ENV_NESTED_DELIMITER in close[0] and ENV_NESTED_DELIMITER not in variable.name:
            hint += " (nested keys use a double underscore)"
    else:
        nested = f"{ENV_PREFIX}<SECTION>{ENV_NESTED_DELIMITER}<KEY>"
        example = next((name for name in names if ENV_NESTED_DELIMITER in name), names[-1])
        hint = f"; settings are {ENV_PREFIX}<NAME> or {nested}, e.g. {example}"
    return f"{variable.origin} is not a known setting{hint}"


def _section_problem(variable: _Variable, name: str, section: type[BaseModel]) -> str:
    prefix = f"{ENV_PREFIX}{name.upper()}{ENV_NESTED_DELIMITER}"
    example = next(iter(section.model_fields), "key").upper()
    return (
        f"{variable.origin} sets the whole {name} section, so its value must be a JSON object;"
        f" to set one key use {prefix}<KEY>, e.g. {prefix}{example}"
    )


def _apply(layer: Layer, variables: list[_Variable], model: type[BaseModel]) -> None:
    """Map ARGUS_<NAME> and ARGUS_<SECTION>__<KEY> variables onto the layer's settings."""
    names = _variable_names(model)
    unknown = 0
    first_seen: dict[str, str] = {}
    keyed: list[tuple[str, str, _Variable]] = []
    for variable in variables:
        upper = variable.name.upper()
        if upper in first_seen:
            layer.problems.append(
                f"{first_seen[upper]} and {variable.origin} set the same setting; keep one"
            )
            continue
        first_seen[upper] = variable.origin
        if variable.problem is not None:
            layer.problems.append(variable.problem)
            continue
        rest = variable.name[len(ENV_PREFIX) :]
        parts = rest.lower().split(ENV_NESTED_DELIMITER)
        name = parts[0]
        section = section_model(model, name)
        if (
            not rest.isascii()
            or name not in model.model_fields
            or len(parts) > 2
            or (
                len(parts) == 2
                # An unknown key is reported here, by origin: pydantic's own error would echo
                # the key, which may hold a value typed without "=".
                and (section is None or not parts[1] or parts[1] not in section.model_fields)
            )
        ):
            unknown += 1
            suggest = unknown <= _MAX_SUGGESTIONS
            layer.problems.append(_unknown_variable(variable, names, suggest=suggest))
        elif len(parts) == 2:
            keyed.append((name, parts[1], variable))
        elif section is None:
            layer.data[name] = variable.value
            layer.origins[(name,)] = variable.origin
        elif (values := _json_object(variable.value)) is None:
            layer.problems.append(_section_problem(variable, name, section))
        else:
            layer.data[name] = values
            layer.origins[(name,)] = variable.origin
            for key in values:
                layer.origins[(name, key)] = variable.origin
    # A key set on its own overrides the same key inside a whole-section JSON value.
    for name, key, variable in keyed:
        layer.data.setdefault(name, {})[key] = variable.value
        layer.origins[(name, key)] = variable.origin
    for name, values in layer.data.items():
        section = section_model(model, name)
        if section is not None and isinstance(values, dict):
            _protect_secrets(section, values)


def environment_layer(environ: Mapping[str, str], model: type[BaseModel]) -> Layer:
    """``ARGUS_*`` variables from the process environment; other variables are ignored."""
    layer = Layer()
    variables: list[_Variable] = []
    for name in sorted(environ):
        if name == CONFIG_ENV_VAR or not _is_argus_name(name):
            continue
        origin = f"environment variable {show_name(name)}"
        problem = None
        if name.upper() == CONFIG_ENV_VAR:
            problem = f"{origin} is ignored: the config file variable is spelled {CONFIG_ENV_VAR}"
        variables.append(_Variable(name, environ[name], origin, problem))
    _apply(layer, variables, model)
    return layer


def dotenv_layer(env_file: Path | None, model: type[BaseModel]) -> Layer | None:
    """``ARGUS_*`` variables from the ``.env`` file, or None when there is no such file.

    Every line must parse (python-dotenv skips one it cannot read, and an unterminated quote can
    swallow the following lines). Variables without the ``ARGUS_`` prefix belong to other tools
    and are ignored, their names never printed: a secret pasted onto a line of its own would
    otherwise be shown as an unknown name. A path that is not a readable regular file is an error,
    and so is a line python-dotenv would take long to read (see _check_env_lines)."""
    if env_file is None:
        return None
    where = safe(env_file)
    raw = _read_capped(env_file, "env file")
    if raw is None:
        return None  # no .env is normal, e.g. when secrets come from the environment
    text = _decode(raw, f"env file {where}")
    _check_env_lines(text, where)
    bindings = list(parse_stream(io.StringIO(text)))
    # A name with a space or line break comes from a quoted name ('A B'=x) that can run over
    # later lines, so printing it could print a value from one of them.
    broken = [
        _binding_line(binding)
        for binding in bindings
        if binding.error or (binding.key is not None and _SPACE.search(binding.key))
    ]
    if broken:
        raise ConfigError(
            f"cannot parse env file {where} ({_line_list(broken)}): write each setting as"
            " NAME=value on its own line; lines starting with # are comments"
        )
    short = safe(env_file.name)  # the report header names the full path
    layer = Layer()
    variables: list[_Variable] = []
    known = {name.upper() for name in _variable_names(model)}
    for binding, value in zip(bindings, _expand_variables(bindings, where=where), strict=True):
        name = binding.key
        if name is None or not _is_argus_name(name):
            continue
        # Only a known name is printed: a line whose "=" is missing or misplaced
        # (ARGUS_DATABASE__PASSWORD<secret>, ARGUS_DATABASE__PASSWORD_<secret>=x) puts the value
        # into the name, so an unknown name is reported by its line number alone.
        shown = show_name(name) if name.upper() in known else "an ARGUS_ variable"
        origin = f"{shown} in {short} line {_binding_line(binding)}"
        problem = None
        if name.upper() == CONFIG_ENV_VAR:
            problem = (
                f"{origin} is not used: choose the config file with --config or the"
                f" {CONFIG_ENV_VAR} environment variable"
            )
        elif value is None:
            problem = f"{origin} has no value (expected NAME=value)"
        variables.append(_Variable(name, value or "", origin, problem))
    _apply(layer, variables, model)
    return layer


def _check_env_lines(text: str, where: str) -> None:
    """Refuse a line that python-dotenv would take long to read, naming only its number: a run of
    blanks longer than MAX_ENV_BLANKS (its comment stripping is quadratic in it) or a line longer
    than MAX_ENV_LINE_CHARS."""
    for pattern, problem in (
        (_LONG_ENV_LINE, f"is longer than {MAX_ENV_LINE_CHARS} characters"),
        (_LONG_ENV_BLANKS, f"has more than {MAX_ENV_BLANKS} spaces or other blanks in a row"),
    ):
        match = pattern.search(text)
        if match is not None:
            line = len(_LINE_BREAK.findall(text, 0, match.start())) + 1
            raise ConfigError(f"env file {where} line {line} {problem}; is it the right file?")


def _expand_variables(bindings: list[Binding], *, where: str = ".env") -> list[str | None]:
    """Each binding's value with ``${VAR}`` expanded as python-dotenv does: the value of VAR on an
    earlier line, else in the environment (``${VAR:-x}`` falls back to x). Linear in the file's
    size, and the values together may hold at most MAX_ENV_EXPANDED_CHARS characters."""
    known: dict[str, str | None] = dict(os.environ)
    values: list[str | None] = []
    room = MAX_ENV_EXPANDED_CHARS
    for binding in bindings:
        value = None
        if binding.value is not None:
            value = _expand(binding.value, known, room)
            if value is None:
                limit = MAX_ENV_EXPANDED_CHARS // 1024
                raise ConfigError(
                    f"env file {where} line {_binding_line(binding)}: with ${{VAR}} references"
                    f" expanded, the values come to more than {limit} KiB"
                )
            room -= len(value)
        if binding.key is not None:
            known[binding.key] = value
        values.append(value)
    return values


def _expand(value: str, known: Mapping[str, str | None], limit: int) -> str | None:
    """``value`` with its references replaced, or None if the result is longer than ``limit``.
    The references are the ones python-dotenv's ``parse_variables`` finds, in one pass: a name
    runs from "${" to the first '}' or ':', and after ":-" a default runs to the next '}'.
    ``${NAME}`` is NAME's value in ``known``, else the default, else empty."""
    pieces: list[str] = []
    size = 0
    copied = 0  # value[:copied] is in pieces
    start = value.find("${")
    while start != -1:
        end = _REFERENCE_END.search(value, start + 2)
        if end is None:
            break  # nothing closes this "${", so nothing closes a later one
        stop = close = end.start()  # where the name stops; the '}' that closes the reference
        default = None
        if end[0] == ":":
            if not value.startswith(":-", stop):
                start = value.find("${", stop + 1)  # every "${" before this ':' stops there too
                continue
            close = value.find("}", stop + 2)
            if close == -1:
                break  # no '}' is left to close any "${"
            default = value[stop + 2 : close]
        replacement = known.get(value[start + 2 : stop], default or "") or ""
        size += start - copied + len(replacement)
        if size > limit:
            return None
        pieces.extend((value[copied:start], replacement))
        copied = close + 1
        start = value.find("${", copied)
    size += len(value) - copied
    if size > limit:
        return None
    pieces.append(value[copied:])
    return "".join(pieces)


def credentials_layer(directory: Path | None, model: type[BaseModel]) -> Layer | None:
    """Secrets from systemd's credential directory (``$CREDENTIALS_DIRECTORY``, filled from
    root-owned files by ``LoadCredential=``), or None without one.

    A credential named ``section.key`` (``database.password``) sets that secret setting to its
    whole content, less one final line break. A credential named like another setting is an error;
    one with any other name (``web-tls.key``) is a file a setting names by path and is not read
    here. Each file is a regular file of at most 1 MiB, UTF-8. Messages name credentials, never
    their content."""
    if directory is None:
        return None
    where = safe(directory)
    try:
        names = sorted(os.listdir(directory))
    except FileNotFoundError:
        raise ConfigError(
            f"the credential directory {where} ({CREDENTIALS_ENV_VAR}) does not exist"
        ) from None
    except OSError as exc:
        raise _unreadable("the credential directory", where, exc) from None
    if len(names) > MAX_CREDENTIALS:
        raise ConfigError(
            f"the credential directory {where} holds more than {MAX_CREDENTIALS} files;"
            f" is {CREDENTIALS_ENV_VAR} right?"
        )
    layer = Layer()
    for name in names:
        if not CREDENTIAL_SETTING.fullmatch(name):
            continue
        origin = f"credential {name}"
        section_name, key = name.split(".")
        section = section_model(model, section_name)
        info = None if section is None else section.model_fields.get(key)
        if info is None or not _is_secret(info.annotation):
            what = "a secret setting" if info is None else "a secret setting (it is not secret)"
            layer.problems.append(
                f"{origin} is not {what}: a credential holds a password or key, named"
                " section.key (database.password); other settings go in the environment"
            )
            continue
        raw = _read_capped(directory / name, "credential")
        if raw is None:  # gone since the listing
            continue
        text = _decode(raw, origin)
        value = text.removesuffix("\n").removesuffix("\r") if text.endswith("\n") else text
        if not value:
            layer.problems.append(f"{origin} is empty")
            continue
        layer.data.setdefault(section_name, {})[key] = SecretStr(value)
        layer.origins[(section_name, key)] = origin
    return layer


def overrides_layer(overrides: Mapping[str, Any]) -> Layer:
    """Keyword overrides from code (tests, CLI flags). Only their origins are needed."""
    layer = Layer()
    for name, value in overrides.items():
        layer.origins[(name,)] = "override"
        if isinstance(value, Mapping):
            for key in value:
                layer.origins[(name, str(key))] = "override"
    return layer
