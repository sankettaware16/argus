"""Anthropic's Messages API, spoken through ARGUS's own transport: the answer's JSON schema in the
form Anthropic's structured outputs take, a model's ``extra`` merged into a body, the reply read
(text blocks only, never thinking; a refusal and a cut-off apart) and the errors that need their
own handling. Pure functions: the gateway builds, checks and sends the bytes."""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

# What structured outputs take (Anthropic's documentation): basic types, enum, const, anyOf,
# allOf, local $ref/$defs, these string formats and minItems 0 or 1; every object closed.
FORMATS = frozenset(
    {"date-time", "time", "date", "duration", "email", "hostname", "uri", "ipv4", "ipv6", "uuid"}
)
TYPES = frozenset({"object", "array", "string", "integer", "number", "boolean", "null"})
# Constraints it does not take. Dropping one only widens what is valid, so an answer valid under
# the original schema is valid under the sent one; ARGUS validates every answer itself.
DROPPED = frozenset({
    "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf",
    "minLength", "maxLength", "pattern", "maxItems", "uniqueItems", "contains", "minContains",
    "maxContains", "minProperties", "maxProperties", "propertyNames", "dependentRequired",
    "dependentSchemas", "if", "then", "else", "contentEncoding", "contentMediaType",
    "contentSchema", "title", "default", "examples", "$comment", "$schema", "deprecated",
    "readOnly", "writeOnly",
})  # fmt: skip
_KEPT = frozenset({
    "type", "enum", "const", "properties", "required", "additionalProperties", "items",
    "anyOf", "oneOf", "allOf", "$ref", "$defs", "definitions", "format", "minItems",
    "description",
})  # fmt: skip
_SHAPED = ("type", "enum", "const", "anyOf", "allOf", "$ref")  # a schema names one of these
_REF = re.compile(r"#/(\$defs|definitions)/([A-Za-z0-9_.-]{1,64})")  # matched whole


class _Inexpressible(Exception):  # noqa: N818 - control flow inside output_schema
    pass


def _scalar(value: Any) -> bool:
    return value is None or isinstance(value, str | int | float | bool)


def _is_object(node: Mapping[str, Any]) -> bool:
    kind = node.get("type")
    kinds = kind if isinstance(kind, list) else [kind]
    return "object" in kinds or "properties" in node or "required" in node


def _types(value: Any) -> str | list[str]:
    kinds = value if isinstance(value, list) else [value]
    if not kinds or any(not isinstance(k, str) or k not in TYPES for k in kinds):
        raise _Inexpressible("type")
    if len(set(kinds)) != len(kinds):
        raise _Inexpressible("type")
    return list(kinds) if isinstance(value, list) else str(value)


Defs = frozenset[tuple[str, str]]  # ("$defs" or "definitions", name)


def _convert(node: Any, defs: Defs, root: bool = False) -> dict[str, Any]:
    if not isinstance(node, dict):  # a boolean schema
        raise _Inexpressible("a boolean schema")
    if "anyOf" in node and "oneOf" in node:
        raise _Inexpressible("anyOf and oneOf together")
    out: dict[str, Any] = {}
    for key, value in node.items():
        if key in DROPPED:
            continue
        if key not in _KEPT:
            raise _Inexpressible(key)
        if key == "type":
            out[key] = _types(value)
        elif key == "enum":
            if not isinstance(value, list) or not value or not all(map(_scalar, value)):
                raise _Inexpressible("enum")
            out[key] = list(value)
        elif key == "const":
            if not _scalar(value):
                raise _Inexpressible("const")
            out[key] = value
        elif key == "properties":
            if not isinstance(value, dict):
                raise _Inexpressible("properties")
            out[key] = {str(name): _convert(sub, defs) for name, sub in value.items()}
        elif key == "required":
            if not isinstance(value, list) or not all(isinstance(r, str) for r in value):
                raise _Inexpressible("required")
            out[key] = list(dict.fromkeys(value))
        elif key == "additionalProperties":
            if value is not False:  # open objects: Anthropic takes closed ones only
                raise _Inexpressible("additionalProperties")
        elif key == "items":
            out[key] = _convert(value, defs)  # a list (tuple items) is no schema here
        elif key in ("anyOf", "oneOf"):  # anyOf is oneOf without exclusivity: wider
            if not isinstance(value, list) or not value:
                raise _Inexpressible(key)
            out["anyOf"] = [_convert(sub, defs) for sub in value]
        elif key == "allOf":
            if not isinstance(value, list) or not value:
                raise _Inexpressible(key)
            members = [_convert(sub, defs) for sub in value]
            # closing each object of an allOf would refuse the keys the others name
            if any(_is_object(m) or "$ref" in m for m in members):
                raise _Inexpressible("allOf with an object")
            out[key] = members
        elif key == "$ref":
            found = _REF.fullmatch(value) if isinstance(value, str) else None
            if found is None or (found.group(1), found.group(2)) not in defs:
                raise _Inexpressible("$ref")
            out[key] = value
        elif key in ("$defs", "definitions"):
            if not root or not isinstance(value, dict):
                raise _Inexpressible(key)
            out[key] = {str(name): _convert(sub, defs) for name, sub in value.items()}
        elif key == "format":
            if isinstance(value, str) and value in FORMATS:
                out[key] = value
        elif key == "minItems":
            if isinstance(value, int) and not isinstance(value, bool) and value in (0, 1):
                out[key] = value
        elif key == "description" and isinstance(value, str):
            out[key] = value
    if "$ref" in out and set(out) - {"$ref", "description", "$defs", "definitions"}:
        raise _Inexpressible("$ref with siblings")
    if not any(k in out for k in _SHAPED):
        raise _Inexpressible("an open schema")
    if _is_object(out):
        properties = out.get("properties", {})
        if not properties and node.get("additionalProperties") is not False:
            raise _Inexpressible("an object of any keys")
        if any(r not in properties for r in out.get("required", ())):
            raise _Inexpressible("a required key with no schema")
        out["additionalProperties"] = False  # a declared shape is the answer's whole shape
    kinds = out.get("type")
    if (kinds == "array" or (isinstance(kinds, list) and "array" in kinds)) and "items" not in out:
        raise _Inexpressible("an array of anything")
    return out


def _refs(node: Any) -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    if isinstance(node, dict):
        ref = _REF.fullmatch(node["$ref"]) if isinstance(node.get("$ref"), str) else None
        if ref is not None:
            found.add((ref.group(1), ref.group(2)))
        for value in node.values():
            found |= _refs(value)
    elif isinstance(node, list):
        for value in node:
            found |= _refs(value)
    return found


def _recursive(defs: Mapping[tuple[str, str], Any]) -> bool:
    """Whether any definition reaches itself through $refs (reached from the root or not)."""
    edges = {name: _refs(sub) for name, sub in defs.items()}
    done: set[tuple[str, str]] = set()

    def cycle(name: tuple[str, str], path: frozenset[tuple[str, str]]) -> bool:
        if name in path:
            return True
        if name in done:
            return False
        found = any(cycle(n, path | {name}) for n in edges.get(name, ()))
        done.add(name)
        return found

    return any(cycle(name, frozenset()) for name in defs)


def output_schema(schema: Mapping[str, Any]) -> dict[str, Any] | None:
    """``schema`` as Anthropic's structured outputs take it: every object closed, constraints it
    does not take dropped, oneOf as anyOf. None when it cannot be said so (recursion, an open
    object, an unknown keyword, ...): the call then goes without a format and the answer is
    checked by ARGUS alone."""
    try:
        defs: dict[tuple[str, str], Any] = {}
        for key in ("$defs", "definitions"):
            held = schema.get(key, {})
            if not isinstance(held, dict):
                return None
            defs.update(((key, str(name)), sub) for name, sub in held.items())
        if _recursive(defs):
            return None
        return _convert(dict(schema), frozenset(defs), root=True)
    except (_Inexpressible, RecursionError):
        return None


def merged(body: dict[str, Any], extra: Mapping[str, Any]) -> dict[str, Any]:
    """``body`` with ``extra`` laid over it, objects merged key by key (an effort beside a
    format in ``output_config``)."""
    out = dict(body)
    for key, value in extra.items():
        held = out.get(key)
        if isinstance(held, dict) and isinstance(value, Mapping):
            out[key] = merged(held, value)
        else:
            out[key] = copy.deepcopy(value)  # the config stays as it was
    return out


def body(
    model: str,
    max_tokens: int,
    instructions: str,
    text: str,
    schema: Mapping[str, Any] | None,
    extra: Mapping[str, Any],
) -> dict[str, Any]:
    """A Messages body: the instructions as the system prompt, the request as the one user
    message (no prefill), the schema as the answer's format when it can be said."""
    out: dict[str, Any] = {
        "model": model,
        "max_tokens": max_tokens,
        "system": instructions,
        "messages": [{"role": "user", "content": text}],
    }
    shape = output_schema(schema) if schema is not None else None
    if shape is not None:
        out["output_config"] = {"format": {"type": "json_schema", "schema": shape}}
    return merged(out, extra)


ANSWERED = frozenset({"end_turn", "stop_sequence"})
CUT_OFF = frozenset({"max_tokens", "model_context_window_exceeded"})
_CATEGORY = re.compile(r"[a-z][a-z0-9_]{0,39}")  # matched whole
_FENCE = re.compile(r"\A\s*```[A-Za-z0-9_-]*[ \t]*\r?\n(.*?)\r?\n?```\s*\Z", re.S)


@dataclass(frozen=True)
class Reply:
    text: str | None  # None: no usable answer
    input_tokens: int | None
    output_tokens: int | None
    truncated: bool  # the cap ran out (stop_reason max_tokens)
    refused: str | None = None  # the ledger's outcome for a refusal: "refused[: category]"


def _count(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _tokens(usage: Mapping[str, Any]) -> tuple[int | None, int | None]:
    """(input, output): input counts the prompt read from and written to the cache too, as they
    are billed; an absent cache count is none, a malformed one makes the input unknown."""
    tin = _count(usage.get("input_tokens"))
    for name in ("cache_creation_input_tokens", "cache_read_input_tokens"):
        value = usage.get(name)
        if tin is None or value is None:
            continue
        cached = _count(value)
        tin = None if cached is None else tin + cached
    return tin, _count(usage.get("output_tokens"))


def refusal(details: Any) -> str:
    """The ledger's outcome for a refusal: its category when it names one plainly; never the
    explanation."""
    category = details.get("category") if isinstance(details, dict) else None
    if isinstance(category, str) and _CATEGORY.fullmatch(category):
        return f"refused: {category}"
    return "refused"


def unfenced(text: str) -> str:
    """A JSON answer without a code fence around the whole of it (a model asked for JSON with no
    format to hold it to may wrap it); anything else as it is."""
    found = _FENCE.match(text)
    return found.group(1) if found else text


def parse(raw: bytes, json_answer: bool) -> Reply | None:
    """A Messages reply, or None if it is not one. The answer is the text blocks joined; a
    thinking block (or a redacted one) never is."""
    try:
        data = json.loads(raw)
        content = data["content"]
        stop = data.get("stop_reason")
        usage = data.get("usage") or {}
    except (ValueError, KeyError, IndexError, TypeError, AttributeError):
        return None
    if not isinstance(content, list) or not isinstance(usage, dict):
        return None
    tin, tout = _tokens(usage)
    if stop == "refusal":  # a safety classifier declined: whatever came is not an answer
        return Reply(None, tin, tout, False, refusal(data.get("stop_details")))
    texts: list[str] = []
    for block in content:
        if isinstance(block, dict) and block.get("type") == "text":
            value = block.get("text")
            if not isinstance(value, str):
                return None
            texts.append(value)
    if stop in CUT_OFF:
        return Reply(None, tin, tout, True)
    text = "".join(texts)
    answer = unfenced(text) if json_answer else text  # an empty fence holds no answer either
    if stop not in ANSWERED or not answer.strip():  # pause_turn, tool_use: no tools are given
        return Reply(None, tin, tout, False)
    return Reply(answer, tin, tout, False)


QUOTA, TOO_LARGE, MODEL_MISMATCH = "quota", "too_large", "model_mismatch"
_QUOTA_WORDS = ("credit balance is too low", "reached your specified api usage limits")


def error(raw: bytes) -> tuple[str, str]:
    """(error.type, error.message) of an error body, or empty strings."""
    try:
        found = json.loads(raw).get("error")
    except (ValueError, AttributeError):
        return "", ""
    if not isinstance(found, dict):
        return "", ""
    kind, message = found.get("type"), found.get("message")
    return (kind if isinstance(kind, str) else ""), (message if isinstance(message, str) else "")


def error_kind(status: int, raw: bytes) -> str | None:
    """An error that needs more than the status's handling: the account out of credit (402, or
    a 400 that says so), a prompt too long for the model (400 or 413), a model or path the API
    does not know (404). None: the status says enough (429, 401/403, 5xx, any other 400)."""
    message = error(raw)[1].lower()
    if status == 402 or (status == 400 and any(w in message for w in _QUOTA_WORDS)):
        return QUOTA
    if status == 413 or (status == 400 and "prompt is too long" in message):
        return TOO_LARGE
    if status == 404:
        return MODEL_MISMATCH
    return None


def missing_model(raw: bytes) -> bool:
    """Whether a 404 is about the model (its message starts "model: <id>") rather than the
    path, such as a wrong base_url: the one model waits, not the provider."""
    kind, message = error(raw)
    return kind == "not_found_error" and message.lstrip().lower().startswith("model:")
