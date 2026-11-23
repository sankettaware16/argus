"""Anthropic's Messages API in the LLM gateway (P4-E1): the configuration's checks, the exact
body, the schema in the form Anthropic takes, the reply (the text, never the thinking; refusals
and cut-offs), every error, the key's header and the probe. Nothing reaches a provider: fakes
and httpx's mock transport only; every key here is made up."""

from __future__ import annotations

import copy
import json
import re
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import jsonschema_rs
import pytest
from hypothesis import assume, given
from hypothesis import strategies as st
from pydantic import SecretStr, ValidationError

from argus.agent import schemas as agent_schemas
from argus.evaluation import tasks
from argus.incident import prose
from argus.llm import anthropic_api, budget
from argus.llm.anthropic_api import Reply, merged, output_schema, parse, unfenced
from argus.llm.doctor import providers_check
from argus.llm.gateway import (
    AUTH_WAIT,
    DEFAULT_WAIT,
    QUOTA_WAIT,
    UNUSABLE,
    Call,
    LlmGateway,
    MemoryLlmStore,
    NoCapacity,
    Refused,
    body_for,
)
from argus.llm.privacy import Privacy, Request
from argus.llm.probe import ProbeState, probe
from argus.llm.prompts import ASSESS_V1_SCHEMA, OUTCOMES, PING_SCHEMA
from argus.llm.providers import DEFAULT_PATH, LlmConfig, Tier, callable_providers, load_config
from argus.llm.wire import HttpxLlmTransport, LlmCassette, LlmReply, LlmWire, TransportError
from tests.unit.llm.test_gateway import NOW, Clock, Fake
from tests.unit.llm.test_privacy import dossier

ANTHROPIC_KEY = SecretStr("made-up-anthropic-key-0001")
FREE_KEY = SecretStr("made-up-free-key-0002")
KEYS = {"ANTHROPIC_API_KEY": ANTHROPIC_KEY, "FREE_KEY": FREE_KEY}
EFFORT = {"output_config": {"effort": "low"}}
HAIKU = "anthropic/claude-haiku-5-5"
# Anthropic's documented limits, written out again here (not imported): what the test checks
# the conversion against
DOC_FORMATS = {"date-time", "time", "date", "duration", "email", "hostname", "uri", "ipv4",
               "ipv6", "uuid"}  # fmt: skip
DOC_KEYWORDS = {"type", "enum", "const", "properties", "required", "additionalProperties",
                "items", "anyOf", "allOf", "$ref", "$defs", "definitions", "format", "minItems",
                "description"}  # fmt: skip


def anthropic(**over: Any) -> dict[str, Any]:
    return {
        "name": "anthropic", "api": "anthropic", "base_url": "https://api.anthropic.com/v1",
        "keys": ["ANTHROPIC_API_KEY"], "schema_output": True,
        "models": {
            "small": {"name": "claude-haiku-5-5", "input_per_m": 0.10, "output_per_m": 0.50,
                      "thinking_tokens": 2048, "extra": EFFORT},
            "medium": {"name": "claude-sonnet-5-5", "input_per_m": 2.0, "output_per_m": 10.0,
                       "thinking_tokens": 2048, "extra": EFFORT},
        },
        **over,
    }  # fmt: skip


FREE = {"name": "free", "base_url": "https://free.example/v1", "keys": ["FREE_KEY"],
        "models": {"small": {"name": "f-small"}, "medium": {"name": "f-medium"}}}  # fmt: skip


def config(*providers: dict[str, Any]) -> LlmConfig:
    chosen = list(providers) or [anthropic(), FREE]
    return LlmConfig.model_validate({"monthly_cap_usd": 5.0, "providers": chosen})


USAGE = {"input_tokens": 300, "output_tokens": 40, "cache_creation_input_tokens": 20,
         "cache_read_input_tokens": 100}  # fmt: skip
THINKING = {"type": "thinking", "thinking": "", "signature": "made-up-signature"}
SUMMARIZED = {"type": "thinking", "thinking": "Weighing it: benign scanning.", "signature": "s"}
REDACTED = {"type": "redacted_thinking", "data": "made-up-opaque-data"}


def text(value: str) -> dict[str, Any]:
    return {"type": "text", "text": value}


def message_body(*blocks: dict[str, Any], stop: str | None = "end_turn",
                 usage: Any = USAGE, details: Any = None) -> bytes:  # fmt: skip
    body = {"id": "msg_made_up", "type": "message", "role": "assistant",
            "model": "claude-haiku-5-5", "content": list(blocks), "stop_reason": stop,
            "stop_sequence": None, "stop_details": details, "usage": usage}  # fmt: skip
    return json.dumps(body).encode()


def message(*blocks: dict[str, Any], **kw: Any) -> LlmReply:
    return LlmReply(200, message_body(*blocks, **kw), 80.0)


def failure(status: int, kind: str, msg: str, retry: str | None = None) -> LlmReply:
    body = {"type": "error", "error": {"type": kind, "message": msg}, "request_id": "req_x"}
    return LlmReply(status, json.dumps(body).encode(), 5.0, retry)


@pytest.fixture
def call(privacy: Privacy) -> Call:
    return Call(privacy.request([dossier()]), "Assess the item. Answer in JSON.", "assess",
                schema=ASSESS_V1_SCHEMA)  # fmt: skip


def make(
    replies: dict[str, list[LlmReply | Exception]], cfg: LlmConfig | None = None
) -> tuple[LlmGateway, Fake, MemoryLlmStore]:
    fake, store = Fake(replies), MemoryLlmStore()
    return LlmGateway(cfg or config(), KEYS, fake, store, Clock()), fake, store


# -- the configuration ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("extra", "why"),
    [
        ({"temperature": 0}, "temperature: refused by the API"),
        ({"top_p": 0.9, "top_k": 5}, "top_p, top_k: refused by the API"),
        ({"output_config": {"format": {"type": "json_schema", "schema": {}}}},
         "output_config holds the effort only"),
        ({"output_config": "low"}, "output_config holds the effort only"),
        ({"model": "other"}, "model: set by ARGUS"),
        ({"max_tokens": 9}, "max_tokens: set by ARGUS"),
        ({"system": "x"}, "system: set by ARGUS"),
        ({"messages": []}, "messages: set by ARGUS"),
        ({"stream": True}, "stream: set by ARGUS"),
    ],
)  # fmt: skip
def test_an_anthropic_model_refuses_what_the_api_refuses(extra: dict[str, Any], why: str) -> None:
    data = anthropic(models={"small": {"name": "claude-haiku-5-5", "extra": extra}})
    with pytest.raises(ValidationError, match=re.escape(why)) as caught:
        LlmConfig.model_validate({"providers": [data]})
    assert "small model claude-haiku-5-5" in str(caught.value)
    LlmConfig.model_validate({"providers": [{**data, "api": "openai"}]})  # its own business


OFF = {"thinking": {"type": "disabled"}}


@pytest.mark.parametrize(
    ("name", "extra", "why"),
    [
        ("claude-sonnet-5-5", OFF, "only Haiku takes disabled thinking (400 on Sonnet and Opus)"),
        ("claude-opus-5-5", {**OFF, **EFFORT}, "only Haiku takes disabled thinking"),
        ("claude-haiku-5-5", {**OFF, "output_config": {"effort": "xhigh"}},
         "disabled thinking takes effort high or below (400 at xhigh)"),
        ("claude-haiku-5-5", {**OFF, "output_config": {"effort": "max"}},
         "disabled thinking takes effort high or below (400 at max)"),
    ],
)  # fmt: skip
def test_thinking_turns_off_on_haiku_only_at_effort_high_or_below(
    name: str, extra: dict[str, Any], why: str
) -> None:
    data = anthropic(models={"small": {"name": name, "extra": extra}})
    with pytest.raises(ValidationError, match=re.escape(why)) as caught:
        LlmConfig.model_validate({"providers": [data]})
    assert f"small model {name}" in str(caught.value)


@pytest.mark.parametrize("effort", [None, "low", "medium", "high"])
def test_haiku_may_turn_its_thinking_off(call: Call, effort: str | None) -> None:
    extra = {**OFF, **({"output_config": {"effort": effort}} if effort else {})}
    data = anthropic(models={"small": {"name": "claude-HAIKU-5-5", "extra": extra}})
    provider = LlmConfig.model_validate({"providers": [data]}).providers[0]
    sent = json.loads(body_for(provider, call))
    assert sent["thinking"] == {"type": "disabled"}
    assert sent["output_config"].get("effort") == effort
    assert "format" in sent["output_config"]  # the answer's format beside it


def test_the_api_and_its_version_are_checked() -> None:
    p = LlmConfig.model_validate({"providers": [FREE]}).providers[0]
    assert (p.api, p.api_version) == ("openai", "2026-10-21")  # every provider before is openai
    for bad in ({"api": "gemini"}, {"api_version": "2026-10-21\r\nx-injected: 1"},
                {"api_version": "2026-10-21\n"}, {"api_version": "latest"},
                {"api_version": "\uff12\uff10\uff12\uff16-10-21"},  # digits, not ASCII ones
                {"max_tokens_field": "max_completion_tokens"}):  # fmt: skip
        with pytest.raises(ValidationError):
            LlmConfig.model_validate({"providers": [anthropic(**bad)]})
    fine = anthropic(api_version="2027-01-01", models={"small": {"name": "m", "extra": {
        "thinking": {"type": "adaptive"}, "output_config": {"effort": "max"}}}})  # fmt: skip
    assert LlmConfig.model_validate({"providers": [fine]}).providers[0].api_version == "2027-01-01"


def test_the_urls_follow_the_api() -> None:
    a, f = config().providers
    assert a.call_url() == "https://api.anthropic.com/v1/messages"
    assert a.models_url() == "https://api.anthropic.com/v1/models?limit=1000"
    assert f.call_url() == "https://free.example/v1/chat/completions"
    assert f.models_url() == "https://free.example/v1/models"


# -- the body ---------------------------------------------------------------------------------

ASSESS_SENT = {
    "type": "object",
    "properties": {
        "outcome": {"type": "string", "enum": list(OUTCOMES)},
        "confidence": {"type": "number"},
        "reason": {"type": "string"},
        "missing": {"type": "array", "items": {"type": "string"}},  # maxItems is not taken
    },
    "required": ["outcome", "confidence", "reason", "missing"],
    "additionalProperties": False,
}


def test_the_body_is_a_messages_body_with_the_schema_and_the_effort(call: Call) -> None:
    raw = body_for(config().providers[0], call)
    assert json.loads(raw) == {
        "model": "claude-haiku-5-5",
        "max_tokens": 1000 + 2048,  # the answer and the thinking's room
        "system": call.instructions,
        "messages": [{"role": "user", "content": call.request.text}],
        "output_config": {"format": {"type": "json_schema", "schema": ASSESS_SENT},
                          "effort": "low"},
    }  # fmt: skip
    assert list(json.loads(raw)) == ["model", "max_tokens", "system", "messages", "output_config"]
    assert raw == json.dumps(json.loads(raw), ensure_ascii=False, separators=(",", ":")).encode()
    plain = body_for(config().providers[0], Call(Request("é", (), (), (), (), call.request.ours),
                                                 "x", "t"))  # fmt: skip
    assert "é".encode() in plain
    assert b", " not in plain
    assert b": " not in plain


def test_a_json_call_without_a_usable_schema_rests_on_its_instructions(call: Call) -> None:
    a = config().providers[0]
    no_format = [replace(call, schema=None), replace(call, json=False),
                 replace(call, schema={"type": "object", "properties": {},
                                       "additionalProperties": True})]  # fmt: skip
    for c in no_format:
        assert json.loads(body_for(a, c))["output_config"] == {"effort": "low"}
    plain = a.model_copy(update={"schema_output": False})
    assert json.loads(body_for(plain, call))["output_config"] == {"effort": "low"}
    bare = a.model_copy(update={"models": {
        Tier.SMALL: a.models[Tier.SMALL].model_copy(update={"extra": {}})}})  # fmt: skip
    body = json.loads(body_for(bare, replace(call, schema=None)))
    assert set(body) == {"model", "max_tokens", "system", "messages"}  # json_mode: no such thing
    assert json.loads(body_for(bare, call))["output_config"] == {
        "format": {"type": "json_schema", "schema": ASSESS_SENT}}  # fmt: skip


def test_extra_is_merged_deeply_and_the_config_is_left_as_it_was(call: Call) -> None:
    extra = {"output_config": {"effort": "high"}, "thinking": {"type": "adaptive"},
             "metadata": {"user_id": "argus"}}  # fmt: skip
    cfg = config(anthropic(models={"small": {"name": "m", "extra": extra}}))
    body = json.loads(body_for(cfg.providers[0], call))
    assert body["output_config"] == {"format": {"type": "json_schema", "schema": ASSESS_SENT},
                                     "effort": "high"}  # fmt: skip
    assert (body["thinking"], body["metadata"]) == ({"type": "adaptive"}, {"user_id": "argus"})
    body["metadata"]["user_id"] = "changed"
    assert cfg.providers[0].models[Tier.SMALL].extra == extra
    base = {"a": {"b": 1}, "c": 1, "d": [1]}
    assert merged(base, {"a": {"e": 2}, "c": {"x": 1}, "d": [2]}) == {
        "a": {"b": 1, "e": 2}, "c": {"x": 1}, "d": [2]}  # fmt: skip
    assert base == {"a": {"b": 1}, "c": 1, "d": [1]}
    held = {"thinking": {"type": "adaptive"}, "stop_sequences": ["x"]}
    out = merged({}, held)
    out["thinking"]["type"] = "changed"
    out["stop_sequences"].append("y")
    assert held == {"thinking": {"type": "adaptive"}, "stop_sequences": ["x"]}  # copies only


def test_the_openai_body_is_unchanged(call: Call) -> None:
    free = config(anthropic(), {**FREE, "schema_output": True}).providers[1]
    body = json.loads(body_for(free, call))
    assert body["messages"][0] == {"role": "system", "content": call.instructions}
    assert body["response_format"]["json_schema"]["schema"] == ASSESS_V1_SCHEMA  # as sent


SHIPPED = {
    "ping": PING_SCHEMA,
    "assess@1": ASSESS_V1_SCHEMA,
    "answer@1": agent_schemas.answer(("web", "proxy", "intel")),
    "answer@1 alone": agent_schemas.answer(()),
    "notes@1": agent_schemas.NOTES,
    "ranking@1": agent_schemas.RANKING,
    "prose@1": agent_schemas.PROSE,
    "incident prose": prose.SCHEMA,
    **{f"task {name}": spec.schema for name, spec in tasks.SPECS.items()},
}


@pytest.mark.parametrize("name", sorted(SHIPPED))
def test_every_schema_argus_sends_has_an_anthropic_form(name: str) -> None:
    original = SHIPPED[name]
    before = copy.deepcopy(original)
    shape = output_schema(original)
    assert shape is not None
    assert broken(shape) == []
    assert original == before
    assert _keys(shape) == _keys(original)  # no key a shipped answer has is lost or added
    jsonschema_rs.validator_for(shape)


def _keys(node: Any) -> Any:
    """Every object's property names and required list, by path."""
    if isinstance(node, dict):
        mine = {"p": sorted(node.get("properties", {})), "r": node.get("required")}
        return [mine, {k: _keys(v) for k, v in node.items() if isinstance(v, dict | list)}]
    if isinstance(node, list):
        return [_keys(v) for v in node]
    return None


async def test_the_validator_checks_the_anthropic_bytes_before_they_go(
    call: Call, privacy: Privacy
) -> None:
    gw, fake, store = make({})
    with pytest.raises(Refused, match="body did not pass"):
        await gw.complete(replace(call, instructions="Ask moodle.example.edu about it"))
    leaky = {"type": "object", "properties": {"host": {"type": "string", "enum": ["10.20.3.4"]}},
             "required": ["host"], "additionalProperties": False}  # fmt: skip
    with pytest.raises(Refused, match="body did not pass"):  # the schema is in the bytes too
        await gw.complete(replace(call, schema=leaky))
    assert fake.sent == []
    assert [(e.provider, e.outcome, e.attempt) for e in store.ledger] == [
        ("anthropic", "blocked", 0), ("anthropic", "blocked", 0)]  # fmt: skip
    assert all(len(e.request_sha256) == 64 for e in store.ledger)
    assert not call.request.check(body_for(config().providers[0], replace(call, schema=leaky))
                                  ).allowed  # fmt: skip


# -- the schema in Anthropic's form -----------------------------------------------------------


def _scalar(v: Any) -> bool:
    return v is None or isinstance(v, str | int | float | bool)


def broken(schema: dict[str, Any]) -> list[str]:
    """What in ``schema`` Anthropic's structured outputs would not take, by its documented
    limits; [] when it takes all of it."""
    out: list[str] = []
    defs = {(k, n): s for k in ("$defs", "definitions") for n, s in schema.get(k, {}).items()}

    def walk(node: Any, at: str) -> None:
        if not isinstance(node, dict):
            out.append(f"{at}: not a schema object")
            return
        out.extend(f"{at}: {k}" for k in node if k not in DOC_KEYWORDS)
        kinds = node.get("type") if isinstance(node.get("type"), list) else [node.get("type")]
        if ("object" in kinds or "properties" in node) and node.get(
            "additionalProperties"
        ) is not False:
            out.append(f"{at}: an object that is not closed")  # fmt: skip
        if "additionalProperties" in node and node["additionalProperties"] is not False:
            out.append(f"{at}: additionalProperties {node['additionalProperties']!r}")
        if node.get("minItems", 0) not in (0, 1):
            out.append(f"{at}: minItems {node['minItems']}")
        if "format" in node and node["format"] not in DOC_FORMATS:
            out.append(f"{at}: format {node['format']}")
        if not all(map(_scalar, node.get("enum", []))) or not _scalar(node.get("const")):
            out.append(f"{at}: a complex enum or const")
        if "$ref" in node:
            found = re.fullmatch(r"#/(\$defs|definitions)/(.+)", node["$ref"])
            if found is None or (found.group(1), found.group(2)) not in defs:
                out.append(f"{at}: $ref {node['$ref']}")
        for name, sub in node.get("properties", {}).items():
            walk(sub, f"{at}.{name}")
        if "items" in node:
            walk(node["items"], f"{at}[]")
        for i, sub in enumerate([*node.get("anyOf", []), *node.get("allOf", [])]):
            walk(sub, f"{at}|{i}")

    walk(schema, "$")
    for (kind, name), sub in defs.items():
        walk(sub, f"{kind}.{name}")
    for start in defs:  # recursion: a definition that reaches itself
        seen, todo = set(), [start]
        while todo:
            for ref in re.findall(
                r'"#/(\$defs|definitions)/([^"]+)"', json.dumps(defs[todo.pop()])
            ):
                if ref == start:
                    out.append(f"{start}: recursive")
                    todo = []
                    break
                if ref not in seen and ref in defs:
                    seen.add(ref)
                    todo.append(ref)
    return out


def test_what_the_conversion_keeps_drops_and_closes() -> None:
    original = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "n": {"type": "integer", "minimum": 0, "maximum": 9, "multipleOf": 3},
            "s": {"type": "string", "minLength": 1, "maxLength": 5, "pattern": "^a",
                  "format": "email", "title": "t", "default": "a", "description": "d"},
            "f": {"type": "string", "format": "regex"},
            "l": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 3,
                  "uniqueItems": True},
            "m": {"type": "array", "items": {"type": "number", "exclusiveMinimum": 0},
                  "minItems": 2},
            "o": {"oneOf": [{"type": "string"}, {"type": "null"}]},
            "e": {"type": ["string", "null"], "enum": ["a", None]},
            "c": {"const": 3},
            "a": {"allOf": [{"type": "string"}, {"type": "string", "maxLength": 3}]},
        },
        "required": ["n", "n"],
    }  # fmt: skip
    assert output_schema(original) == {
        "type": "object",
        "properties": {
            "n": {"type": "integer"},
            "s": {"type": "string", "format": "email", "description": "d"},
            "f": {"type": "string"},
            "l": {"type": "array", "items": {"type": "string"}, "minItems": 1},
            "m": {"type": "array", "items": {"type": "number"}},
            "o": {"anyOf": [{"type": "string"}, {"type": "null"}]},
            "e": {"type": ["string", "null"], "enum": ["a", None]},
            "c": {"const": 3},
            "a": {"allOf": [{"type": "string"}, {"type": "string"}]},
        },
        "required": ["n"],
        "additionalProperties": False,  # absent before: the declared keys are the answer's
    }  # fmt: skip
    with_defs = {"$defs": {"k": {"type": "string", "enum": ["a", "b"]}},
                 "definitions": {"j": {"type": "integer"}},
                 "type": "object", "properties": {"x": {"$ref": "#/$defs/k"},
                                                  "y": {"$ref": "#/definitions/j"}},
                 "required": ["x"], "additionalProperties": False}  # fmt: skip
    assert output_schema(with_defs) == with_defs
    at_root = {"$ref": "#/$defs/k", "$defs": {"k": {"type": "boolean"}}}
    assert output_schema(at_root) == at_root
    closed = {"type": "object", "properties": {}, "additionalProperties": False}
    assert output_schema(closed) == closed  # only {} is valid, as before


RECURSIVE = {
    "direct": {"$defs": {"n": {"type": "object", "properties": {"next": {"$ref": "#/$defs/n"}},
                               "additionalProperties": False}}, "$ref": "#/$defs/n"},
    "indirect": {"$defs": {"a": {"type": "array", "items": {"$ref": "#/$defs/b"}},
                           "b": {"anyOf": [{"type": "null"}, {"$ref": "#/$defs/a"}]}},
                 "type": "object", "properties": {"x": {"$ref": "#/$defs/a"}},
                 "additionalProperties": False},
    "unused": {"$defs": {"t": {"type": "array", "items": {"$ref": "#/$defs/t"}}},
               "type": "string"},
}  # fmt: skip
INEXPRESSIBLE: list[Any] = [
    {"type": "object", "properties": {"x": {"type": "string"}}, "additionalProperties": True},
    {
        "type": "object",
        "properties": {"x": {"type": "string"}},
        "additionalProperties": {"type": "string"},
    },
    {
        "type": "object",
        "properties": {"x": {"type": "string"}},
        "patternProperties": {"^y": {"type": "string"}},
    },
    {"type": "object", "properties": {"x": {"type": "string"}}, "unevaluatedProperties": False},
    {"not": {"type": "string"}},
    {"type": "array", "prefixItems": [{"type": "string"}], "items": {"type": "string"}},
    {"type": "array", "items": [{"type": "string"}]},
    {"type": "object"},  # any keys at all
    {"type": "array"},  # items of anything
    {"description": "anything"},
    {"$ref": "https://example.org/schema"},
    {"$ref": "#/$defs/missing"},
    {"$ref": "#/$defs/k\n", "$defs": {"k": {"type": "string"}}},
    {"$ref": "#/definitions/k", "$defs": {"k": {"type": "string"}}},
    {"$ref": "#/$defs/k", "type": "string", "$defs": {"k": {"type": "string"}}},
    {"enum": [{"a": 1}]},
    {"enum": []},
    {"const": [1]},
    {"type": "object", "properties": {}, "required": ["x"], "additionalProperties": False},
    {"type": "colour"},
    {"type": ["string", "string"]},
    {"type": "string", "x-made-up": 1},
    {"type": "string", "$id": "https://example.org/s"},
    {"allOf": [{"type": "object", "properties": {"a": {"type": "string"}}}]},
    {"allOf": [{"$ref": "#/$defs/k"}], "$defs": {"k": {"type": "string"}}},
    {"anyOf": []},
    {"anyOf": [{"type": "string"}], "oneOf": [{"type": "null"}]},
    True,
    False,
    {"type": "string", "items": True},
]


@pytest.mark.parametrize("name", sorted(RECURSIVE))
def test_a_recursive_schema_goes_without_a_format(name: str) -> None:
    assert output_schema(RECURSIVE[name]) is None


@pytest.mark.parametrize("poison", INEXPRESSIBLE, ids=lambda p: json.dumps(p)[:50])
def test_what_anthropic_cannot_take_is_never_sent(poison: Any) -> None:
    if isinstance(poison, dict):
        assert output_schema(poison) is None
    wrapped = {"type": "object", "properties": {"x": poison}, "additionalProperties": False}
    assert output_schema(wrapped) is None


def test_a_schema_too_deep_to_walk_goes_without_a_format() -> None:
    deep: dict[str, Any] = {"type": "string"}
    for _ in range(5000):
        deep = {"type": "array", "items": deep}
    assert output_schema(deep) is None
    assert output_schema({"$defs": "x", "type": "string"}) is None


# Schemas Anthropic can be told (drawn with the constraints it drops), and answers to them.

SCALARS = st.one_of(st.none(), st.booleans(), st.integers(-3, 3), st.text("abc", max_size=2))


def _leaves(refs: list[str]) -> st.SearchStrategy[dict[str, Any]]:
    string = st.fixed_dictionaries({"type": st.just("string")}, optional={
        "minLength": st.integers(0, 2), "maxLength": st.integers(2, 5),
        "pattern": st.just("^[abc]*$"), "description": st.text("xyz", max_size=3),
        "format": st.sampled_from(["date-time", "email", "uuid", "regex", "colour"]),
        "title": st.just("t"), "default": st.just(""),
    })  # fmt: skip
    integer = st.fixed_dictionaries({"type": st.just("integer")}, optional={
        "minimum": st.integers(-3, 0), "maximum": st.integers(0, 3), "multipleOf": st.just(1),
        "exclusiveMaximum": st.integers(4, 6),
    })  # fmt: skip
    number = st.fixed_dictionaries({"type": st.just("number")}, optional={
        "minimum": st.integers(-3, 0), "exclusiveMinimum": st.just(-4),
    })  # fmt: skip
    simple = st.sampled_from([{"type": "boolean"}, {"type": "null"},
                              {"type": ["string", "null"]}])  # fmt: skip
    enum = st.lists(SCALARS, min_size=1, max_size=4, unique_by=json.dumps).map(
        lambda v: {"enum": v}
    )
    const = SCALARS.map(lambda v: {"const": v})
    every = [string, integer, number, simple, enum, const]
    if refs:
        every.append(st.sampled_from(refs).map(lambda n: {"$ref": f"#/$defs/{n}"}))
    return st.one_of(every)


TYPED = st.sampled_from([{"type": "string", "maxLength": 9}, {"type": "integer", "minimum": -9},
                         {"type": "boolean"}])  # fmt: skip


def _composites(children: st.SearchStrategy[dict[str, Any]]) -> st.SearchStrategy[dict[str, Any]]:
    def obj(props: dict[str, Any]) -> st.SearchStrategy[dict[str, Any]]:
        return st.fixed_dictionaries(
            {"type": st.just("object"), "properties": st.just(props),
             "required": st.lists(st.sampled_from(sorted(props)), unique=True)},
            optional={"additionalProperties": st.just(False), "minProperties": st.just(0),
                      "description": st.just("an item")},
        )  # fmt: skip

    def arr(item: dict[str, Any]) -> st.SearchStrategy[dict[str, Any]]:
        return st.fixed_dictionaries({"type": st.just("array"), "items": st.just(item)},
                                     optional={"minItems": st.integers(0, 2),
                                               "maxItems": st.integers(2, 4),
                                               "uniqueItems": st.just(True)})  # fmt: skip

    return st.one_of(
        st.dictionaries(st.text("pqrs", min_size=1, max_size=2), children, min_size=1,
                        max_size=3).flatmap(obj),
        children.flatmap(arr),
        st.lists(children, min_size=1, max_size=3).map(lambda xs: {"anyOf": xs}),
        st.lists(children, min_size=1, max_size=2).map(lambda xs: {"oneOf": xs}),
        TYPED.map(lambda t: {"allOf": [t, {"type": t["type"]}]}),
    )  # fmt: skip


@st.composite
def schemas(draw: st.DrawFn) -> dict[str, Any]:
    names = draw(st.lists(st.sampled_from(["a", "b"]), unique=True, max_size=2))
    defs = {n: draw(st.recursive(_leaves([]), _composites, max_leaves=4)) for n in names}
    schema = dict(draw(st.recursive(_leaves(names), _composites, max_leaves=8)))
    if names:
        schema["$defs"] = defs
    return schema


def answers(node: dict[str, Any], defs: dict[str, Any]) -> st.SearchStrategy[Any]:
    """Values shaped by ``node``: mostly valid under it (each is checked)."""
    if "$ref" in node:
        return st.deferred(lambda: answers(defs[node["$ref"].rsplit("/", 1)[1]], defs))
    if "const" in node:
        return st.just(node["const"])
    if "enum" in node:
        return st.sampled_from(node["enum"])
    for key in ("anyOf", "oneOf"):
        if key in node:
            return st.one_of([answers(sub, defs) for sub in node[key]])
    if "allOf" in node:
        return answers(node["allOf"][0], defs)
    kinds = node["type"] if isinstance(node["type"], list) else [node["type"]]
    out: list[st.SearchStrategy[Any]] = []
    for kind in kinds:
        if kind == "string":
            low = node.get("minLength", 0)
            out.append(st.text("abc", min_size=low, max_size=max(low, node.get("maxLength", 4))))
        elif kind in ("integer", "number"):
            top = min(node.get("maximum", 9), node.get("exclusiveMaximum", 10) - 1)
            low = max(node.get("minimum", -9), node.get("exclusiveMinimum", -10) + 1)
            out.append(st.integers(low, top))
            if kind == "number":
                out.append(st.floats(low, top, allow_nan=False, allow_infinity=False))
        elif kind == "boolean":
            out.append(st.booleans())
        elif kind == "null":
            out.append(st.none())
        elif kind == "object":
            props, needed = node["properties"], node.get("required", [])
            out.append(st.fixed_dictionaries(
                {k: answers(props[k], defs) for k in needed},
                optional={k: answers(v, defs) for k, v in props.items() if k not in needed},
            ))  # fmt: skip
        elif kind == "array":
            low = node.get("minItems", 0)
            top = max(low, min(node.get("maxItems", 3), 3))
            unique = json.dumps if node.get("uniqueItems") else None
            out.append(st.lists(answers(node["items"], defs), max_size=top, unique_by=unique,
                                min_size=min(low, 1) if unique else low))  # fmt: skip
    return st.one_of(out)


def _validator(schema: dict[str, Any]) -> Any:
    return jsonschema_rs.validator_for(schema, validate_formats=False)


@given(st.data())
def test_every_answer_valid_under_the_original_is_valid_under_the_sent_schema(
    data: st.DataObject,
) -> None:
    schema = data.draw(schemas())
    shape = output_schema(schema)
    assert shape is not None  # drawn from what Anthropic can be told
    assert broken(shape) == []
    assert output_schema(shape) == shape  # converting again changes nothing
    original, sent = _validator(schema), _validator(shape)
    answer = data.draw(answers(schema, schema.get("$defs", {})))
    assume(original.is_valid(answer))
    assert sent.is_valid(answer)


@given(st.data())
def test_anything_anthropic_cannot_take_anywhere_means_no_format(data: st.DataObject) -> None:
    schema = data.draw(schemas())
    poison = data.draw(st.sampled_from([p for p in INEXPRESSIBLE if isinstance(p, dict)]))
    where = data.draw(st.sampled_from(["property", "anyOf", "items", "definition"]))
    if where == "property":
        planted = {"type": "object", "properties": {"x": schema, "y": poison},
                   "additionalProperties": False}  # fmt: skip
    elif where == "anyOf":
        planted = {"anyOf": [schema, poison]}
    elif where == "items":
        planted = {"type": "array", "items": {"anyOf": [poison, schema]}}
    else:  # a definition nothing uses is converted too
        planted = {**schema, "$defs": {**schema.get("$defs", {}), "unused": poison}}
    if where != "definition":
        planted = {**planted, **({"$defs": schema["$defs"]} if "$defs" in schema else {})}
        schema.pop("$defs", None)
    assert output_schema(planted) is None


# -- the reply ---------------------------------------------------------------------------------


def test_the_answer_is_the_text_never_the_thinking() -> None:
    got = parse(message_body(THINKING, text('{"outcome": '), REDACTED, SUMMARIZED,
                             text('"inconclusive"}')), True)  # fmt: skip
    assert got == Reply('{"outcome": "inconclusive"}', 420, 40, False, None)
    assert parse(message_body(text("plain"), stop="stop_sequence"), False) == Reply(
        "plain", 420, 40, False)  # fmt: skip


@pytest.mark.parametrize(
    ("details", "outcome"),
    [
        ({"type": "refusal", "category": "cyber", "explanation": "Made-up explanation."},
         "refused: cyber"),
        ({"type": "refusal", "category": "reasoning_extraction", "explanation": "x"},
         "refused: reasoning_extraction"),
        ({"type": "refusal", "category": None, "explanation": "x"}, "refused"),
        ({"type": "refusal", "category": "Not A Category!"}, "refused"),
        ({"type": "refusal", "category": "c" * 41}, "refused"),
        ({"type": "refusal", "category": 7}, "refused"),
        ({"type": "refusal", "category": "cyber\n"}, "refused"),
        (None, "refused"),
        ("cyber", "refused"),
    ],
)  # fmt: skip
def test_a_refusal_is_no_answer_and_names_only_its_category(details: Any, outcome: str) -> None:
    got = parse(message_body(text('{"outcome": "benign_expected"}'), stop="refusal",
                             details=details), True)  # fmt: skip
    assert got == Reply(None, 420, 40, False, outcome)
    assert "explanation" not in repr(got).lower()
    assert "Made-up" not in repr(got)


@pytest.mark.parametrize("stop", ["max_tokens", "model_context_window_exceeded"])
def test_a_reply_cut_off_is_truncated_even_with_text(stop: str) -> None:
    assert parse(message_body(THINKING, text('{"outcome": "tr'), stop=stop), True) == Reply(
        None, 420, 40, True)  # fmt: skip
    assert parse(message_body(THINKING, stop=stop), True) == Reply(None, 420, 40, True)


@pytest.mark.parametrize(
    "raw",
    [
        message_body(THINKING),  # thinking only
        message_body(THINKING, text("  \n ")),
        message_body(),
        message_body(text('{"a": 1}'), stop="pause_turn"),
        message_body(text('{"a": 1}'), stop="tool_use"),
        message_body(text('{"a": 1}'), stop=None),
        message_body(text('{"a": 1}'), stop="something_new"),
        message_body(text("```json\n\n```")),  # an empty fence: nothing inside it
        message_body(text("```\n   \n```")),
        message_body(THINKING, text("```JSON\r\n"), text("\r\n```  ")),
    ],
)
def test_a_reply_without_a_finished_text_is_no_answer(raw: bytes) -> None:
    got = parse(raw, True)
    assert got is not None
    assert (got.text, got.truncated, got.refused) == (None, False, None)


@pytest.mark.parametrize(
    "raw",
    [b"not json", b"[]", b"null", b'"x"', b'{"type": "message"}', b'{"content": "text"}',
     b'{"content": [{"type": "text", "text": 5}], "stop_reason": "end_turn"}',
     b'{"content": [{"type": "text"}], "stop_reason": "end_turn"}',
     b'{"content": [], "usage": [1], "stop_reason": "end_turn"}',
     b'{"content": {"type": "text"}, "stop_reason": "end_turn"}',
     b'{"type": "error", "error": {"type": "api_error", "message": "x"}}', b""],
)  # fmt: skip
def test_a_malformed_reply_is_none(raw: bytes) -> None:
    assert parse(raw, True) is None


@pytest.mark.parametrize(
    ("usage", "counts"),
    [
        (USAGE, (420, 40)),
        ({"input_tokens": 300, "output_tokens": 40}, (300, 40)),
        ({"input_tokens": 300, "output_tokens": 40, "cache_creation_input_tokens": None,
          "cache_read_input_tokens": None}, (300, 40)),
        ({"input_tokens": 300, "output_tokens": 40, "cache_read_input_tokens": "9"}, (None, 40)),
        ({"input_tokens": 300, "output_tokens": 40, "cache_creation_input_tokens": -1},
         (None, 40)),
        ({"input_tokens": True, "output_tokens": 40}, (None, 40)),
        ({"input_tokens": -5, "output_tokens": 1.5}, (None, None)),
        ({}, (None, None)),
        (None, (None, None)),
    ],
)  # fmt: skip
def test_tokens_count_the_cache_and_are_taken_only_when_sane(
    usage: Any, counts: tuple[int | None, int | None]
) -> None:
    got = parse(message_body(text("{}"), usage=usage), True)
    assert got is not None
    assert (got.input_tokens, got.output_tokens) == counts


def test_a_fenced_json_answer_is_unwrapped_and_nothing_else() -> None:
    assert unfenced('```json\n{"a": 1}\n```') == '{"a": 1}'
    assert unfenced("```\n{}\n```") == "{}"
    assert unfenced("  ```JSON \r\n[1]\r\n```  ") == "[1]"
    for kept in ('{"a": 1}', "Here: ```json\n{}\n```", "```json {}```", "```json\n{}", ""):
        assert unfenced(kept) == kept
    fenced = message_body(text('```json\n{"a": 1}\n```'))
    assert parse(fenced, True) == Reply('{"a": 1}', 420, 40, False)
    assert parse(fenced, False) == Reply('```json\n{"a": 1}\n```', 420, 40, False)
    empty = message_body(text("```json\n\n```"))  # no answer as JSON; as text, what was said
    assert parse(empty, False) == Reply("```json\n\n```", 420, 40, False)


JSON = st.recursive(
    st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=8)),
    lambda inner: st.one_of(st.lists(inner, max_size=3),
                            st.dictionaries(st.text(max_size=3), inner, max_size=3)),
    max_leaves=10,
)  # fmt: skip


@given(JSON, st.sampled_from(["json", "JSON", ""]), st.sampled_from([None, 2]))
def test_any_json_in_a_fence_reads_back(value: Any, lang: str, indent: int | None) -> None:
    raw = json.dumps(value, indent=indent, ensure_ascii=False)
    assert json.loads(unfenced(f"```{lang}\n{raw}\n```")) == value
    assert unfenced(raw) == raw


BLOCKS = st.lists(st.one_of(
    st.text(max_size=6).map(text), st.just(THINKING), st.just(SUMMARIZED), st.just(REDACTED),
    st.just({"type": "server_tool_use", "id": "x", "name": "y", "input": {}}),
), max_size=6)  # fmt: skip


@given(BLOCKS)
def test_the_answer_is_exactly_the_text_blocks_joined(blocks: list[dict[str, Any]]) -> None:
    got = parse(message_body(*blocks), False)
    assert got is not None
    joined = "".join(b["text"] for b in blocks if b["type"] == "text")
    assert got.text == (joined if joined.strip() else None)


# -- through the gateway: answers, refusals and errors ----------------------------------------


async def test_an_answer_from_anthropic(call: Call) -> None:
    gw, fake, store = make({"anthropic": [message(THINKING, text('{"ok": true}'))]})
    done = await gw.complete(call)
    assert (done.provider, done.model, done.text) == ("anthropic", "claude-haiku-5-5",
                                                      '{"ok": true}')  # fmt: skip
    assert (done.input_tokens, done.output_tokens) == (420, 40)  # the cache's tokens are billed
    assert done.cost_usd == pytest.approx((420 * 0.10 + 40 * 0.50) / 1e6)
    (wire, key), = fake.sent  # fmt: skip
    assert wire.url == "https://api.anthropic.com/v1/messages"
    assert key == ANTHROPIC_KEY.get_secret_value()
    (entry,) = store.ledger
    assert (entry.outcome, entry.http_status, entry.request_bytes) == ("ok", 200, len(wire.body))
    shown = repr(store.ledger)
    for value in (call.request.text[:40], "Assess the item", ANTHROPIC_KEY.get_secret_value()):
        assert value not in shown


async def test_a_refusal_goes_on_to_the_next_provider(call: Call) -> None:
    details = {"type": "refusal", "category": "cyber", "explanation": "Made-up explanation."}
    gw, fake, store = make({"anthropic": [message(text("{"), stop="refusal", details=details)]})
    done = await gw.complete(call)
    assert done.provider == "free"
    assert [(e.provider, e.outcome, e.attempt) for e in store.ledger] == [
        ("anthropic", "refused: cyber", 1), ("free", "ok", 2)]  # fmt: skip
    assert "Made-up" not in repr(store.ledger)
    assert b"Made-up" not in fake.sent[1][0].body  # nothing of it goes on
    assert fake.sent[0][0].body == body_for(config().providers[0], call)
    state = await store.state()
    assert state.cooldowns == {}
    assert state.alarms == {}
    assert not any(b.is_open(NOW) for b in state.breakers.values())
    assert "refused" in UNUSABLE


async def test_when_only_anthropic_refuses_the_call_is_refused_and_counted(call: Call) -> None:
    gw, _, store = make({"anthropic": [message(stop="refusal")]}, config(anthropic()))
    with pytest.raises(Refused, match=re.escape("anthropic: refused (200)")) as caught:
        await gw.complete(call)
    assert caught.value.failed == 1
    assert [e.outcome for e in store.ledger] == ["refused"]


CREDIT = ("Your credit balance is too low to access the Anthropic API. Please go to Plans &"
          " Billing to upgrade or purchase credits.")  # fmt: skip
LIMITS = ("You have reached your specified API usage limits. You will regain access on"
          " 2026-12-01 at 00:00 UTC.")  # fmt: skip


@pytest.mark.parametrize(
    ("reply", "outcome", "cooldown", "breaker", "alarm"),
    [
        (failure(429, "rate_limit_error", "rate limit", "7"), "rate_limited",
         (HAIKU, timedelta(seconds=7)), None, None),
        (failure(429, "rate_limit_error", "rate limit"), "rate_limited", (HAIKU, DEFAULT_WAIT),
         None, None),
        (failure(529, "overloaded_error", "Overloaded"), "server_error", None, HAIKU, None),
        (failure(500, "api_error", "Internal server error"), "server_error", None, HAIKU, None),
        (failure(504, "timeout_error", "Request timed out"), "server_error", None, HAIKU, None),
        (failure(401, "authentication_error", "invalid x-api-key"), "unauthorized",
         ("anthropic", AUTH_WAIT), None, "unauthorized"),
        (failure(403, "permission_error", "no access"), "unauthorized",
         ("anthropic", AUTH_WAIT), None, "unauthorized"),
        (failure(402, "billing_error", "billing"), "no_credit", ("anthropic", QUOTA_WAIT),
         None, None),
        (failure(402, "billing_error", "billing", "120"), "no_credit",
         ("anthropic", timedelta(seconds=120)), None, None),
        (failure(400, "invalid_request_error", CREDIT), "no_credit", ("anthropic", QUOTA_WAIT),
         None, None),
        (failure(400, "invalid_request_error", LIMITS), "no_credit", ("anthropic", QUOTA_WAIT),
         None, None),
        (failure(400, "invalid_request_error", "prompt is too long: 1200000 tokens > 1000000"
                 " maximum"), "too_large", None, None, None),
        (failure(413, "request_too_large", "Request exceeds the maximum size"), "too_large",
         None, None, None),
        (failure(404, "not_found_error", "model: claude-haiku-5-5"), "model_mismatch",
         (HAIKU, AUTH_WAIT), None, "model_mismatch"),  # the one model waits
        (failure(404, "not_found_error", "Not Found"), "model_mismatch",
         ("anthropic", AUTH_WAIT), None, "model_mismatch"),  # the path: the provider waits
        (LlmReply(404, b"<html>404</html>", 5.0), "model_mismatch", ("anthropic", AUTH_WAIT),
         None, "model_mismatch"),
        (failure(400, "invalid_request_error", "messages.0.content: Field required"),
         "rejected", None, None, None),
        (LlmReply(400, b"not json", 5.0), "rejected", None, None, None),
        (LlmReply(402, b"", 5.0), "no_credit", ("anthropic", QUOTA_WAIT), None, None),
        (message(text('{"a"'), stop="max_tokens"), "truncated", None, None, None),
        (message(THINKING), "bad_answer", None, None, None),
        (message(text("```json\n\n```")), "bad_answer", None, None, None),
        (LlmReply(200, b"<html></html>", 5.0), "bad_answer", None, None, None),
    ],
)  # fmt: skip
async def test_each_anthropic_error_is_handled_as_its_kind_and_the_next_provider_answers(
    call: Call,
    reply: LlmReply,
    outcome: str,
    cooldown: tuple[str, timedelta] | None,
    breaker: str | None,
    alarm: str | None,
) -> None:
    gw, fake, store = make({"anthropic": [reply]})
    done = await gw.complete(call)
    assert done.provider == "free"
    assert [w.provider for w, _ in fake.sent] == ["anthropic", "free"]
    first, second = store.ledger
    assert (first.outcome, first.http_status, second.outcome) == (outcome, reply.status, "ok")
    state = await store.state()
    assert state.cooldowns == ({} if cooldown is None else {cooldown[0]: NOW + cooldown[1]})
    assert {n for n, b in state.breakers.items() if b.is_open(NOW)} == (
        {breaker} if breaker else set())  # fmt: skip
    assert {p: a.kind for p, a in state.alarms.items()} == ({"anthropic": alarm} if alarm else {})
    for a in state.alarms.values():
        assert ANTHROPIC_KEY.get_secret_value() not in a.detail
    if alarm == "model_mismatch":
        one = cooldown is not None and cooldown[0] == HAIKU
        found = state.alarms["anthropic"]
        assert found.detail == "claude-haiku-5-5 not found (404): the model name" + (
            "" if one else " or base_url")  # fmt: skip
        assert found.model == ("claude-haiku-5-5" if one else None)


async def test_a_404_naming_one_model_pauses_it_alone_and_its_alarm_stays(call: Call) -> None:
    missing = failure(404, "not_found_error", "model: claude-sonnet-5-5")
    gw, fake, store = make({"anthropic": [missing, message(text("{}"))]})
    medium = replace(call, tier=Tier.MEDIUM)
    assert (await gw.complete(medium)).provider == "free"
    done = await gw.complete(call)  # Haiku, beside it, still answers
    assert (done.provider, done.model) == ("anthropic", "claude-haiku-5-5")
    state = await store.state()
    assert state.cooldowns == {"anthropic/claude-sonnet-5-5": NOW + AUTH_WAIT}
    alarm = state.alarms["anthropic"]  # Haiku's answer does not disprove Sonnet's 404
    assert (alarm.kind, alarm.model) == ("model_mismatch", "claude-sonnet-5-5")
    sent = len(fake.sent)
    assert (await gw.complete(medium)).provider == "free"  # Sonnet waits, nothing is sent
    assert [w.provider for w, _ in fake.sent[sent:]] == ["free"]
    assert isinstance(gw.clock, Clock)
    gw.clock.now = NOW + AUTH_WAIT
    done = await gw.complete(medium)  # its hour is over and it answers: the alarm ends
    assert (done.provider, done.model) == ("anthropic", "claude-sonnet-5-5")
    assert (await store.state()).alarms == {}


def test_an_alarm_about_one_model_ends_with_that_model_or_a_probe() -> None:
    later = NOW + timedelta(minutes=1)
    state = budget.cool_down(budget.State(), "anthropic/claude-sonnet-5-5", NOW + AUTH_WAIT, NOW)
    state = budget.cool_down(state, "anthropic/claude-haiku-5-5", NOW + AUTH_WAIT, NOW)  # slow
    state = budget.raise_alarm(state, "anthropic", "model_mismatch", "x", NOW,
                               "claude-sonnet-5-5")  # fmt: skip
    assert budget.clear_alarm(state, "anthropic", answered="claude-haiku-5-5") is state
    assert budget.clear_alarm(state, "anthropic", answered="claude-sonnet-5-5").alarms == {}
    assert budget.clear_alarm(state, "anthropic").alarms == {}
    whole = budget.raise_alarm(state, "anthropic", "unauthorized", "401", NOW)
    assert budget.clear_alarm(whole, "anthropic", answered="claude-haiku-5-5").alarms == {}
    assert budget.from_json(budget.to_json(state)) == state
    old = budget.to_json(state)
    del old["alarms"]["anthropic"]["model"]  # a state written before the field
    assert budget.from_json(old).alarms["anthropic"].model is None
    cleared, up = budget.probe_up(state, "anthropic", later)  # it found the model listed
    assert cleared == state.alarms["anthropic"]
    assert (up.alarms, up.cooldowns) == ({}, {"anthropic/claude-haiku-5-5": NOW + AUTH_WAIT})


@pytest.mark.parametrize(
    ("raw", "names"),
    [
        (b'{"type": "error", "error": {"type": "not_found_error",'
         b' "message": "model: claude-opus-5-5"}}', True),
        (b'{"error": {"type": "not_found_error", "message": " Model: x (not available)"}}', True),
        (b'{"error": {"type": "not_found_error", "message": "Not Found"}}', False),
        (b'{"error": {"type": "invalid_request_error", "message": "model: x"}}', False),
        (b'{"error": {"type": "not_found_error", "message": 5}}', False),
        (b"<html>404</html>", False),
        (b"", False),
    ],
)  # fmt: skip
def test_a_404_names_the_model_only_in_anthropics_words(raw: bytes, names: bool) -> None:
    assert anthropic_api.missing_model(raw) is names


async def test_when_every_provider_waits_the_call_is_deferred_to_the_soonest(call: Call) -> None:
    gw, _, _ = make({"anthropic": [failure(402, "billing_error", "billing")],
                     "free": [failure(429, "rate_limit_error", "slow down", "30")]})  # fmt: skip
    with pytest.raises(NoCapacity) as caught:
        await gw.complete(call)
    assert caught.value.until == NOW + timedelta(seconds=30)
    assert "anthropic: no_credit (402)" in str(caught.value)


@pytest.mark.parametrize(
    "reply",
    [failure(402, "billing_error", "x"),
     failure(413, "request_too_large", "x"), failure(400, "x", "prompt is too long"),
     failure(400, "x", CREDIT)],
)  # fmt: skip
async def test_the_openai_wire_keeps_its_own_error_handling(call: Call, reply: LlmReply) -> None:
    gw, _, store = make(
        {"free": [reply], "anthropic": [message(text("{}"))]}, config(FREE, anthropic())
    )
    done = await gw.complete(call)
    assert done.provider == "anthropic"
    assert store.ledger[0].outcome == "rejected"
    assert (await store.state()).cooldowns == {}


@pytest.mark.parametrize(
    ("status", "raw", "kind"),
    [
        (402, b"", anthropic_api.QUOTA),
        (400, b'{"error": {"message": "CREDIT BALANCE IS TOO LOW"}}', anthropic_api.QUOTA),
        (413, b"", anthropic_api.TOO_LARGE),
        (400, b'{"error": {"message": "Prompt is too long"}}', anthropic_api.TOO_LARGE),
        (404, b"", anthropic_api.MODEL_MISMATCH),
        (400, b'{"error": {"message": 5}}', None),
        (400, b'{"error": "prompt is too long"}', None),
        (429, b'{"error": {"message": "credit balance is too low"}}', None),
        (500, b"", None),
    ],
)  # fmt: skip
def test_error_kinds(status: int, raw: bytes, kind: str | None) -> None:
    assert anthropic_api.error_kind(status, raw) == kind


# -- the transport: the key's header ----------------------------------------------------------


def transport_with(handler: Any, cfg: LlmConfig | None = None) -> HttpxLlmTransport:
    mock = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)
    return HttpxLlmTransport(cfg or config(), {"anthropic": mock, "free": mock, "other": mock})


async def test_anthropic_gets_the_key_in_x_api_key_with_the_version_and_no_bearer() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=message_body(text("{}")))

    transport = transport_with(handler)
    secret = ANTHROPIC_KEY.get_secret_value()
    post = LlmWire("anthropic", "https://api.anthropic.com/v1/messages", b'{"model":"m"}', 5.0)
    await transport.send(post, ANTHROPIC_KEY)
    await transport.get(LlmWire("anthropic", "https://api.anthropic.com/v1/models?limit=1000",
                                b"", 5.0), ANTHROPIC_KEY)  # fmt: skip
    await transport.send(LlmWire("free", "https://free.example/v1/chat/completions", b"{}", 5.0),
                         FREE_KEY)  # fmt: skip
    await transport.aclose()
    a_post, a_get, f_post = seen
    for request in (a_post, a_get):
        assert request.headers["x-api-key"] == secret
        assert request.headers["anthropic-version"] == "2026-10-21"
        assert "authorization" not in request.headers
        assert secret not in str(request.url)
    assert (a_post.method, a_get.method) == ("POST", "GET")
    assert a_post.headers["content-type"] == "application/json"
    assert a_post.content == post.body
    assert f_post.headers["authorization"] == f"Bearer {FREE_KEY.get_secret_value()}"
    assert "x-api-key" not in f_post.headers
    assert "anthropic-version" not in f_post.headers


async def test_the_configured_version_is_sent() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=b"{}")

    cfg = config(anthropic(api_version="2027-02-03"))
    await transport_with(handler, cfg).send(
        LlmWire("anthropic", cfg.providers[0].call_url(), b"{}", 5.0), ANTHROPIC_KEY
    )
    assert seen[0].headers["anthropic-version"] == "2027-02-03"


async def test_a_wire_for_a_provider_not_configured_is_never_sent() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=b"{}")

    wire = LlmWire("other", "https://other.example/v1/messages", b"{}", 5.0)
    with pytest.raises(TransportError, match="no configuration for provider 'other'") as caught:
        await transport_with(handler).send(wire, ANTHROPIC_KEY)
    assert caught.value.reached is False
    assert seen == []


async def test_the_key_is_in_no_recording_ledger_or_error(tmp_path: Path, call: Call) -> None:
    secret = ANTHROPIC_KEY.get_secret_value()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=message_body(THINKING, text('{"ok": true}')))

    path = tmp_path / "anthropic.json"
    recording = LlmCassette(path, "record", transport_with(handler))
    store = MemoryLlmStore()
    done = await LlmGateway(config(), KEYS, recording, store, Clock()).complete(call)
    recording.save()
    raw = path.read_text(encoding="utf-8")
    assert secret not in raw
    assert "x-api-key" not in raw
    assert "anthropic-version" not in raw
    assert all(secret not in k for k in recording.entries)
    assert secret not in repr(store.ledger)
    other = {**KEYS, "ANTHROPIC_API_KEY": SecretStr("another-made-up-key-0003")}
    again = await LlmGateway(config(), other, LlmCassette(path), MemoryLlmStore(),
                             Clock()).complete(call)  # fmt: skip
    assert again.text == done.text == '{"ok": true}'  # the key is no part of the recording

    def broken(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"refused {request.headers['x-api-key']}")

    wire = LlmWire("anthropic", "https://api.anthropic.com/v1/messages", b"{}", 5.0)
    with pytest.raises(TransportError) as caught:
        await transport_with(broken).send(wire, ANTHROPIC_KEY)
    assert secret not in str(caught.value)
    assert caught.value.__cause__ is None
    failed = MemoryLlmStore()
    gw = LlmGateway(config(anthropic()), KEYS, transport_with(broken), failed, Clock())
    with pytest.raises(NoCapacity):
        await gw.complete(call)
    assert failed.ledger[0].outcome == "no_answer: ConnectError"
    assert secret not in repr(failed.ledger)


# -- the probe --------------------------------------------------------------------------------

LISTED = {"data": [{"id": "claude-haiku-5-5", "max_input_tokens": 1000000, "max_tokens": 128000},
                   {"id": "claude-sonnet-5-5"}], "has_more": False,
          "first_id": "claude-haiku-5-5", "last_id": "claude-sonnet-5-5"}  # fmt: skip


@pytest.mark.parametrize(
    ("response", "state", "detail"),
    [
        (httpx.Response(200, json=LISTED), ProbeState.UP,
         "claude-haiku-5-5, claude-sonnet-5-5 listed"),
        (httpx.Response(200, json={**LISTED, "data": LISTED["data"][:1]}),
         ProbeState.MODEL_MISMATCH, "claude-sonnet-5-5 not listed (it lists claude-haiku-5-5)"),
        (httpx.Response(401, json={"type": "error", "error": {"type": "authentication_error"}}),
         ProbeState.UNAUTHORIZED, "the key was refused (401)"),
        (httpx.Response(529, json={"type": "error", "error": {"type": "overloaded_error"}}),
         ProbeState.DOWN, "answered 529"),
    ],
)  # fmt: skip
async def test_the_probe_asks_anthropic_for_its_whole_model_list(
    response: httpx.Response, state: ProbeState, detail: str
) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return response

    result = await probe(config().providers[0], ANTHROPIC_KEY, transport_with(handler))
    assert (result.state, result.detail) == (state, detail)
    (request,) = seen
    assert (request.method, str(request.url)) == (
        "GET",
        "https://api.anthropic.com/v1/models?limit=1000",
    )
    assert request.headers["x-api-key"] == ANTHROPIC_KEY.get_secret_value()
    assert "authorization" not in request.headers


# -- what lists providers and keys ------------------------------------------------------------


def test_the_shipped_anthropic_key_is_listed_and_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    keys = tmp_path / "keys.env"
    keys.write_text("ANTHROPIC_API_KEY=made-up-anthropic-key-0006\n", encoding="utf-8")
    alone = tmp_path / "llm.yaml"  # an installation's llm.local.yaml is its own
    alone.write_text(DEFAULT_PATH.read_text(encoding="utf-8"), encoding="utf-8")
    shipped = load_config(alone).model_copy(update={"keys_file": keys})
    assert callable_providers(shipped) == ["anthropic"]
    found = providers_check(shipped, {"ANTHROPIC_API_KEY"})
    assert "anthropic (on, key)" in found.detail
    assert "openai (on, no key)" in found.detail
    assert "made-up-anthropic-key-0006" not in found.detail


async def test_an_openai_compatible_404_is_a_retired_model_alone_with_an_alarm(call: Call) -> None:
    # a free model the provider no longer serves answered 404 for three days with no alarm
    gone = LlmReply(404, b'{"error":{"message":"No endpoints found for f-small.","code":404}}', 5.0)
    gw, _, store = make(
        {"free": [gone], "anthropic": [message(text("{}"))]}, config(FREE, anthropic())
    )
    done = await gw.complete(call)
    assert done.provider == "anthropic"
    assert [e.outcome for e in store.ledger] == ["model_mismatch", "ok"]
    state = await store.state()
    assert state.cooldowns == {"free/f-small": NOW + AUTH_WAIT}  # f-medium beside it is not held
    alarm = state.alarms["free"]
    assert (alarm.kind, alarm.model) == ("model_mismatch", "f-small")
    assert alarm.detail == "f-small not found (404): the model name"
