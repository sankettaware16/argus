"""The egress validator (P1; plan §2.2, D-076): the last check on the exact bytes of a request
before it leaves, and on a model's answer before it is used.

``check(payload, campus, ordinary=...)`` blocks a request that holds any identifier
``argus.llm.detect`` finds, in clear or encoded. A JSON payload (a provider's body) is
checked as bytes and then string by string, once decoded (JSON escapes hide nothing). In a
text, each quoted string is untrusted: there no word is exempt from being a name.
``ordinary`` (ARGUS's own template words) is exempt only outside quotes. Any error inside
the check blocks too (fail closed). A ``Verdict`` holds kinds only, never a value or an
excerpt, so it can be stored and logged (P5's ledger).

``foreign(answer, items, about)`` lists the pseudonyms in a text that belong to no item of
the request, or to an item other than ``about`` (plan §5.2).
"""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, replace
from typing import Any

from argus.llm.detect import TOKEN, Campus, find

MAX_BYTES = 128 * 1024  # requests are at most 60,000 characters; anything bigger is refused
QUOTED = re.compile(r'"(?:[^"\\\n]|\\.){0,4000}"')


@dataclass(frozen=True)
class Blocked:
    kind: str
    encoded: bool
    part: str  # "bytes" (the payload as sent), "json" (a decoded string), "quoted" (inside it)


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    findings: tuple[Blocked, ...] = ()
    error: str | None = None  # why the check itself failed (then nothing is allowed)

    def audit(self) -> dict[str, Any]:
        """What may be stored and logged: counts per kind, no values, no excerpts."""
        kinds = Counter(f.kind + (" (encoded)" if f.encoded else "") for f in self.findings)
        return {"allowed": self.allowed, "kinds": dict(sorted(kinds.items())), "error": self.error}


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield str(k)
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)


def _quoted(text: str) -> Iterator[str]:
    """The JSON-quoted strings inside ``text``, decoded (untrusted text is quoted)."""
    for m in QUOTED.finditer(text):
        try:
            inner = json.loads(m.group(0))
        except ValueError:
            inner = m.group(0)[1:-1]
        if isinstance(inner, str):
            yield inner


def _check(text: str, strict: Campus, outside: Campus, part: str) -> list[Blocked]:
    out = [Blocked(f.kind, f.encoded, part) for f in find(text, outside)]
    for inner in _quoted(text):
        out += [Blocked(f.kind, f.encoded, "quoted") for f in find(inner, strict)]
    return out


def check(payload: bytes | str, campus: Campus, ordinary: Iterable[str] = ()) -> Verdict:
    try:
        raw = payload if isinstance(payload, bytes) else payload.encode("utf-8")
        if len(raw) > MAX_BYTES:
            return Verdict(False, error="too large")
        text = raw.decode("utf-8")
        strict = replace(campus, ordinary=frozenset())
        outside = replace(campus, ordinary=frozenset(w.lower() for w in ordinary))
        try:
            decoded = json.loads(text)
        except ValueError:
            decoded = None
        if isinstance(decoded, dict | list):
            # a provider's body: the bytes as sent, then each of its strings as a text of its
            # own (whose quoted parts are the untrusted ones), not the body's own quotes
            findings = [Blocked(f.kind, f.encoded, "bytes") for f in find(text, outside)]
            for string in _strings(decoded):
                findings += _check(string, strict, outside, "json")
        else:
            findings = _check(text, strict, outside, "bytes")
        return Verdict(not findings, tuple(findings))
    except Exception as exc:  # fail closed on anything
        return Verdict(False, error=type(exc).__name__)


def foreign(answer: str, items: Iterable[str], about: str | None = None) -> list[str]:
    """Pseudonyms in ``answer`` that are not ``about``'s (or, without ``about``, belong to no
    item in ``items``). A bare pseudonym without an item prefix is foreign as well."""
    allowed = {about} if about is not None else set(items)
    out = []
    for m in TOKEN.finditer(answer):
        token = m.group(0)
        item = token.split(".", 1)[0] if "." in token else None
        if item not in allowed:
            out.append(token)
    return out
