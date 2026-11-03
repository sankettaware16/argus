"""Strict, byte-exact cassettes of Kibana and Elasticsearch exchanges (Q-D1).

A cassette is the list of one test's exchanges with the local tier, in order: who asked (a
principal label, never a credential), the method, the path, the query, the body, and the
answer's status and body. Values that differ between runs are replaced by placeholders, so two
runs from a clean volume write the same bytes:

* the run's id -> ``<run>``; every registered secret (a generated password, an API key) ->
  ``<secret>``;
* UUIDs -> ``<uuid:N>``, 64-hex ids (alert ids) -> ``<hex:N>``, Elasticsearch's 20-character ids
  (API keys) -> ``<id:N>``, case versions -> ``<version:N>``, numbered by first appearance, so
  the same value is always the same placeholder within a cassette;
* timestamps -> ``<time>``; timings and sequence numbers (``took``, ``_seq_no``, ...) by key.

Live (the tier answers), the normalized recording must equal the committed cassette byte for
byte (``KIBANA_TIER_RECORD=1`` rewrites it after a reviewed change); a missing one is an error
(``KIBANA_TIER_RECORD=new`` writes the missing ones, for a new test). Replay (no tier), every
request must equal the next recorded one, or the test fails with ``CassetteMismatchError``: nothing
is answered that was not recorded. Answers are de-normalized for the test: a placeholder whose
value the test already sent becomes that value again; a new one becomes a stand-in of the right
shape, unique to the cassette.
"""

from __future__ import annotations

import base64
import difflib
import hashlib
import json
import re
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

FORMAT = 1
CASSETTES = Path(__file__).resolve().parent / "cassettes"
STAND_IN_TIME = "2000-01-01T00:00:00.000Z"
SECRET = "<secret>"

UUID = re.compile(
    r"(?<![0-9A-Fa-f-])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?![0-9A-Fa-f-])"
)
HEX64 = re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])")
TIME = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?(?![0-9])"
)
# Elasticsearch's random ids (API keys, auto ids): 20 base64url characters. Ordinary words of
# that length are left alone: an id has upper and lower case letters and a digit, or stands
# where ids stand (ID_KEYS, ES_ID_IN_TEXT): about 3 % of real ids hold no digit.
ES_ID = re.compile(r"(?<![A-Za-z0-9_\-])[A-Za-z0-9_\-]{20}(?![A-Za-z0-9_\-])")
ES_ID_SHAPE = re.compile(r"[A-Za-z0-9_\-]{20}")
ID_KEYS = frozenset(
    {"id", "_id", "ids", "invalidated", "invalidated_api_keys", "previously_invalidated_api_keys"}
)
ES_ID_IN_TEXT = re.compile(r"(?i)\bapi key (?:id )?\[([A-Za-z0-9_\-]{20})\]")
VERSION = re.compile(r"^Wz[A-Za-z0-9+/]+={0,2}$")  # a case version: base64 of [seq_no,term]
PLACEHOLDER = re.compile(r"<(uuid|hex|id|version):(\d+)>")
# A long run of one character (a limit test's 30,000 "d"s) is kept as its count.
REPEAT = re.compile(r"(.)\1{99,}", re.DOTALL)
REPEATED = re.compile(r"<repeat:(.)x(\d+)>", re.DOTALL)
# Values that vary with timing, by key: replaced whatever they hold.
VOLATILE_KEYS = {
    "took": "<took>",
    "_seq_no": "<seq>",
    "_primary_term": "<term>",
    "duration": "<duration>",
    "issue_date_in_millis": "<millis>",
    "expiry_date_in_millis": "<millis>",
    "expiration": "<millis>",
    "creation": "<millis>",
    "invalidation": "<millis>",
    # a case's timings (seconds between its create and its first status changes)
    "time_to_acknowledge": "<seconds>",
    "time_to_investigate": "<seconds>",
    "time_to_resolve": "<seconds>",
}
SECRET_KEYS = frozenset({"password", "api_key", "encoded", "token", "access_token"})


def _is_es_id(text: str) -> bool:
    return (
        any(c.isupper() for c in text)
        and any(c.islower() for c in text)
        and any(c.isdigit() for c in text)
    )


@dataclass
class Normalizer:
    """One cassette's mapping between real values and placeholders, kept for the whole
    recording or replay so that a value keeps its placeholder."""

    run: str
    secrets: set[str] = field(default_factory=set)
    namespace: str = ""
    # values the same in every run (the seed's argus_uid values): kept as they are, so a test
    # can compare an answer with them in replay too
    constants: frozenset[str] = frozenset()
    values: dict[str, dict[str, int]] = field(default_factory=dict)  # kind -> value -> n
    reverse: dict[str, dict[int, str]] = field(default_factory=dict)  # kind -> n -> value
    ids: set[str] = field(default_factory=set)  # Elasticsearch ids known by where they stand

    def learn(self, value: Any, key: str | None = None) -> None:
        """Note the Elasticsearch ids in ``value`` by where they stand (under an id key, or in
        "API key id [...]"), whatever characters they hold. A recording is learnt whole before
        it is normalized, so an id first seen in a message is an id there too."""
        if isinstance(value, dict):
            for k, v in value.items():
                self.learn(v, str(k))
        elif isinstance(value, list):
            for v in value:
                self.learn(v, key)
        elif isinstance(value, str):
            if key in ID_KEYS and ES_ID_SHAPE.fullmatch(value):
                self.ids.add(value)
            self.ids.update(m[1] for m in ES_ID_IN_TEXT.finditer(value))

    def secret(self, value: str) -> None:
        if value:
            self.secrets.add(value)

    def _index(self, kind: str, value: str) -> int:
        known = self.values.setdefault(kind, {})
        if value not in known:
            n = len(known) + 1
            while n in self.reverse.setdefault(kind, {}):
                n += 1
            known[value] = n
            self.reverse[kind][n] = value
        return known[value]

    # ----------------------------------------------------------------------- normalize

    def text(self, value: str) -> str:
        for secret in sorted(self.secrets, key=len, reverse=True):
            value = value.replace(secret, SECRET)
        if self.run:
            value = value.replace(self.run, "<run>")
        value = REPEAT.sub(lambda m: f"<repeat:{m[1]}x{len(m[0])}>", value)
        value = HEX64.sub(lambda m: f"<hex:{self._index('hex', m[0])}>", value)
        value = UUID.sub(
            lambda m: (
                m[0]
                if m[0].lower() in self.constants
                else f"<uuid:{self._index('uuid', m[0].lower())}>"
            ),
            value,
        )
        value = TIME.sub("<time>", value)
        return ES_ID.sub(
            lambda m: (
                f"<id:{self._index('id', m[0])}>"
                if _is_es_id(m[0]) or m[0] in self.ids or m[0] in self.values.get("id", {})
                else m[0]
            ),
            value,
        )

    def normalize(self, value: Any, key: str | None = None) -> Any:
        if key in VOLATILE_KEYS and isinstance(value, int | float) and not isinstance(value, bool):
            return VOLATILE_KEYS[key]
        if (
            key == "sort"
            and isinstance(value, list)
            and all(isinstance(v, int | float | str) for v in value)
        ):
            return "<sort>"  # a hit's sort values (epoch millis); a request's sort holds objects
        if key in SECRET_KEYS and isinstance(value, str):
            return SECRET
        if isinstance(value, dict):
            return {str(k): self.normalize(v, str(k)) for k, v in value.items()}
        if isinstance(value, list):
            return [self.normalize(v, key) for v in value]
        if isinstance(value, str):
            self.learn(value, key)  # replay normalizes request by request, unlearnt
            if key == "version" and VERSION.match(value):
                return f"<version:{self._index('version', value)}>"
            return self.text(value)
        return value

    # ----------------------------------------------------------------------- de-normalize

    def _stand_in(self, kind: str, n: int) -> str:
        seed = f"{self.namespace}:{kind}:{n}"
        digest = hashlib.sha256(seed.encode()).hexdigest()
        if kind == "uuid":
            return str(uuid.UUID(digest[:32], version=4))
        if kind == "hex":
            return digest
        if kind == "version":
            return base64.b64encode(f"[{n},{int(digest[:6], 16)}]".encode()).decode()
        # an Elasticsearch id: 20 characters with an upper, a lower case letter and a digit
        body = base64.urlsafe_b64encode(bytes.fromhex(digest[:30])).decode()[:17]
        return f"Q{body}x{n % 10}"

    def _value(self, kind: str, n: int) -> str:
        known = self.reverse.setdefault(kind, {})
        if n not in known:
            value = self._stand_in(kind, n)
            known[n] = value
            self.values.setdefault(kind, {})[value] = n
        return known[n]

    def denormalize(self, value: Any, key: str | None = None) -> Any:
        if isinstance(value, dict):
            return {k: self.denormalize(v, k) for k, v in value.items()}
        if isinstance(value, list):
            return [self.denormalize(v, key) for v in value]
        if not isinstance(value, str):
            return value
        if value in ("<took>", "<seq>", "<term>", "<duration>", "<millis>", "<seconds>"):
            return 0
        if value == "<sort>":
            return [0]
        if value == SECRET:
            return "replay-secret"
        value = value.replace("<run>", self.run).replace("<time>", STAND_IN_TIME)
        value = REPEATED.sub(lambda m: m[1] * int(m[2]), value)
        return PLACEHOLDER.sub(lambda m: self._value(m[1], int(m[2])), value)


@dataclass(frozen=True)
class Exchange:
    """One request and its answer, as a cassette holds it."""

    target: str  # "kibana" or "es"
    principal: str  # who asked: a label such as "elastic" or "key:argus-kibana-reader"
    method: str
    path: str
    params: tuple[tuple[str, str], ...]
    body: Any
    headers: tuple[tuple[str, str], ...]
    status: int
    answer: Any

    def request_part(self) -> dict[str, Any]:
        part: dict[str, Any] = {
            "target": self.target,
            "as": self.principal,
            "method": self.method,
            "path": self.path,
        }
        if self.params:
            part["params"] = [list(p) for p in self.params]
        if self.body is not None:
            part["body"] = self.body
        if self.headers:
            part["headers"] = [list(h) for h in self.headers]
        return part

    def as_json(self) -> dict[str, Any]:
        return {**self.request_part(), "status": self.status, "answer": self.answer}


class CassetteMismatchError(AssertionError):
    """A replayed request the cassette does not hold next, or a live run that differs."""


def dump(exchanges: Iterable[dict[str, Any]]) -> str:
    """The cassette's bytes: stable key order, one indent, a final newline."""
    return (
        json.dumps({"format": FORMAT, "exchanges": list(exchanges)}, indent=1, sort_keys=True)
        + "\n"
    )


def load(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("format") != FORMAT:
        raise ValueError(f"{path}: cassette format {data.get('format')} is not {FORMAT}")
    exchanges: list[dict[str, Any]] = data["exchanges"]
    return exchanges


def diff(expected: str, actual: str, name: str, lines: int = 80) -> str:
    out = list(
        difflib.unified_diff(
            expected.splitlines(),
            actual.splitlines(),
            f"{name} (committed)",
            f"{name} (this run)",
            lineterm="",
            n=2,
        )
    )
    more = f"\n... {len(out) - lines} more lines" if len(out) > lines else ""
    return "\n".join(out[:lines]) + more


@dataclass
class Recorder:
    """Records one cassette (live) or answers from it (replay)."""

    name: str
    run: str
    mode: str  # "live" or "replay"
    # live: True rewrites the cassette instead of comparing it; "new" writes it only when none
    # is committed; False (the default) compares, and a missing cassette is an error
    record: bool | str = False
    directory: Path = CASSETTES
    normalizer: Normalizer = field(init=False)
    raw: list[Exchange] = field(default_factory=list)  # live: what was sent and answered
    replayed: list[dict[str, Any]] = field(default_factory=list)
    position: int = 0
    secrets: set[str] = field(default_factory=set)
    constants: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        self.normalizer = Normalizer(self.run, namespace=self.name, constants=self.constants)
        self._loaded = False

    def _replayed(self) -> list[dict[str, Any]]:
        """The cassette's exchanges, read at the first replayed request."""
        if not self._loaded:
            if not self.path.is_file():
                raise CassetteMismatchError(
                    f"no cassette {self.path.name}: run this test once with the Kibana tier "
                    "up (docs/runbooks/kibana-tier.md) to record it"
                )
            self.replayed = load(self.path)
            self._loaded = True
        return self.replayed

    @property
    def path(self) -> Path:
        return self.directory / f"{self.name}.json"

    def secret(self, value: str) -> None:
        """A value that must never reach a cassette (a password, a key)."""
        self.secrets.add(value)
        self.normalizer.secret(value)

    # ----------------------------------------------------------------------- replay

    def answer(self, request: Exchange) -> tuple[int, Any]:
        """The recorded answer to ``request`` (replay), which must be the next one recorded."""
        wanted = self.normalizer.normalize(request.request_part())
        replayed = self._replayed()
        if self.position >= len(replayed):
            raise CassetteMismatchError(
                f"{self.name}: request {self.position + 1} is not in the cassette "
                f"(it holds {len(replayed)}): {json.dumps(wanted)[:400]}"
            )
        recorded = replayed[self.position]
        held = {k: v for k, v in recorded.items() if k not in ("status", "answer")}
        if held != wanted:
            raise CassetteMismatchError(
                f"{self.name}: request {self.position + 1} differs from the cassette\n"
                + diff(
                    json.dumps(held, indent=1, sort_keys=True),
                    json.dumps(wanted, indent=1, sort_keys=True),
                    self.name,
                )
            )
        self.position += 1
        return int(recorded["status"]), self.normalizer.denormalize(recorded["answer"])

    # ----------------------------------------------------------------------- live

    def add(self, exchange: Exchange) -> None:
        self.raw.append(exchange)

    def normalized(self) -> str:
        normalizer = Normalizer(self.run, namespace=self.name, constants=self.constants)
        for value in self.secrets:
            normalizer.secret(value)
        for exchange in self.raw:
            normalizer.learn(exchange.as_json())
        return dump(normalizer.normalize(e.as_json()) for e in self.raw)

    def finish(self, on_note: Callable[[str], None] = lambda _: None) -> None:
        """Live: compare with (or write) the committed cassette. Replay: every recorded
        exchange must have been asked for."""
        if self.mode == "replay":
            if not self._loaded and not self.path.is_file():
                return  # asked for nothing, and holds nothing
            if self.position != len(self._replayed()):
                raise CassetteMismatchError(
                    f"{self.name}: {len(self.replayed) - self.position} recorded requests were "
                    "never made"
                )
            return
        if not self.raw and not self.path.is_file():
            return  # a test that recorded nothing (live-only checks) keeps no cassette
        text = self.normalized()
        for value in self.secrets:
            if value and value in text:  # the normalizer replaced them; a last guard
                raise AssertionError(f"{self.name}: a secret would reach the cassette")
        if not self.path.is_file() and self.record is False:
            raise CassetteMismatchError(
                f"{self.name}: no committed cassette {self.path.name}. A new test records its "
                "first one with KIBANA_TIER_RECORD=new (writes missing cassettes only); review "
                "it and commit it"
            )
        if self.record is True or not self.path.is_file():
            self.directory.mkdir(parents=True, exist_ok=True)
            self.path.write_text(text, encoding="utf-8")
            on_note(f"cassette {self.path.name} written ({len(self.raw)} exchanges)")
            return
        committed = self.path.read_text(encoding="utf-8")
        if committed != text:
            raise CassetteMismatchError(
                f"{self.name}: the tier answered differently from the committed cassette "
                "(a contract changed?). If the change is understood and reviewed, re-record "
                "with KIBANA_TIER_RECORD=1.\n" + diff(committed, text, self.path.name)
            )
