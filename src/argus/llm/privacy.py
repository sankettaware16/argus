"""The model's view of a dossier (P1; plan §2.1, §5.1, §5.2, §5.5, D-075, D-076).

``Privacy.request(bodies)`` turns dossier bodies into one ``Request``:
- each body becomes an item (``I1``, ``I2``…) built field by field under the data policy
  (``config/llm_data_policy.yaml``, default deny); a body that cannot be read is left out;
- internal identifiers become typed pseudonyms in a space of their own per item
  (``I2.IP_1``, ``I2.HOST_1``); public addresses and domains stay as they are;
- times are relative, counts are rounded, untrusted text is decoded, cleaned, stripped of
  anything shaped like a pseudonym, quoted and capped on a token boundary;
- then the text is rendered, cut only between items.
Re-identification (``Request.reveal``) happens only in memory, for one item, and refuses an
answer that names any other pseudonym. The map is never printed, pickled or stored.
``Request.validate`` runs the egress validator on the exact text.
"""

from __future__ import annotations

import ast
import fnmatch
import ipaddress
import json
import math
import re
import unicodedata
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal, NoReturn
from urllib.parse import SplitResult, urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field

from argus import site
from argus.assets.assetmap import AssetMap
from argus.assets.classify import IpClass, IpClassifier
from argus.context import display
from argus.llm import egress
from argus.llm.detect import LOOKALIKE, TOKEN, Campus, Found, canonical, find, outermost
from argus.outside import facts as outside

POLICY = Path(__file__).resolve().parents[3] / "config" / "llm_data_policy.yaml"
Action = Literal["send", "number", "ip", "domain", "url", "host", "user", "drop"]
_NAME = re.compile(r"[a-z0-9_.@*-]{1,80}")
_SCHEME = re.compile(r"[a-z][a-z0-9+.-]{0,15}")
_HASH_LENGTHS = (32, 40, 64, 128)
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_MON = "|".join(_MONTHS)
_TIMES = (
    # ISO 8601 with a time, compact ISO, Apache, Kibana, syslog (no year), a bare date, epoch
    re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?\b"),
    re.compile(r"\b\d{8}T\d{6}Z?\b"),
    re.compile(rf"\b\d{{2}}/(?:{_MON})/\d{{4}}:\d{{2}}:\d{{2}}:\d{{2}}(?: [+-]\d{{4}})?"),
    re.compile(rf"\b(?:{_MON}) \d{{1,2}}, \d{{4}} @ \d{{2}}:\d{{2}}(?::\d{{2}}(?:\.\d+)?)?"),
    re.compile(rf"\b(?:{_MON}) {{1,2}}\d{{1,2}} \d{{2}}:\d{{2}}:\d{{2}}\b"),
    re.compile(r"\b\d{4}-\d{2}-\d{2}\b"),
    re.compile(r"(?<!\d)1[5-9]\d{8}(?:\d{3})?(?!\d)"),
)
_CUT = " […]"
_GLUE = re.compile(r"[\w.-]")
_FORGED = "[pseudonym-like text]"


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: int = Field(ge=1)
    # extra campus domains besides ``site.own_domains`` (D-284); the privacy layer uses both
    campus_domains: tuple[str, ...] = ()
    asset_fields: tuple[str, ...] = ()
    # index patterns whose URL query values are sent; None (left out): the site's web families
    query_values_for: tuple[str, ...] | None = None
    text_chars: int = Field(default=300, ge=40, le=2000)
    top_values: int = Field(default=5, ge=1, le=20)
    entities: int = Field(default=10, ge=1, le=50)
    ti_answers: int = Field(default=10, ge=1, le=50)
    fields: dict[str, Action]


class PrivacyConfigError(ValueError):
    """The privacy layer cannot run with what is configured: it fails closed (nothing is built,
    nothing is sent) rather than send text that names the organisation."""


def query_patterns(policy: Policy) -> tuple[str, ...]:
    """The index patterns whose URL query values are sent: the policy's ``query_values_for``, or,
    left out, the site's web families (D-294), each daily pattern with the separator before its
    ``*`` dropped (``acme-logs-nginx-*`` as ``acme-logs-nginx*``: a rule may name it either way)."""
    if policy.query_values_for is not None:
        return policy.query_values_for
    return tuple(
        f.prefix.rstrip("-._") + "*" if f.daily else f.pattern
        for f in site.active().of_role(site.Role.WEB)
    )


def own_domains_of(policy: Policy) -> tuple[str, ...]:
    """The organisation's own domains the privacy layer replaces and keeps out of outside lookups:
    ``site.own_domains`` and the policy's ``campus_domains``, each once. A layer that knows none
    would let ``example.org`` through to a cloud provider, so it refuses to run (D-285)."""
    domains = site.own_domains(policy.campus_domains)
    if not domains:
        raise PrivacyConfigError(
            "the privacy layer needs at least one domain of the organisation: list them in"
            " site.own_domains (or campus_domains in config/llm_data_policy.yaml). Until then"
            " no text is built for a model."
        )
    return domains


def load_policy(path: Path = POLICY, *, require_domains: bool = True) -> Policy:
    """The data policy. It refuses (``PrivacyConfigError``) while the organisation's domains are
    unknown: ``site.own_domains`` and its ``campus_domains`` together name none. ``require_domains``
    False is for a reader that sends nothing to a model (the case titles read the list)."""
    policy = Policy.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    if require_domains:
        own_domains_of(policy)
    return policy


@lru_cache(maxsize=1)
def template_words() -> frozenset[str]:
    """The words ARGUS writes outside quotes: this module's string constants (not its
    docstrings) and the signal registry's labels and sentences. The validator does not take
    them for names outside quoted text; inside quotes (untrusted text) nothing is exempt,
    and the pseudonymizer never exempts anything."""
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    docstrings = set()
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if isinstance(body, list) and body and isinstance(body[0], ast.Expr):
            docstrings.add(id(body[0].value))
    texts = [
        n.value
        for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docstrings
    ]
    for entry in display.registry().values():
        texts += [entry.label, entry.sentence]
    texts.extend(display.PARTS.values())
    # the legends are written with the site's words, so the AST holds their tokens, not their text
    texts += [*_LEGENDS.values(), site.a_own("host name"), site.a_own("site"),
              site.a_own("device"), site.a_own("public address")]  # fmt: skip
    return frozenset(w.lower() for t in texts for w in re.findall(r"[A-Za-z0-9]+", t))


def bucket(n: float) -> str:
    """A count as sent: exact below 100, else 2 significant figures with separators (so that
    no long digit run reads as an address)."""
    if not math.isfinite(n):
        return "?"
    value = int(n)
    if abs(value) < 100:
        return str(value)
    digits = len(str(abs(value))) - 2
    return f"~{round(value, -digits):,}"


def quote(text: str) -> str:
    """Untrusted text as a JSON string; ``<``, ``>`` and line separators escaped, so it can
    neither close a tag nor start a line of its own."""
    out = json.dumps(text, ensure_ascii=False)
    for c in "<>\u2028\u2029\u0085":
        out = out.replace(c, f"\\u{ord(c):04x}")
    return out


class Pseudonyms:
    """One item's pseudonym space. Never printed, pickled or stored (plan §2.6)."""

    def __init__(self, item: str) -> None:
        self.item = item
        self._token: dict[tuple[str, str], str] = {}
        self._value: dict[str, str] = {}
        self._count: dict[str, int] = {}
        self.legend: dict[str, str] = {}

    def token(self, label: str, value: str, legend: str | None = None) -> str:
        key = (label, value.lower())
        found = self._token.get(key)
        if found is None:
            self._count[label] = self._count.get(label, 0) + 1
            found = f"{self.item}.{label}_{self._count[label]}"
            self._token[key] = found
            self._value[found] = value
        if legend and found not in self.legend:
            self.legend[found] = legend
        return found

    def value(self, token: str) -> str | None:
        return self._value.get(token)

    def __len__(self) -> int:
        return len(self._value)

    def __repr__(self) -> str:
        return f"Pseudonyms({self.item}, {len(self)} values)"

    def __reduce__(self) -> NoReturn:
        raise TypeError("pseudonym maps are never pickled")


@dataclass
class Item:
    id: str
    lines: list[str]
    pseudonyms: Pseudonyms
    withheld: int = 0
    truncated: bool = False

    @property
    def text(self) -> str:
        return "\n".join([f'<item id="{self.id}">', *self.lines, "</item>"])


@dataclass
class Request:
    text: str
    items: tuple[str, ...]  # rendered, in order
    omitted: tuple[str, ...]  # built but cut by the size limit
    failed: tuple[str, ...]  # bodies that could not be read: never sent
    truncated: tuple[str, ...]  # rendered items with untrusted text cut (plan §5.5)
    campus: Campus = field(repr=False)
    _maps: dict[str, Pseudonyms] = field(repr=False, default_factory=dict)

    def validate(self) -> egress.Verdict:
        return egress.check(self.text, self.campus, ordinary=template_words())

    def check(self, body: bytes) -> egress.Verdict:
        """The validator on the exact bytes a provider would receive (P5)."""
        return egress.check(body, self.campus, ordinary=template_words())

    def unknown(self, answer: str, about: str) -> list[str]:
        """Pseudonyms in ``answer`` that are not ``about``'s own, or that it never had."""
        own = self._maps.get(about)
        return [
            m.group(0)
            for m in TOKEN.finditer(answer)
            if own is None
            or not m.group(0).startswith(about + ".")
            or own.value(m.group(0)) is None
        ]

    def reveal(self, answer: str, about: str) -> str:
        """``answer`` (about item ``about``) with its pseudonyms replaced by their values, in
        memory only. Refuses an answer naming any other item's or an unknown pseudonym."""
        unknown = self.unknown(answer, about)
        if unknown:
            raise ValueError(f"{len(unknown)} pseudonym(s) not of {about} in the answer")
        own = self._maps[about]
        return TOKEN.sub(lambda m: own.value(m.group(0)) or m.group(0), answer)


def _label(found: Found, campus: Campus) -> str:
    match found.kind:
        case "ip":
            return "IP"
        case "mac":
            return "MAC"
        case "domain":
            return "SITE"
        case "name":
            return "USER" if campus.name_kind(found.value) == "user" else "HOST"
        case "email":
            return "EMAIL"
        case "user_path" | "roll_number":
            return "USER"
        case "hex_id":  # a UUID has dashes; a hash is plain hex of a hash's length
            return "HASH" if "-" not in found.value and len(found.value) in _HASH_LENGTHS else "ID"
        case _:
            return "CRED"


_LEGENDS = site.Words(
    {  # what the model is told a token stands for (the site's words)
        "MAC": "a hardware (MAC) address",
        "SITE": "{a_own:site}",
        "HOST": "{a_own:host name}",
        "USER": "a user",
        "EMAIL": "an e-mail address",
        "HASH": "a hash value",
        "ID": "an opaque identifier",
        "CRED": "a secret or credential",
    }
)


def _seq(value: Any) -> list[Any]:
    """A list as a list; anything else as one value (never iterated letter by letter)."""
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _map(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


class Privacy:
    # what an item's values are replaced with, and how; P2's comparison arms swap them (D-078)
    space: Callable[[str], Pseudonyms] = Pseudonyms
    scrub: type[_Scrub]

    def __init__(self, policy: Policy, classifier: IpClassifier, campus: Campus) -> None:
        self.policy = policy
        self.classifier = classifier
        self.campus = campus

    @classmethod
    def build(
        cls,
        policy: Policy,
        assets: AssetMap | None,
        campus_prefixes: Sequence[ipaddress.IPv4Network | ipaddress.IPv6Network] = (),
    ) -> Privacy:
        """Fails closed without an asset map: without it, asset names cannot be recognised."""
        if assets is None:
            raise ValueError("the privacy layer needs the asset map")
        campus = Campus(
            networks=tuple(campus_prefixes),
            domains=own_domains_of(policy),
            assets=frozenset(e.name for e in assets.entries),
            is_internal=lambda ip: assets.match(ip) is not None,
        )
        return cls(policy, IpClassifier(assets, campus_prefixes), campus)

    # -- the request ----------------------------------------------------------------------

    def request(self, bodies: Sequence[Any], max_chars: int = 60_000) -> Request:
        """Items for ``bodies`` (dossier bodies) rendered as one text of at most ``max_chars``;
        an item that does not fit is left out whole, and so is every one after it."""
        campus = self.campus_for(bodies)
        items: list[Item] = []
        failed: list[str] = []
        ids = [f"I{n}" for n in range(1, len(bodies) + 1)]
        for item_id, body in zip(ids, bodies, strict=True):
            try:
                item = self._item(body, item_id, campus)
            except Exception:  # an unreadable body is left out, never sent half-built
                failed.append(item_id)
                continue
            if egress.foreign(item.text, ids, about=item_id):
                failed.append(item_id)  # never expected: untrusted look-alikes are removed
                continue
            items.append(item)
        kept: list[Item] = []
        size = 0
        for item in items:
            text = item.text
            if size + len(text) + (1 if kept else 0) > max_chars:
                break
            size += len(text) + (1 if kept else 0)
            kept.append(item)
        return Request(
            text="\n".join(i.text for i in kept),
            items=tuple(i.id for i in kept),
            omitted=tuple(i.id for i in items[len(kept) :]),
            failed=tuple(failed),
            truncated=tuple(i.id for i in kept if i.truncated),
            campus=campus,
            _maps={i.id: i.pseudonyms for i in kept},
        )

    def campus_for(self, bodies: Iterable[Any]) -> Campus:
        """The base campus plus every host and user name these dossiers mention: entities,
        fields and grouping keys whose policy action is ``host`` or ``user``. Public so that
        outside lookups (AR3) refuse exactly what the model's view of an item scrubs."""
        hosts: set[str] = set()
        users: set[str] = set()
        for body in bodies:
            try:
                facts = _map(_map(body).get("facts"))
                entities = _map(facts.get("entities"))
                hosts.update(str(v) for v in _seq(entities.get("host")))
                users.update(str(v) for v in _seq(entities.get("user")))
                pairs = self._key_pairs(facts.get("group_key"))
                fields = _map(_map(_map(_map(body).get("context")).get("pack")).get("fields"))
                for path, fact in fields.items():
                    pairs += [
                        (path, _seq(row)[0]) for row in _seq(_map(fact).get("top")) if _seq(row)
                    ]
                for path, value in pairs:
                    action = self.policy.fields.get(str(path))
                    if action == "host":
                        hosts.add(str(value))
                    elif action == "user":
                        users.add(str(value))
            except Exception:  # noqa: S112 - such a body fails in _item and is never sent
                continue
        hosts = {h for h in hosts if not self._is_public_address(h)}
        return replace(self.campus, hosts=frozenset(hosts), users=frozenset(users))

    def _is_public_address(self, value: str) -> bool:
        """A public address names no campus host."""
        c = self.classifier.classify(value)
        return c.ip_class is IpClass.PUBLIC and not self.campus.internal(
            ipaddress.ip_address(value)
        )

    @staticmethod
    def _key_pairs(key: Any) -> list[tuple[Any, Any]]:
        try:
            pairs = json.loads(key) if isinstance(key, str) else key
        except ValueError:
            return []
        return [(p[0], p[1]) for p in _seq(pairs) if isinstance(p, (list, tuple)) and len(p) == 2]

    # -- one item -------------------------------------------------------------------------

    def _item(self, body: Any, item_id: str, campus: Campus) -> Item:
        if not isinstance(body, Mapping):
            raise TypeError("a dossier body is a mapping")
        ps = self.space(item_id)
        facts = _map(body.get("facts"))
        report = _map(body.get("report"))
        context = _map(body.get("context"))
        pack = _map(context.get("pack"))
        indices = [str(i) for i in _seq(pack.get("indices"))]
        query = any(fnmatch.fnmatch(i, p) for i in indices for p in query_patterns(self.policy))
        cx = self.scrub(self, campus, ps, _when(facts.get("first_event_at")), query)
        lines: list[str] = []

        lines.append(
            f"Rule: {cx.text(str(facts.get('rule_name') or 'unnamed rule'), 200)}"
            f" · severity {cx.word(facts.get('severity'))}"
            f" · risk {cx.real(facts.get('risk_score'))}"
        )
        first = _when(facts.get("first_event_at"))
        hour = (
            f", the first at {first.astimezone(site.zone()).hour:02d} h {site.zone_label(first)}"
            if first
            else ""
        )
        lines.append(
            f"Alerts: {cx.count(facts.get('alert_count'))} over"
            f" {cx.count(facts.get('span_minutes'))} min{hour};"
            f" duplicates {cx.count(facts.get('duplicate_count'))},"
            f" late arrivals {cx.count(facts.get('late_arrivals'))}"
        )
        if facts.get("group_key") is not None:
            lines.append(f"Grouped by: {self._group_key(facts['group_key'], cx)}")
        entities = _map(facts.get("entities"))
        counts = _map(facts.get("entity_counts"))
        parts = []
        for kind in sorted(entities, key=str):
            values = _seq(entities[kind])[: self.policy.entities]
            shown = ", ".join(cx.entity(str(kind), v) for v in values)
            parts.append(f"{cx.word(kind)} {cx.count(counts.get(kind, len(values)))}: {shown}")
        if parts:
            lines.append("Entities: " + "; ".join(parts))

        steps = [_map(s) for s in _seq(report.get("steps"))]
        if steps:
            lines.append("Steps (the rule's own investigation steps, as ARGUS checked them):")
        for step in steps:
            lines.append(
                f"{cx.exact(step.get('number'))}. [{cx.word(step.get('status'))}]"
                f" {cx.text(str(step.get('text') or ''))}"
            )
            lines.append(f"   found: {cx.text(str(step.get('sentence') or ''))}")
            listed = [cx.text(str(s), 160) for s in _seq(step.get("shown"))[:6]]
            if listed:
                lines.append("   shown: " + "; ".join(listed))
            needs = [cx.word(n) for n in _seq(step.get("needs"))[:6]]
            if needs:
                lines.append("   needs: " + ", ".join(needs))
        if not steps and report:
            lines.append("The rule's note has no investigation steps.")
        for line in _seq(report.get("summary"))[:6]:
            lines.append(f"Summary: {cx.text(str(line))}")

        withheld = 0
        fields = _map(pack.get("fields"))
        if fields:
            sample = "all of them" if pack.get("complete") else "a sample: counts are lower bounds"
            lines.append(
                f"Fields (from {cx.count(pack.get('alerts_read'))} alerts read, {sample};"
                " distinct values; top values with alert counts):"
            )
        for path, fact in fields.items():
            action = self.policy.fields.get(str(path), "drop")
            if action == "drop" or not _NAME.fullmatch(str(path)):
                withheld += 1
                continue
            fact = _map(fact)
            top = []
            for row in _seq(fact.get("top"))[: self.policy.top_values]:
                pair = _seq(row)
                if len(pair) == 2:
                    top.append(f"{cx.field(action, pair[0])} x{cx.count(pair[1])}")
            lines.append(f"- {path} ({cx.count(fact.get('distinct'))}): " + "; ".join(top))

        signals = [_map(s) for s in [*_seq(body.get("local_signals")), *_seq(body.get("signals"))]]
        if signals:
            lines.append("Signals:")
        for signal in signals:
            lines.append("- " + display.sentence(cx.signal(signal)))

        lines.extend(self._ti(_map(pack.get("ti")), cx))
        lines.extend(self._outside(body.get("outside"), cx))
        lines.extend(self._web(_map(pack.get("web")), cx))
        heuristics = _map(pack.get("heuristics"))
        if heuristics:
            shown = ", ".join(
                f"{cx.word(k)}: {cx.any(v, counts=True)}"
                for k, v in sorted(heuristics.items(), key=lambda kv: str(kv[0]))
            )
            lines.append(f"Proxy heuristics: {shown}")
        evidence = [_map(e) for e in _seq(body.get("evidence"))]
        if evidence:
            shown = "; ".join(
                f"{cx.word(e.get('template'))}: {cx.word(e.get('status'))}"
                + (f", {cx.count(e['row_count'])} rows" if e.get("row_count") is not None else "")
                + (" (cut at the row limit)" if e.get("truncated") else "")
                + (f", coverage {cx.any(e['coverage'])}" if e.get("coverage") else "")
                for e in evidence[:20]
            )
            lines.append(f"Evidence read: {shown}")
        lines.append(
            f"Related investigations: {cx.count(context.get('related_total') or 0)};"
            " entities shared with very many others:"
            f" {cx.count(context.get('supernode_entities') or 0)};"
            f" the rule has a note: {'yes' if pack.get('has_note') else 'no'}"
        )
        withheld += cx.withheld
        if withheld:
            lines.append(f"Withheld by the data policy: {withheld} field(s) or value(s)")
        if ps.legend:
            lines.append("Pseudonyms in this item:")
            lines.extend(f"- {token}: {text}" for token, text in ps.legend.items())
        return Item(item_id, lines, ps, withheld, cx.truncated)

    def _group_key(self, key: Any, cx: _Scrub) -> str:
        """``[["source.ip", "10.1.2.3"]]`` as ``source.ip = I1.IP_1``, each value by its
        field's action; a field the policy does not send is withheld."""
        pairs = self._key_pairs(key)
        if not pairs:
            return cx.text(str(key), 200)
        shown = []
        for path, value in pairs:
            named = _NAME.fullmatch(str(path)) is not None
            action = self.policy.fields.get(str(path), "drop") if named else "drop"
            label = cx.word(path) if named else "(a field)"
            shown.append(f"{label} = {cx.field(action, value)}")
        return ", ".join(shown)

    def _ti(self, ti: Mapping[str, Any], cx: _Scrub) -> list[str]:
        answers = [_map(a) for a in _seq(ti.get("answers"))]
        if not answers and not ti.get("listed"):
            return []
        tally: dict[str, int] = {}
        stale = 0
        for answer in answers:
            for outcome in _map(answer.get("sources")).values():
                status, flag = _ti_status(_map(outcome))
                tally[status] = tally.get(status, 0) + 1
                stale += flag
        outcomes = ", ".join(f"{cx.word(k)} {cx.count(v)}" for k, v in sorted(tally.items()))
        lines = [
            f"Threat intel: {cx.count(len(_seq(ti.get('listed'))))} value(s) listed;"
            f" {cx.count(len(answers))} checked; source answers: {outcomes or 'none'};"
            f" stale answers {cx.count(stale)}"
            + ("; the check was cut at its limit" if ti.get("cut") else "")
        ]
        hits = [
            a for a in answers if any(_map(s).get("match") for s in _map(a.get("sources")).values())
        ]
        rest = [a for a in answers if a not in hits]
        for answer in [*hits, *rest][: self.policy.ti_answers]:
            kind = str(answer.get("kind") or "value")
            parts = []
            for source, outcome in sorted(
                _map(answer.get("sources")).items(), key=lambda s: str(s[0])
            ):
                outcome = _map(outcome)
                status, flag = _ti_status(outcome)
                matches = []
                for match in [_map(m) for m in _seq(outcome.get("match"))]:
                    confidence = match.get("confidence")
                    seen = [
                        f"{label} {cx.time(match.get(key))}"
                        for key, label in (("first_seen", "first seen"), ("last_seen", "last seen"))
                        if match.get(key)
                    ]
                    matches.append(
                        f"{cx.word(match.get('type'))}"
                        + (f", confidence {cx.word(confidence)}" if confidence else "")
                        + (f", {', '.join(seen)}" if seen else "")
                        + f": {cx.text(str(match.get('description') or ''), 200)}"
                    )
                shown = f" ({'; '.join(matches)})" if matches else ""
                stale_mark = " (stale)" if flag else ""
                parts.append(f"{cx.word(source)}: {cx.word(status)}{stale_mark}{shown}")
            lines.append(
                f"- {cx.word(kind)} {cx.entity(kind, answer.get('value'))}: " + "; ".join(parts)
            )
        if ti.get("cadence_cv") is not None:
            lines.append(
                f"Regularity of the alerts: variation {cx.real(ti['cadence_cv'])}"
                f" over {cx.count(ti.get('cadence_alerts'))} alerts"
                " (low means regular, like a beacon)"
            )
        return lines

    def _outside(self, value: Any, cx: _Scrub) -> list[str]:
        """What outside threat intel (VirusTotal, Shodan, Censys) said of the item's external
        indicators (AR3, D-165): ARGUS's own sentence from the answer's numbers, with the text a
        source supplied quoted as untrusted, and the indicator (public by construction) after it."""
        found = outside.facts_of(value)[: self.policy.ti_answers]
        if not found:
            return []
        lines = ["Outside threat intel (looked up for this item's external indicators only):"]
        for entry in found:
            said = outside.describe(entry, quote=lambda t: cx.text(t, 80))
            lines.append(f"- {said} ({cx.entity(str(entry['kind']), entry['value'])})")
        return lines

    def _web(self, web: Mapping[str, Any], cx: _Scrub) -> list[str]:
        if not web:
            return []
        lines = [f"Web: {cx.count(web.get('agents') or 0)} user agent(s)"]
        for key, label, kind in (
            ("sites", "sites", "domain"),
            ("categories", "request categories", "text"),
            ("scanner_agents", "scanner user agents", "text"),
            ("decoded_paths", "decoded paths", "url"),
        ):
            values = _seq(web.get(key))[: self.policy.top_values]
            if values:
                shown = "; ".join(
                    cx.entity(kind, v) if kind != "text" else cx.any(v) for v in values
                )
                lines.append(f"- {label}: {shown}")
        naxsi = []
        for rule in [_map(r) for r in _seq(web.get("naxsi"))[: self.policy.top_values]]:
            naxsi.append(
                f"rule {cx.exact(rule.get('id'))} ({cx.text(str(rule.get('class') or ''), 80)}):"
                f" {cx.count(rule.get('alerts'))} alerts"
            )
        if naxsi:
            lines.append("- WAF (naxsi) matches: " + "; ".join(naxsi))
        return lines


def _ti_status(outcome: Mapping[str, Any]) -> tuple[str, bool]:
    """A source's answer (``match``, ``no_match``, ``not_checked``…) and whether it is stale."""
    status = next((str(k) for k in sorted(outcome, key=str) if k != "freshness"), "unknown")
    meta = _map(outcome.get(status) if status != "match" else outcome.get("freshness"))
    return status, bool(meta.get("stale"))


def _when(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _relative(at: datetime, t0: datetime | None) -> str:
    if t0 is None:
        return "[a time]"
    minutes = round((at - t0).total_seconds() / 60)
    sign = "+" if minutes >= 0 else "-"
    minutes = abs(minutes)
    if minutes < 120:
        return f"t0{sign}{minutes}m"
    if minutes < 48 * 60:
        return f"t0{sign}{round(minutes / 60)}h"
    return f"t0{sign}{round(minutes / 1440)}d"


_FORMATS = (  # ISO forms, also compact and date-only, are read by fromisoformat (``_when``)
    "%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S",
    "%b %d, %Y @ %H:%M:%S.%f", "%b %d, %Y @ %H:%M:%S", "%b %d, %Y @ %H:%M",
)  # fmt: skip


def _parse_time(text: str, t0: datetime | None) -> datetime | None:
    """A time in one of ``_TIMES``' formats; a syslog time takes ``t0``'s year; an epoch
    number only within 400 days of ``t0`` (else it is some other number)."""
    for fmt in _FORMATS:
        try:
            parsed = datetime.strptime(text, fmt)  # noqa: DTZ007 - made UTC just below
        except ValueError:
            continue
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    if text[:3] in _MONTHS and t0 is not None:
        try:
            parsed = datetime.strptime(f"{t0.year} {' '.join(text.split())}", "%Y %b %d %H:%M:%S")  # noqa: DTZ007
        except ValueError:
            return None
        return parsed.replace(tzinfo=UTC)
    if text.isdigit():
        if t0 is None:
            return None
        at = datetime.fromtimestamp(int(text) / (1000 if len(text) == 13 else 1), UTC)
        return at if abs(at - t0) < timedelta(days=400) else None
    return _when(text)


class _Scrub:
    """Pseudonymizes values for one item."""

    rescan = True  # look again after replacing (a comparison arm's fakes would be found again)

    def __init__(
        self, privacy: Privacy, campus: Campus, ps: Pseudonyms, t0: datetime | None, query: bool
    ) -> None:
        self.p = privacy
        self.campus = campus
        self.ps = ps
        self.t0 = t0
        self.query = query  # URL query values are sent (the policy's query_values_for)
        self.truncated = False
        self.withheld = 0

    # -- numbers and words ------------------------------------------------------------------

    def count(self, value: Any) -> str:
        """A count: rounded (``bucket``)."""
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return "?" if value is None else self.text(str(value), 40)
        return bucket(value)

    def exact(self, value: Any) -> str:
        """A number that names something (a port, a status code, a rule id): never rounded."""
        if isinstance(value, str) and value.isascii() and value.isdigit() and len(value) <= 6:
            return value
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return "?" if value is None else self.text(str(value), 40)
        if isinstance(value, float):
            return f"{value:.2f}".rstrip("0").rstrip(".") if math.isfinite(value) else "?"
        return str(value)

    def real(self, value: Any) -> str:
        """A measure (a score, a ratio): two decimals; a large one rounded like a count."""
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return "?" if value is None else self.text(str(value), 40)
        if not math.isfinite(value):
            return "?"
        if abs(value) >= 100:
            return bucket(value)
        return f"{value:.2f}".rstrip("0").rstrip(".") if isinstance(value, float) else str(value)

    def word(self, value: Any) -> str:
        """A short label from the data (a status, a kind): bare when it is plainly one, else
        quoted text."""
        if value is None:
            return "?"
        text = str(value)
        if _NAME.fullmatch(text) and not find(text, self.campus):
            return text
        return self.text(text, 80)

    def any(self, value: Any, *, counts: bool = False) -> str:
        if isinstance(value, bool):
            return "yes" if value else "no"
        if isinstance(value, float):
            return self.real(value)
        if isinstance(value, int):
            return self.count(value) if counts else self.exact(value)
        if isinstance(value, Mapping):
            inner = ", ".join(
                f"{self.word(k)}: {self.any(v, counts=counts)}" for k, v in value.items()
            )
            return "{" + inner + "}"
        if isinstance(value, (list, tuple)):
            return "[" + ", ".join(self.any(v, counts=counts) for v in list(value)[:10]) + "]"
        return self.text(str(value))

    def signal(self, signal: Mapping[str, Any]) -> dict[str, Any]:
        """A signal for the registry's sentence (ARGUS's own words), its name, reason and
        value cleaned first."""
        name = str(signal.get("name") or "?")
        plain = _NAME.fullmatch(name) is not None and not find(name, self.campus)
        out: dict[str, Any] = {
            "name": name if plain else self.text(name, 80),
            "status": signal.get("status"),
            "completeness": self.word(signal.get("completeness")),
            "unknown_reason": self.word(signal.get("unknown_reason") or "unknown"),
        }
        value = signal.get("value")
        if value is None:
            out["value"] = "?"
        elif isinstance(value, bool):
            out["value"] = value
        elif isinstance(value, int):
            out["value"] = bucket(value)
        elif isinstance(value, float):
            out["value"] = self.real(value)
        else:
            out["value"] = self.text(str(value), 120)
        return out

    def time(self, value: Any) -> str:
        at = _parse_time(str(value), self.t0) if value is not None else None
        return _relative(at, self.t0) if at else "[a time]"

    # -- typed values -----------------------------------------------------------------------

    def field(self, action: Action, value: Any) -> str:
        if value is None:
            return "(none)"
        match action:
            case "send":
                return self.any(value)
            case "number":
                return self.count(value) if isinstance(value, (int, float)) else self.any(value)
            case "ip":
                return self.ip(value)
            case "domain":
                return self.domain(str(value))
            case "url":
                return self.url(str(value))
            case "host":
                return self.ps.token("HOST", str(value), site.a_own("host name"))
            case "user":
                return self.ps.token("USER", str(value), "a user name")
            case "drop":
                self.withheld += 1
                return "(withheld)"

    def entity(self, kind: str, value: Any) -> str:
        if value is None:
            return "(none)"
        if kind in ("ip", "domain", "url", "host", "user"):
            return self.field(kind, value)  # type: ignore[arg-type]
        return self.text(str(value), 200)

    def ip(self, value: Any) -> str:
        c = self.p.classifier.classify(value)
        if c.address is None:
            return self.text(str(value), 80)
        internal = self.campus.internal(ipaddress.ip_address(c.address))
        if c.ip_class in (IpClass.PUBLIC, IpClass.SPECIAL) and not internal:
            return c.address
        return self.ps.token("IP", c.address, self._ip_legend(c.ip_class, c.asset))

    def _ip_legend(self, ip_class: IpClass, asset: Any) -> str:
        if ip_class is IpClass.ASSET and asset is not None:
            entry = asset.entries[0]
            parts = []
            for name in self.p.policy.asset_fields:
                value = entry.fields.get(name)
                if value and not find(value, self.campus):
                    parts.append(f"{name.split('.')[-1]} {quote(value)}")
            detail = f" ({', '.join(parts)})" if parts else ""
            return f"{site.a_own('device')} in the asset map{detail}"
        if ip_class is IpClass.CAMPUS:
            return f"{site.a_own('public address')} (not in the asset map)"
        return "an internal address (not in the asset map)"

    def domain(self, value: str, *, quoted: bool = True) -> str:
        host = value.strip().lower().rstrip(".")
        if _is_ip(host):
            return self.ip(host)
        if self.campus.campus_domain(host) and not any(c.isspace() for c in host):
            return self.ps.token("SITE", host, site.a_own("site"))
        return self.text(value, 120, quoted=quoted)

    def url(self, value: str) -> str:
        """Scheme and host first (an address or domain), then the path and the query as text
        with identifiers replaced; query values only for the policy's indices, else keys only.
        Taken from the original string (a URL parser drops tabs and newlines and would join
        what they separate). A fragment is never sent."""
        value = value.strip()
        prefix, rest = "", value.split("#", 1)[0]
        parts = _split(value)
        if parts is not None and parts.scheme and parts.hostname:
            scheme, host = parts.scheme.lower(), parts.hostname
            if _SCHEME.fullmatch(scheme) and not find(scheme, self.campus):
                shown = self.ip(host) if _is_ip(host) else self.domain(host, quoted=False)
                cred = "[credentials]@" if parts.username is not None or parts.password else ""
                port = f":{parts.port}" if parts.port else ""
                prefix = f"{scheme}://{cred}{shown}{port}"
                rest = rest.split("://", 1)[1][len(parts.netloc) :]
        if not self.query and "?" in rest:
            path, query = rest.split("?", 1)
            keys = [q.split("=", 1)[0] for q in query.split("&") if q]
            rest = path + "?" + "&".join(f"{k}=…" if k else "…" for k in keys)
        return quote(prefix + self.text(rest, quoted=False))

    # -- free text ----------------------------------------------------------------------------

    def text(self, value: str, limit: int | None = None, *, quoted: bool = True) -> str:
        """``value`` decoded, without control characters or pseudonym look-alikes, with every
        identifier replaced and times made relative, cut to ``limit`` on a token boundary;
        JSON-quoted unless ``quoted`` is false (then the caller quotes it)."""
        limit = limit or self.p.policy.text_chars
        plain = LOOKALIKE.sub(_FORGED, _clean(canonical(value)))
        for pattern in _TIMES:
            plain = pattern.sub(lambda m: self.time(m.group(0)), plain)
        for _ in range(4):
            found = outermost(find(plain, self.campus))
            if not found:
                break
            plain = self._replace(plain, found)
            if not self.rescan:
                break
        else:
            plain = "[withheld: could not be made safe]"
        if len(plain) > limit:
            self.truncated = True
            plain = _cut(plain, limit)
        return quote(plain) if quoted else plain

    def _replace(self, text: str, found: Sequence[Found]) -> str:
        out = []
        last = 0
        for f in found:
            out.append(text[last : f.start])
            if f.encoded and f.start == 0 and f.end == len(text):
                return "[withheld: encoded identifier]"
            if f.kind == "ip" and _is_ip(f.value):
                token = self.ip(f.value)
            elif f.kind == "user_path":
                token = "/~" + self.ps.token("USER", f.value[2:], "a user's home directory")
            elif f.kind == "credentials":
                token = "://" + self.ps.token("CRED", f.value, "credentials in a URL") + "@"
            else:
                label = _label(f, self.campus)
                legend = _LEGENDS.get(label, "part of an internal address")
                token = self.ps.token(label, f.value, legend)
            shown = f"[encoded: {token}]" if f.encoded else token
            # set off from what touches it, so no part of it reads as another pseudonym
            # (``://I1.CRED_1@`` and ``/~I1.USER_1`` bring their own separators)
            glued = f.start > 0 and _GLUE.match(text[f.start - 1]) and shown[0].isalnum()
            before = " " if glued else ""
            glued = f.end < len(text) and _GLUE.match(text[f.end]) and shown[-1].isalnum()
            after = " " if glued else ""
            out.append(before + shown + after)
            last = f.end
        out.append(text[last:])
        return "".join(out)


def _split(value: str) -> SplitResult | None:
    """``value`` as URL parts, or None when it cannot be read as one as written: blanks
    (a parser drops tabs and newlines and would join what they separate), or an invalid
    port or address."""
    if any(c.isspace() for c in value):
        return None
    try:
        parts = urlsplit(value)
        parts.port  # noqa: B018 - raises on an invalid port
    except ValueError:
        return None
    return parts


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _clean(text: str) -> str:
    """Without control, format, line-separator or private-use characters (but ``\\n``, ``\\t``)."""
    return "".join(
        c
        for c in text
        if c in "\n\t" or unicodedata.category(c) not in ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp")
    )


def _cut(text: str, limit: int) -> str:
    """At most ``limit`` characters, never inside a pseudonym; the mark is set off by a blank
    so a cut number never reads as a partial address."""
    if len(text) <= limit:
        return text
    cut = limit - len(_CUT)
    for m in TOKEN.finditer(text):
        if m.start() < cut < m.end():
            cut = m.start()
            break
    blank = text.rfind(" ", 0, cut)
    if blank >= 0 and blank > cut - 40:
        cut = blank
    return text[:cut].rstrip() + _CUT


Privacy.scrub = _Scrub


def privacy_map(settings: Any) -> AssetMap:
    """The asset map for this installation's privacy view (``map_for_privacy``): an empty one
    only while no model and no outside service has a key."""
    from argus.assets.store import map_for_privacy
    from argus.llm.providers import callable_providers, load_config

    outside = settings.outside
    outside_keys = any(
        getattr(outside, name) is not None
        for name in ("virustotal_api_key", "shodan_api_key", "censys_api_key")
    )
    return map_for_privacy(
        settings.assets.map_path,
        model_keys=bool(callable_providers(load_config())),
        outside_keys=outside_keys,
    )
