"""What the privacy layer costs: the same dossiers rendered for every arm of a comparison; only the
rendering differs. ``B`` is the policy (pseudonyms) as sent in production; ``A-fake`` replaces
identifiers with realistic fakes of the same kind; ``A-real`` keeps real values (run only on a
small sample, after a second confirmation); ``C-…`` is B with one kind of value faked, or exact
counts or times. Secrets and keys stay removed in every arm; only ``B`` is meant for the egress
validator."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import uuid
from dataclasses import dataclass, field
from functools import partial
from typing import Any

from argus.llm import egress
from argus.llm.detect import TOKEN
from argus.llm.privacy import Privacy, Pseudonyms, Request, _parse_time, _Scrub

FAKE_DOMAIN = "campus.example"
CREDENTIAL = "[credential removed]"
KINDS = {"ips": ("IP",), "hosts": ("HOST",), "users": ("USER", "EMAIL"), "sites": ("SITE",),
         "ids": ("MAC", "HASH", "ID")}  # fmt: skip
# Service words every organisation uses: they keep a fake site's meaning and name nothing.
GENERIC_LABELS = frozenset(
    [
        "www",
        "mail",
        "webmail",
        "smtp",
        "imap",
        "pop",
        "mx",
        "vpn",
        "moodle",
        "lms",
        "portal",
        "api",
        "app",
        "apps",
        "admin",
        "login",
        "sso",
        "auth",
        "cloud",
        "git",
        "gitlab",
        "wiki",
        "ftp",
        "dns",
        "ns",
        "ns1",
        "ns2",
        "cdn",
        "static",
        "blog",
        "news",
        "library",
        "lib",
        "exam",
        "exams",
        "erp",
        "student",
        "students",
        "staff",
        "hostel",
        "hr",
        "intranet",
        "dev",
        "test",
        "staging",
    ]
)
ALL_FAKE = frozenset(label for labels in KINDS.values() for label in labels)
ARMS = ("B", "A-fake", "A-real", *(f"C-{k}" for k in KINDS), "C-counts", "C-times")
REAL_DATA = frozenset({"A-real"})  # arms that send real values


class Fakes(Pseudonyms):
    """Realistic fakes for ``labels`` (one per value, the same within an item); any other
    label gets its pseudonym as in production. Credentials are always removed."""

    def __init__(self, item: str, labels: frozenset[str], domains: tuple[str, ...]) -> None:
        super().__init__(item)
        self.labels = labels
        self.domains = domains
        self._fakes: dict[tuple[str, str], str] = {}
        self._labels: dict[str, str] = {}

    def token(self, label: str, value: str, legend: str | None = None) -> str:
        if label == "CRED":
            return CREDENTIAL
        if label not in self.labels:
            return super().token(label, value, legend)
        key = (label, value.lower())
        if key not in self._fakes:
            n = sum(1 for k in self._fakes if k[0] == label) + 1
            self._fakes[key] = self._fake(label, value, n, legend or "")
        fake = self._fakes[key]
        if legend and fake not in self.legend:
            self.legend[fake] = legend
        return fake

    def _label(self, label: str) -> str:
        """A subdomain label: a generic service word stays (it says what the site is and
        names the organisation), any other becomes a neutral fake, the same within an item."""
        if label in GENERIC_LABELS:
            return label
        if label not in self._labels:
            self._labels[label] = f"part{len(self._labels) + 1}"
        return self._labels[label]

    def _fake(self, label: str, value: str, n: int, legend: str) -> str:
        match label:
            case "IP":
                try:
                    v6 = ipaddress.ip_address(value).version == 6
                except ValueError:
                    v6 = False
                if v6:
                    return f"fd00:fa:ce::{n:x}"
                if "campus public" in legend:
                    return f"203.0.113.{n % 254 + 1}"  # a documentation range
                return f"10.{200 + n // 65536 % 50}.{n // 256 % 256}.{n % 256}"
            case "SITE":
                host = value.lower().rstrip(".")
                for domain in self.domains:
                    if host == domain:
                        return FAKE_DOMAIN
                    if host.endswith("." + domain):
                        labels = host[: -len(domain) - 1].split(".")
                        return ".".join([*map(self._label, labels), FAKE_DOMAIN])
                return f"site{n}.{FAKE_DOMAIN}"
            case "HOST":
                return f"host-{n}"
            case "USER":
                return f"user{n}"
            case "EMAIL":
                return f"user{n}@{FAKE_DOMAIN}"
            case "MAC":
                return f"02:00:5e:00:{n // 256 % 256:02x}:{n % 256:02x}"  # locally administered
            case "HASH":
                return hashlib.sha512(f"fake {n}".encode()).hexdigest()[: len(value)]
            case _:
                return str(uuid.UUID(int=n))


class Real(Pseudonyms):
    """The value itself (``A-real``); credentials are still removed."""

    def token(self, label: str, value: str, legend: str | None = None) -> str:
        if label == "CRED":
            return CREDENTIAL
        if legend and value not in self.legend:
            self.legend[value] = legend
        return value


class _Plain(_Scrub):
    rescan = False  # fakes and real values would be found again


class _ExactCounts(_Scrub):
    def count(self, value: Any) -> str:
        return self.exact(value)


class _AbsoluteTimes(_Scrub):
    def time(self, value: Any) -> str:
        at = _parse_time(str(value), self.t0) if value is not None else None
        return at.isoformat(timespec="minutes") if at else "[a time]"


def arm(privacy: Privacy, name: str) -> Privacy:
    if name not in ARMS:
        raise ValueError(f"unknown arm {name!r}; arms: {', '.join(ARMS)}")
    variant = Privacy(privacy.policy, privacy.classifier, privacy.campus)
    domains = privacy.campus.domains
    if name == "A-fake":
        variant.space = partial(Fakes, labels=ALL_FAKE, domains=domains)
        variant.scrub = _Plain
    elif name == "A-real":
        variant.space = Real
        variant.scrub = _Plain
    elif name == "C-counts":
        variant.scrub = _ExactCounts
    elif name == "C-times":
        variant.scrub = _AbsoluteTimes
    elif name.startswith("C-"):
        labels = frozenset(KINDS[name[2:]])
        variant.space = partial(Fakes, labels=labels, domains=domains)
        variant.scrub = _Plain
    return variant


FAKE_ARMS = frozenset({"A-fake", *(f"C-{k}" for k in KINDS)})


def _escaped(text: str) -> str:
    return json.dumps(text, ensure_ascii=False)[1:-1]


@dataclass
class FakeRequest(Request):
    """A fake arm's request. The validator cannot pass realistic fakes (a fake private address
    is private), so it is sendable only as a proof: its text must be exactly its policy twin's
    (``base``, arm B on the same bodies) with our fakes put in place of the twin's pseudonyms,
    and the twin must pass the validator. A value the twin removed and this arm kept breaks the
    equality, and the request is refused."""

    base: Request | None = field(default=None, repr=False)

    def proven(self) -> bool:
        if self.base is None:
            return False
        swap: dict[str, str] = {}
        for item, space in self.base._maps.items():
            fakes = getattr(self._maps.get(item), "_fakes", {})
            for key, token in space._token.items():
                if key[0] == "CRED":
                    swap[token] = CREDENTIAL
                elif key in fakes:
                    swap[token] = fakes[key]
        expected = TOKEN.sub(lambda m: swap.get(m.group(0), m.group(0)), self.base.text)
        return expected == self.text

    def validate(self) -> egress.Verdict:
        if self.base is None:
            return egress.Verdict(False, error="no policy twin")
        verdict = self.base.validate()
        if verdict.allowed and not self.proven():
            return egress.Verdict(False, error="not the policy text with fakes")
        return verdict

    def check(self, body: bytes) -> egress.Verdict:
        """The twin's check on these bytes with the twin's text in place of this text (which
        must occur exactly once): the rest of the body is checked as it is."""
        try:
            raw = body.decode("utf-8")
        except UnicodeDecodeError:
            return egress.Verdict(False, error="not UTF-8")
        mine = _escaped(self.text)
        if self.base is None or raw.count(mine) != 1 or not self.proven():
            return egress.Verdict(False, error="not the policy body with fakes")
        return self.base.check(raw.replace(mine, _escaped(self.base.text)).encode("utf-8"))


def _faked(base: Request, labels: frozenset[str], domains: tuple[str, ...]) -> FakeRequest:
    """``base`` with a fake in place of each pseudonym of ``labels``: the same text, cut
    at the same places, so only the identifiers differ between the arms."""
    maps: dict[str, Pseudonyms] = {}
    swap: dict[str, str] = {}
    for item, space in base._maps.items():
        fakes = Fakes(item, labels, domains)
        for (label, value), token in space._token.items():  # in the order B numbered them
            if label == "CRED" or label in labels:
                swap[token] = fakes.token(label, value, space.legend.get(token))
        maps[item] = fakes
    text = TOKEN.sub(lambda m: swap.get(m.group(0), m.group(0)), base.text)
    return FakeRequest(
        text, base.items, base.omitted, base.failed, base.truncated, base.campus, maps, base
    )


def render(privacy: Privacy, name: str, bodies: list[Any], max_chars: int = 60_000) -> Request:
    if name not in ARMS:
        raise ValueError(f"unknown arm {name!r}; arms: {', '.join(ARMS)}")
    if name in FAKE_ARMS:
        labels = ALL_FAKE if name == "A-fake" else frozenset(KINDS[name[2:]])
        return _faked(privacy.request(bodies, max_chars), labels, privacy.campus.domains)
    return arm(privacy, name).request(bodies, max_chars)
