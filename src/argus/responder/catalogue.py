"""``config/actions.yaml``: the actions ARGUS may advise (Q-H2, plan §7.7), strictly loaded.

A **family** is a kind of true-positive incident the packs can tell apart (``when``: facts from
:data:`argus.responder.facts.FACTS`); each has **actions** with an owner role, plain words for
RAs and TAs, and how a person's "done" can be checked, or why it cannot be in Phase 3.

* Unknown keys, a duplicate key, an unknown owner or fact, a rank used twice, a fact no family
  uses (a signal the packs establish must have its advice), an id or version the table cannot
  hold, text outside a short allow-list (letters, digits, spaces and basic punctuation: no link,
  markup, flag or command) and any verifier that is not a read are refused, with the reason.
* A verifier names a registered *read* template (:data:`VERIFIERS`: a search of the proxy or web
  logs, which the gateway sends as ``POST _search`` and nothing else), ARGUS's own stored
  alerts (``local: alerts``), or says ``not_verifiable`` with the reason. A catalogue entry
  holds no URL, method, body or command: it cannot name a write, and nothing here sends a
  request. The watch (Q-C2) and the evidence ledger already hold the answers; verification
  reads them from the database (:mod:`argus.responder.machine`).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from argus.config.errors import ConfigError
from argus.config.sources import read_yaml_file
from argus.gateway.templates import REGISTRY, Endpoint
from argus.gateway.templates import Family as LogFamily

PATH = Path(__file__).resolve().parents[3] / "config" / "actions.yaml"
NAME = re.compile(r"[a-z][a-z0-9_]{0,59}")
# The endpoints that read documents (the gateway's wire_path sends them as POST .../_search and
# .../_mget); a verifier template must use one of these, and only log families.
READ_ENDPOINTS = frozenset({Endpoint.SEARCH, Endpoint.MGET})
# The templates whose stored answers verification reads, and the watch source or evidence it
# reads them from (argus.responder.machine).
VERIFIERS: Mapping[str, str] = MappingProxyType(
    {
        "proxy.contact": "the proxy logs, through the still-active watch's stored answers",
        "web.path_outcomes": "the web server's answers, from a check made after the action",
    }
)
LOCAL_VERIFIERS: Mapping[str, str] = MappingProxyType(
    {"alerts": "ARGUS's own stored alerts, through the still-active watch"}
)
TITLE_MAX, SAY_MAX, REASON_MAX = 60, 300, 200
ACTION_ID_MAX = 80  # case_actions.action (CHECK, migration 0044)
VERSION_MAX = 2**31 - 1  # case_actions.catalogue_version is a 32-bit integer
# What wording may hold: letters, digits, spaces and . , ' ( ) - ? ! (a colon only as punctuation,
# before a space); nothing else, so no link, markup, quote, backtick or shell character.
PLAIN = re.compile(r"(?:[A-Za-z0-9 .,'()?!-]|:(?= |$))*")
# Things plain words never hold even though every character passes: a domain or file name
# (a dot between letters or digits), a command flag (" -x") and a few command names.
NOT_WORDS = re.compile(
    r"[A-Za-z0-9]\.[A-Za-z0-9]|(?:^|\s)-[A-Za-z0-9]"
    r"|\b(?:sudo|rm|curl|wget|chmod|chown|powershell|bash|iptables|netsh)\b",
    re.IGNORECASE,
)


class CatalogueError(ConfigError):
    """The catalogue is not valid: nothing is advised from a catalogue that cannot be read."""


def _plain(value: str, limit: int, what: str) -> str:
    text = value.strip()
    if not text or len(text) > limit:
        raise ValueError(f"{what} is 1 to {limit} characters")
    if not PLAIN.fullmatch(text) or NOT_WORDS.search(text):
        raise ValueError(f"{what} is plain words: letters, digits and basic punctuation only")
    return text


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class Owner(_Strict):
    name: str
    does: str

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        return _plain(value, 60, "an owner's name")

    @field_validator("does")
    @classmethod
    def _does(cls, value: str) -> str:
        return _plain(value, SAY_MAX, "what an owner does")


class Verify(_Strict):
    """How a person's "done" is checked: exactly one of the three."""

    template: str | None = None
    local: str | None = None
    not_verifiable: str | None = None

    @model_validator(mode="after")
    def _one(self) -> Verify:
        given = [k for k in ("template", "local", "not_verifiable") if getattr(self, k) is not None]
        if len(given) != 1:
            raise ValueError("verify holds exactly one of template, local, not_verifiable")
        if self.template is not None and self.template not in VERIFIERS:
            raise ValueError(f"verify.template {self.template!r} is not a verifier template")
        if self.local is not None and self.local not in LOCAL_VERIFIERS:
            raise ValueError(f"verify.local {self.local!r} is not a local verifier")
        if self.not_verifiable is not None:
            _plain(self.not_verifiable, REASON_MAX, "the reason it cannot be verified")
        return self

    @property
    def kind(self) -> str:
        """``proxy.contact``, ``web.path_outcomes``, ``alerts`` or ``none``."""
        if self.template is not None:
            return self.template
        return "alerts" if self.local is not None else "none"


class ActionSpec(_Strict):
    rank: int = Field(ge=1, le=50)
    owner: str
    title: str
    say: str
    verify: Verify

    @field_validator("title")
    @classmethod
    def _title(cls, value: str) -> str:
        return _plain(value, TITLE_MAX, "a title")

    @field_validator("say")
    @classmethod
    def _say(cls, value: str) -> str:
        return _plain(value, SAY_MAX, "the wording")


class FamilySpec(_Strict):
    title: str
    scope: Literal["case", "rule"] = "case"
    when: list[str] = Field(default_factory=list)
    actions: dict[str, ActionSpec]

    @field_validator("title")
    @classmethod
    def _title(cls, value: str) -> str:
        return _plain(value, 100, "a family's title")


class _File(_Strict):
    version: int = Field(ge=1, le=VERSION_MAX)
    owners: dict[str, Owner]
    families: dict[str, FamilySpec]


@dataclass(frozen=True)
class Action:
    id: str  # "<family>.<key>", the id case_actions holds
    family: str
    rank: int
    owner: str
    title: str
    say: str
    verify: Verify


@dataclass(frozen=True)
class Family:
    key: str
    title: str
    scope: str
    when: tuple[str, ...]
    actions: tuple[Action, ...]  # by rank


@dataclass(frozen=True)
class Catalogue:
    version: int
    owners: Mapping[str, Owner]
    families: tuple[Family, ...]  # in the file's order: the order advice is given in

    def action(self, action_id: str) -> Action | None:
        return next(
            (a for f in self.families for a in f.actions if a.id == action_id),
            None,
        )

    def family(self, key: str) -> Family:
        return next(f for f in self.families if f.key == key)

    @property
    def actions(self) -> tuple[Action, ...]:
        return tuple(a for f in self.families for a in f.actions)


def _problem(exc: ValidationError) -> str:
    out = []
    for error in exc.errors()[:3]:
        where = ".".join(str(p) for p in error["loc"])
        message = "unknown key" if error["type"] == "extra_forbidden" else error["msg"]
        out.append(f"{where}: {message}")
    return "; ".join(out)


def _check_verifier(action_id: str, verify: Verify) -> None:
    if verify.template is None:
        return
    template = REGISTRY.get(verify.template)
    if template is None:
        raise CatalogueError(f"{action_id}: the template {verify.template} is not registered")
    if template.endpoint not in READ_ENDPOINTS or template.family is not LogFamily.LOG:
        raise CatalogueError(f"{action_id}: {verify.template} is not a read of the logs")


def parse(data: Mapping[str, Any], facts: frozenset[str]) -> Catalogue:
    """The catalogue from a parsed file; ``facts`` is the vocabulary a family may use."""
    from argus.context import beacon, paths  # noqa: F401  (registers the verifier templates)

    try:
        file = _File.model_validate(data)
    except ValidationError as exc:
        raise CatalogueError(_problem(exc)) from None
    for key in (*file.owners, *file.families):
        if not NAME.fullmatch(key):
            raise CatalogueError(f"{key!r}: a name is lowercase letters, digits and _")
    used: set[str] = set()
    families = []
    for fkey, family in file.families.items():
        if not family.actions:
            raise CatalogueError(f"{fkey}: a family has at least one action")
        if (family.scope == "case") != bool(family.when):
            raise CatalogueError(f"{fkey}: a case family says when it applies, a rule family not")
        unknown = sorted(set(family.when) - facts)
        if unknown:
            raise CatalogueError(f"{fkey}: no fact {', '.join(unknown)}")
        used |= set(family.when)
        ranks = [a.rank for a in family.actions.values()]
        if len(set(ranks)) != len(ranks):
            raise CatalogueError(f"{fkey}: two actions share a rank")
        actions = []
        for akey, spec in family.actions.items():
            if not NAME.fullmatch(akey):
                raise CatalogueError(f"{fkey}.{akey}: a name is lowercase letters, digits and _")
            action_id = f"{fkey}.{akey}"
            if len(action_id) > ACTION_ID_MAX:
                raise CatalogueError(
                    f"{action_id}: an action id is at most {ACTION_ID_MAX} characters"
                )
            if spec.owner not in file.owners:
                raise CatalogueError(f"{action_id}: no owner {spec.owner!r}")
            _check_verifier(action_id, spec.verify)
            actions.append(Action(action_id, fkey, spec.rank, spec.owner, spec.title, spec.say,
                                  spec.verify))  # fmt: skip
        actions.sort(key=lambda a: a.rank)
        when = tuple(family.when)
        families.append(Family(fkey, family.title, family.scope, when, tuple(actions)))
    missing = sorted(facts - used)
    if missing:
        raise CatalogueError(f"no family uses the fact {', '.join(missing)}: it has no advice")
    return Catalogue(file.version, MappingProxyType(dict(file.owners)), tuple(families))


def load(path: Path | None = None) -> Catalogue:
    """``config/actions.yaml`` (of the repo, not of the working directory). A missing or invalid
    file is an error: without it nothing is advised."""
    from argus.responder.facts import FACTS

    path = PATH if path is None else path
    if not path.exists():
        raise CatalogueError(f"{path} is missing: it lists the actions ARGUS may advise")
    data, _ = read_yaml_file(path)
    return parse(data, frozenset(FACTS))
