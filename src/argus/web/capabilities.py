"""What a person may do in ARGUS: eight capabilities, each declared by every route that needs it.

In ELK mode they come from the person's Kibana privileges, re-checked (plus ``answer_gold`` for the
gold-key owners ARGUS names itself); in local mode from the ``users.capabilities`` column. A
capability counts only with its prerequisites (``NEEDS``: everything needs ``view``, answering gold
needs ``review``, approving needs ``manage_cases``): ``effective`` drops unknown names and
capabilities whose prerequisites are missing, so a broken or partial grant fails closed."""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum


class Capability(StrEnum):
    VIEW = "view"
    SEE_LOGS = "see_logs"
    REVIEW = "review"
    ANSWER_GOLD = "answer_gold"
    MANAGE_CASES = "manage_cases"
    REOPEN = "reopen"
    APPROVE = "approve"
    ADMIN = "admin"


# What each one lets a person do, in plain words (the session contract, "Your access").
LABELS: dict[Capability, str] = {
    Capability.VIEW: "use ARGUS: see investigations, alerts and reports",
    Capability.SEE_LOGS: "see raw logs and the facts ARGUS read from them",
    Capability.REVIEW: "review: verdicts, group reviews, accepting proposals, asking the AI",
    Capability.ANSWER_GOLD: "answer gold-set items",
    Capability.MANAGE_CASES: "manage cases: take, assign, contain, request closure, merge, open",
    Capability.REOPEN: "reopen a closed case",
    Capability.APPROVE: "approve closures and other writes, after confirming it is you",
    Capability.ADMIN: "change ARGUS's settings",
}

NEEDS: dict[Capability, frozenset[Capability]] = {
    Capability.VIEW: frozenset(),
    Capability.SEE_LOGS: frozenset({Capability.VIEW}),
    Capability.REVIEW: frozenset({Capability.VIEW}),
    Capability.ANSWER_GOLD: frozenset({Capability.VIEW, Capability.REVIEW}),
    Capability.MANAGE_CASES: frozenset({Capability.VIEW}),
    Capability.REOPEN: frozenset({Capability.VIEW}),
    Capability.APPROVE: frozenset({Capability.VIEW, Capability.MANAGE_CASES}),
    Capability.ADMIN: frozenset({Capability.VIEW}),
}

# What every local account could do before capabilities existed: every page, the raw alerts,
# reviews (one by one, by pattern, by proposal group), accepting a proposal, asking the AI
# investigator, and gold-set answers. The migration gives it to every existing account.
LOCAL_DEFAULT: frozenset[Capability] = frozenset(
    {Capability.VIEW, Capability.SEE_LOGS, Capability.REVIEW, Capability.ANSWER_GOLD}
)
ALL: tuple[Capability, ...] = tuple(Capability)
# What the break-glass account may do: view and review, never anything that is
# written to Kibana, approved or changed in ARGUS's settings.
BREAK_GLASS: frozenset[Capability] = frozenset({Capability.VIEW, Capability.REVIEW})


def parse(names: Iterable[object]) -> frozenset[Capability]:
    """The known capabilities among ``names``; anything else is dropped (never an error: a
    stored value this code does not know grants nothing)."""
    known = {c.value: c for c in Capability}
    return frozenset(known[n] for n in names if isinstance(n, str) and n in known)


def effective(names: Iterable[object]) -> frozenset[Capability]:
    """The capabilities that count: known ones whose prerequisites all count too."""
    have = set(parse(names))
    while True:
        lacking = {c for c in have if not NEEDS[c] <= have}
        if not lacking:
            return frozenset(have)
        have -= lacking


def ordered(caps: Iterable[Capability]) -> list[Capability]:
    """In the declaration order (for stable output)."""
    wanted = set(caps)
    return [c for c in ALL if c in wanted]


def elk_capabilities(snapshot: Iterable[object], grants: Iterable[object]) -> frozenset[Capability]:
    """A person's capabilities in ELK mode: what the last check showed in ELK, plus
    ``answer_gold`` when ARGUS names them a gold-key owner (``users.capabilities``) and they
    can review. Nothing else in ``grants`` counts in ELK mode: ELK decides the rest."""
    have = set(parse(snapshot))
    if Capability.ANSWER_GOLD in parse(grants):
        have.add(Capability.ANSWER_GOLD)
    return effective(have)
