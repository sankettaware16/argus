"""Domain families: the names devices reach, grouped under the registered parent they share. A
campaign shows in no single investigation, but grouped by parent the data is plain: a **family**
is a parent with, over the history window, its distinct names, the internal hosts that reached
them, the investigations that hold them and how many names look random. A family is a candidate
for an outside look-up when large (:data:`MIN_HOSTS` hosts or :data:`MIN_NAMES` names; a hosted
customer by names only). What may be sent outside is not decided here. Pure: no I/O."""

from __future__ import annotations

import re
import uuid
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from math import log2

from argus.outside.psl import Rules, registered_parent, under_private_suffix

MIN_HOSTS = 3  # internal hosts that make a family a candidate
MIN_NAMES = 20  # distinct names that make a family a candidate
MIN_RANDOM_LABEL = 8  # a shorter label is never called random
MIN_RELATIVE_ENTROPY = 0.6  # of the most a label of that length could have (log2 of its length)
MAX_VOWEL_SHARE = 0.2  # a long run of consonants: not a word in any language the site uses
_PLAIN_LABEL = re.compile(r"[a-z0-9]+")  # a hyphen or an underscore is a word break: not random

Key = tuple[str, str]  # (kind, value): ("ip", "10.1.2.3") or ("host", "pc-12")


def entropy(text: str) -> float:
    """Shannon entropy of the characters of ``text``, in bits a character (0 for no text)."""
    if not text:
        return 0.0
    counts = Counter(text)
    size = len(text)
    return -sum(n / size * log2(n / size) for n in counts.values())


def random_looking(label: str) -> bool:
    """Whether a label looks machine-made: at least :data:`MIN_RANDOM_LABEL` letters and digits
    with enough variety (:data:`MIN_RELATIVE_ENTROPY` of the most a label that long could have)
    that either mixes digits among the letters or has almost no vowels. A hint to show, never a
    verdict: real-time media services use random labels too, which is why rarity and the
    outside answer decide, not this."""
    text = label.lower()
    if len(text) < MIN_RANDOM_LABEL or not _PLAIN_LABEL.fullmatch(text):
        return False
    if entropy(text) < MIN_RELATIVE_ENTROPY * log2(len(text)):
        return False
    letters = sum(c.isalpha() for c in text)
    digits = len(text) - letters
    vowels = sum(c in "aeiou" for c in text)
    mixed = letters >= 2 and digits >= 2
    consonants = letters >= 6 and vowels <= MAX_VOWEL_SHARE * letters
    return mixed or consonants


@dataclass(frozen=True)
class Sighting:
    """What one investigation holds: its internal devices (none when no internal device acted) and
    the domain names it involves, in the canonical spelling."""

    investigation_id: uuid.UUID
    hosts: frozenset[Key]
    names: frozenset[str]
    rule: str = ""  # the rule that raised the investigation (its name, else its id)


@dataclass(frozen=True)
class Family:
    parent: str
    names: frozenset[str]  # distinct names under the parent (the parent itself too)
    hosts: frozenset[Key]
    investigations: frozenset[uuid.UUID]
    random: int  # names below the parent with a label that looks random
    below: int  # names below the parent (the share's denominator)
    hosted: bool = False  # a customer of a hosting service (see the module's docstring)
    rules: frozenset[str] = frozenset()  # the rules that raised the investigations

    @property
    def random_share(self) -> float:
        """The share of the names below the parent that look random (0 when none are below)."""
        return self.random / self.below if self.below else 0.0

    @property
    def candidate(self) -> bool:
        wide = len(self.hosts) >= MIN_HOSTS and not self.hosted
        return wide or len(self.names) >= MIN_NAMES


def labels_below(name: str, parent: str) -> list[str]:
    """The labels of ``name`` below ``parent``, left to right (none for the parent itself). A
    campaign's random label sits right below its domain (``www.google.com.<random>.bad.example``)
    or at the far left (``<random>.probe.bad.example``)."""
    if name == parent or not name.endswith("." + parent):
        return []
    return name[: -len(parent) - 1].split(".")


def families_of(sightings: Iterable[Sighting], psl_rules: Rules | None = None) -> dict[str, Family]:
    """Every family the sightings show, by parent. A name with no registered parent (a bare
    suffix) belongs to none."""
    names: dict[str, set[str]] = defaultdict(set)
    hosts: dict[str, set[Key]] = defaultdict(set)
    found: dict[str, set[uuid.UUID]] = defaultdict(set)
    rules: dict[str, set[str]] = defaultdict(set)
    parents: dict[str, str | None] = {}
    for s in sightings:
        for name in s.names:
            if name not in parents:
                parents[name] = registered_parent(name, psl_rules)
            parent = parents[name]
            if parent is None:
                continue
            names[parent].add(name)
            found[parent].add(s.investigation_id)
            hosts[parent].update(s.hosts)
            if s.rule:
                rules[parent].add(s.rule)
    out: dict[str, Family] = {}
    for parent, held in names.items():
        below = [labels for n in held if (labels := labels_below(n, parent))]
        out[parent] = Family(
            parent, frozenset(held), frozenset(hosts[parent]), frozenset(found[parent]),
            sum(any(random_looking(label) for label in labels) for labels in below), len(below),
            under_private_suffix(parent, psl_rules), frozenset(rules[parent]),
        )  # fmt: skip
    return out


def candidates(found: Mapping[str, Family]) -> list[Family]:
    """The large families, the widest first (most hosts, then most names, then by name): the order
    a daily allowance is spent in."""
    large = [f for f in found.values() if f.candidate]
    return sorted(large, key=lambda f: (-len(f.hosts), -len(f.names), f.parent))
