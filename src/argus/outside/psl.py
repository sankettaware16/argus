"""The registered parent of a domain name (AR2c, D-168, D-170): ``a.b.example.co.uk`` is
``example.co.uk`` and ``x.y.workers.dev`` is ``y.workers.dev``.

The rules are the Public Suffix List, ICANN and private sections both (so a hosting service such
as ``workers.dev`` is a suffix and each customer under it is a parent of its own), read from the
snapshot bundled with the package (``data/public_suffix_list.dat``, the version on its first
lines). Nothing is fetched at run time: a new snapshot is a reviewed change to that file.

The algorithm is the list's own (publicsuffix.org/list): the longest matching rule wins, a
wildcard rule (``*.ck``) matches any one label, an exception rule (``!www.ck``) beats the
wildcard and takes one label less, and a name that matches no rule has its last label as the
suffix. Names are the canonical spelling ARGUS keys by (``facts.canonical``: lowercase ASCII,
punycode for other scripts); the rules are put in that spelling when they are loaded.

A suffix from the private section is a hosting service's (``workers.dev``, ``github.io``,
``scf.usercontent.goog``): what sits directly under it is a customer of the service, one of
thousands (:func:`under_private_suffix`).

Pure functions: no I/O but the one read of the bundled file.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache
from pathlib import Path

LIST_PATH = Path(__file__).resolve().parent / "data" / "public_suffix_list.dat"
_BEGIN_PRIVATE = "// ===BEGIN PRIVATE DOMAINS==="
_END_PRIVATE = "// ===END PRIVATE DOMAINS==="


@dataclass(frozen=True)
class Rules:
    plain: frozenset[str]  # "co.uk", "workers.dev"
    wildcard: frozenset[str]  # "ck" for "*.ck": any one label under it is a suffix
    exception: frozenset[str]  # "www.ck" for "!www.ck": a name, not a suffix
    private: frozenset[str] = frozenset()  # the plain and wildcard rules of the private section


def _ascii(rule: str) -> str | None:
    """A rule in the canonical spelling, or None when its labels cannot be encoded."""
    if rule.isascii():
        return rule.lower()
    try:
        return ".".join(
            label if label.isascii() else label.encode("idna").decode("ascii")
            for label in rule.lower().split(".")
        )
    except UnicodeError:
        return None


def parse(text: str) -> Rules:
    """The rules in the text of a list: one per line, the first word of a line that is not a
    comment (``//``) or blank."""
    plain: set[str] = set()
    wildcard: set[str] = set()
    exception: set[str] = set()
    private: set[str] = set()
    in_private = False
    for line in text.splitlines():
        words = line.split()
        if line.startswith(_BEGIN_PRIVATE):
            in_private = True
        elif line.startswith(_END_PRIVATE):
            in_private = False
        if not words or words[0].startswith("//"):
            continue
        rule = words[0]
        kind = plain
        if rule.startswith("!"):
            kind, rule = exception, rule[1:]
        elif rule.startswith("*."):
            kind, rule = wildcard, rule[2:]
        encoded = _ascii(rule)
        if encoded:
            kind.add(encoded)
            if in_private and kind is not exception:
                private.add(encoded)
    return Rules(frozenset(plain), frozenset(wildcard), frozenset(exception), frozenset(private))


@cache
def bundled() -> Rules:
    """The rules of the snapshot that ships with the package (read once)."""
    return parse(LIST_PATH.read_text(encoding="utf-8"))


def suffix_labels(labels: list[str], rules: Rules) -> int:
    """How many of the last labels are the name's public suffix (at least 1)."""
    return _suffix(labels, rules)[0]


def _suffix(labels: list[str], rules: Rules) -> tuple[int, bool]:
    """The suffix's label count and whether the rule that made it is from the private section."""
    best, private = 1, False  # the prevailing rule "*": an unlisted last label is a suffix
    for n in range(1, len(labels) + 1):
        tail = ".".join(labels[-n:])
        if tail in rules.exception:
            return n - 1, False  # the exception's own name is registrable: one label less
        wild = ".".join(labels[-n + 1 :]) if n >= 2 else ""
        matched = tail in rules.plain or (n >= 2 and wild in rules.wildcard)
        if matched and n >= best:
            best, private = n, tail in rules.private or wild in rules.private
    return best, private


def registered_parent(name: str, rules: Rules | None = None) -> str | None:
    """The suffix and one more label of ``name`` (lowercase ASCII, no trailing dot), or None when
    the name is itself a public suffix, has a single label, or is not a plain host name."""
    labels = name.split(".")
    if len(labels) < 2 or not all(labels):
        return None
    n = suffix_labels(labels, bundled() if rules is None else rules)
    if len(labels) <= n:
        return None
    return ".".join(labels[-(n + 1) :])


def under_private_suffix(name: str, rules: Rules | None = None) -> bool:
    """Whether the public suffix of ``name`` is a hosting service's, from the private section of
    the list: ``name`` is then a customer of the service (or a name inside one's space)."""
    labels = name.split(".")
    if not name or not all(labels):
        return False
    return _suffix(labels, bundled() if rules is None else rules)[1]


def public_suffix(name: str, rules: Rules | None = None) -> str | None:
    """The public suffix of ``name`` (``co.uk``), or None when it has no labels."""
    labels = name.split(".")
    if not name or not all(labels):
        return None
    n = suffix_labels(labels, bundled() if rules is None else rules)
    return ".".join(labels[-n:])


__all__ = [
    "Rules",
    "bundled",
    "parse",
    "public_suffix",
    "registered_parent",
    "suffix_labels",
    "under_private_suffix",
]
