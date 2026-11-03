"""Keyed, deterministic pseudonyms for names, domains and identifiers (R2, D-030).

Every function is a pure function of (key, kind, value): the same original always becomes the same
pseudonym, so references between alerts, source events, TI documents and cassettes stay intact.
"""

from __future__ import annotations

import base64
import contextlib
import functools
import hashlib
import hmac
import math
import re
import string
import unicodedata
from collections.abc import Callable, Iterable

# Public suffixes with more than one label that occur in campus and Internet traffic. Anything else
# keeps only its last label as the suffix. (A full Public Suffix List is not needed for fixtures:
# the suffix is kept purely so pseudonymous domains stay recognisably domain-shaped.)
MULTI_LABEL_SUFFIXES = frozenset(
    {
        "ac.in",
        "co.in",
        "gov.in",
        "nic.in",
        "org.in",
        "net.in",
        "edu.in",
        "res.in",
        "ernet.in",
        "firm.in",
        "gen.in",
        "ind.in",
        "mil.in",
        "co.uk",
        "ac.uk",
        "gov.uk",
        "org.uk",
        "ltd.uk",
        "plc.uk",
        "me.uk",
        "net.uk",
        "com.au",
        "net.au",
        "org.au",
        "edu.au",
        "gov.au",
        "co.jp",
        "ne.jp",
        "or.jp",
        "ac.jp",
        "go.jp",
        "com.br",
        "com.cn",
        "net.cn",
        "org.cn",
        "edu.cn",
        "gov.cn",
        "com.sg",
        "com.my",
        "co.za",
        "com.tr",
        "com.hk",
        "co.kr",
        "co.nz",
        "com.mx",
        "com.ar",
        "com.ru",
        "com.ua",
        "com.pk",
        "com.bd",
        "com.np",
        "com.lk",
        "co.id",
        "com.vn",
        "com.ph",
        "com.tw",
        "com.sa",
        "co.il",
        "com.eg",
        "com.ng",
        "co.ke",
    }
)

_DECIMAL = re.compile(r"[0-9]+")
_HEX = re.compile(r"[0-9a-f]+")
_HEX_UPPER = re.compile(r"[0-9A-F]+")
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_B64URL = re.compile(r"[A-Za-z0-9_-]+")
_B64URL_DIGITS = string.ascii_uppercase + string.ascii_lowercase + string.digits + "-_"
# (pattern, alphabet) in order: the first pattern an id matches decides its alphabet.
_ID_ALPHABETS = (
    (_DECIMAL, string.digits),
    (_HEX, string.digits + "abcdef"),
    (_HEX_UPPER, string.digits + "ABCDEF"),
    (_B64URL, _B64URL_DIGITS),
)
_FPE_MAX_BITS = 128  # ids up to this many bits get a keyed permutation (no collisions at all)
_FEISTEL_ROUNDS = 8
_MAX_ID_STEPS = 10_000  # a cycle walk takes a handful of steps; this many means a bug


class TokenCollisionError(ValueError):
    """Two different originals got one pseudonym (a truncated-hash collision)."""


class Tokenizer:
    def __init__(self, key: bytes) -> None:
        if len(key) < 32:
            raise ValueError("the fixture key must be at least 32 bytes")
        # Length-prefixed, so K and K + b"\0" (one key to HMAC) are different keys here.
        self._key = hashlib.sha256(
            b"argus-fixtures/tokens|" + len(key).to_bytes(4, "big") + key
        ).digest()
        self._issued: dict[tuple[str, str], str] = {}

    def digest(self, kind: str, value: str) -> bytes:
        message = kind.encode() + b"\x00" + value.encode("utf-8", "surrogatepass")
        return hmac.new(self._key, message, hashlib.sha256).digest()

    def token(self, kind: str, value: str, prefix: str, length: int = 8) -> str:
        """``prefix`` + ``length`` lowercase base32 characters, e.g. ``u-k3x7q2ab``.

        Raises TokenCollisionError if another value of the same kind already got this token, so a
        collision can never silently merge two identities."""
        b32 = base64.b32encode(self.digest(kind, value)).decode().rstrip("=").lower()
        out = prefix + b32[:length]
        first = self._issued.setdefault((kind, out), value)
        if first != value:
            raise TokenCollisionError(
                f"two different {kind} values share the pseudonym {out}; use a longer token"
            )
        return out

    def opaque_id(self, value: str) -> str:
        """A pseudonymous identifier with the same shape (length and alphabet) as ``value``.

        Ids of up to 128 bits (every Elasticsearch ``_id``, short decimal and hex ids) go through
        a keyed permutation of their alphabet, so two ids never share a pseudonym; UUIDs keep
        their layout and are case-insensitive, as UUIDs are."""
        if not value:
            return value
        if value.startswith("{") and value.endswith("}") and _UUID.fullmatch(value[1:-1]):
            return "{" + self.opaque_id(value[1:-1]) + "}"
        if _UUID.fullmatch(value):
            h = self.digest("id", value.lower()).hex()
            out = f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
            return out.upper() if value.isupper() else out
        for pattern, alphabet in _ID_ALPHABETS:
            if pattern.fullmatch(value) and len(value) <= 128:
                if len(value) * math.log2(len(alphabet)) <= _FPE_MAX_BITS:
                    return self._permute_id(value, alphabet)
                digest = self.digest("id", value)
                return _stretch(digest, functools.partial(_encode, alphabet=alphabet), len(value))
        # 23 characters: longer than any id the permutation handles (21), so a permuted id can
        # never equal a fallback one.
        return "id-" + self.token("id", value, "", 20)

    def _permute_id(self, value: str, alphabet: str) -> str:
        """Format-preserving, one-to-one, never the input itself.

        ``D = F⁻¹ ∘ (+1 mod N) ∘ F`` (``F`` a keyed Feistel permutation of all N strings of this
        length and alphabet) is a single cycle through all of them, so it moves every string.
        It is walked until the result is of the same id class as the input (all digits, hex with
        a letter, upper-case hex with a letter, other base64url): every class maps onto itself,
        so ids of two classes never share a pseudonym (``0f`` and ``11``), and a cycle through a
        class of two or more ids still moves each of them."""
        base, size = len(alphabet), len(alphabet) ** len(value)
        number = 0
        for char in value:
            number = number * base + alphabet.index(char)
        tweak = f"id|{alphabet}|{len(value)}".encode()
        bits = (size - 1).bit_length()  # size is at least 10 (one decimal digit)
        bits += bits & 1  # a balanced Feistel network needs an even width
        wanted = _id_class(value)
        for _ in range(_MAX_ID_STEPS):  # the cycle through all N strings passes the whole class
            forward = self._cycle_walk(number, size, bits, tweak, inverse=False)
            number = self._cycle_walk((forward + 1) % size, size, bits, tweak, inverse=True)
            digits = []
            rest = number
            for _ in value:
                rest, digit = divmod(rest, base)
                digits.append(alphabet[digit])
            candidate = "".join(reversed(digits))
            if _id_class(candidate) == wanted:
                return candidate
        raise ValueError("the id permutation did not reach the id's class")

    def _cycle_walk(self, number: int, size: int, bits: int, tweak: bytes, inverse: bool) -> int:
        """The Feistel permutation (or its inverse) restricted to [0, size) by cycle-walking."""
        for _ in range(_MAX_ID_STEPS):
            number = self._feistel(number, bits, tweak, inverse)
            if number < size:
                return number
        raise ValueError("the id permutation's cycle walk did not return")

    def _feistel(self, value: int, bits: int, tweak: bytes, inverse: bool = False) -> int:
        half = bits // 2
        mask = (1 << half) - 1
        left, right = value >> half, value & mask
        rounds = range(_FEISTEL_ROUNDS)
        for round_ in reversed(rounds) if inverse else rounds:
            if inverse:  # undo (L, R) -> (R, L ^ F(R))
                left, right = right ^ self._round(left, round_, tweak, mask), left
            else:
                left, right = right, left ^ self._round(right, round_, tweak, mask)
        return (left << half) | right

    def _round(self, half_value: int, round_: int, tweak: bytes, mask: int) -> int:
        message = tweak + bytes([round_]) + half_value.to_bytes(16, "big")
        return (
            int.from_bytes(hmac.new(self._key, message, hashlib.sha256).digest()[:16], "big") & mask
        )


def _id_class(value: str) -> int:
    """Which ``_ID_ALPHABETS`` entry an id belongs to (its first matching pattern)."""
    return next(i for i, (pattern, _) in enumerate(_ID_ALPHABETS) if pattern.fullmatch(value))


def _encode(data: bytes, alphabet: str) -> str:
    number = int.from_bytes(data, "big")
    out = []
    while number:
        number, digit = divmod(number, len(alphabet))
        out.append(alphabet[digit])
    return "".join(out)


def _stretch(seed: bytes, encode: Callable[[bytes], str], length: int) -> str:
    out = ""
    block = seed
    while len(out) < length:
        out += encode(block)
        block = hashlib.sha256(block).digest()
    return out[:length]


class DomainMapper:
    """Pseudonymous domains that keep their label count and public suffix.

    * names are normalised first (``normalize_domain``): Unicode labels become punycode, so
      ``straße.de`` and ``xn--strae-oqa.de`` are one domain and ``strasse.de`` another;
    * allowlisted public vendor/CDN domains (and their subdomains) are kept verbatim, unless the
      labels in front of the kept suffix carry a campus name (``example-backups.s3.amazonaws.com``,
      ``www.example.edu.cdn.example``, also in punycode or with dashes): those labels become
      tokens;
    * campus domains (``*.example.edu``) become ``<label tokens>.univ.example``; a second campus
      domain becomes ``<label tokens>.c2.univ.example`` and so on, in policy order;
    * every other label becomes an 8-character keyed token; the public suffix is kept, unless it
      carries a campus name itself (``printer.campus``).
    """

    def __init__(
        self,
        tokenizer: Tokenizer,
        campus_domains: Iterable[str],
        keep_domains: Iterable[str],
        campus_replacement: str = "univ.example",
        sensitive_terms: Iterable[str] = (),
    ) -> None:
        self._tokens = tokenizer
        ordered = list(dict.fromkeys(_norm(d) for d in campus_domains if _norm(d)))
        self._replacements = {
            domain: campus_replacement if i == 0 else f"c{i + 1}.{campus_replacement}"
            for i, domain in enumerate(ordered)
        }
        self.campus = tuple(sorted(ordered, key=len, reverse=True))
        self.keep = tuple(
            sorted({_norm(d) for d in keep_domains if _norm(d)}, key=len, reverse=True)
        )
        terms = {_squash(t) for t in sensitive_terms}
        for campus in ordered:
            decoded = _unpuny(campus)  # an IDN campus name is compared as its letters
            terms |= {
                _squash(campus.split(".")[0]),
                _squash(decoded.split(".")[0]),
            }  # the first label
            terms |= {_squash(campus), _squash(decoded)}  # the whole domain: cu-ac-in
        self._sensitive = tuple(sorted(t for t in terms if len(t) >= 3))

    def map(self, domain: str) -> str:
        try:
            name = _norm(domain)
        except UnicodeError:
            return self._tokens.token("domain", domain.strip().lower(), "d-", 12) + ".invalid"
        if not name:
            return domain
        for campus in self.campus:
            if _under(name, campus):
                head = name[: -len(campus)].rstrip(".")
                return self._join(head, self._replacements[campus])
        for kept in self.keep:
            if _under(name, kept):
                head = name[: -len(kept)].rstrip(".")
                return self._join(head, kept) if self._is_sensitive(head) else name
        labels = name.split(".")
        if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
            head, suffix = ".".join(labels[:-2]), ".".join(labels[-2:])
        elif len(labels) >= 2:
            head, suffix = ".".join(labels[:-1]), labels[-1]
        else:
            return self.label(name)
        if self._is_sensitive(suffix):  # not a public suffix: a campus name in last place
            return ".".join(self.label(label) for label in labels)
        return self._join(head, suffix)

    def label(self, label: str) -> str:
        """One label's token: the same for a short host name and the first label of its FQDN."""
        return self._tokens.token("label", label.lower(), "", 8)

    def _is_sensitive(self, head: str) -> bool:
        """Whether ``head`` carries a campus name, a whole campus domain or a policy literal, in
        any spelling (the squashed whole campus domain covers ``x.campus.ac.in.cdn``)."""
        squashed = _squash(_unpuny(head))
        return any(term in squashed for term in self._sensitive)

    def _join(self, head: str, suffix: str) -> str:
        if not head:
            return suffix
        return ".".join([*(self.label(label) for label in head.split(".")), suffix])


_DOTS = re.compile("[.\u3002\uff0e\uff61]")  # ".", and the ideographic and fullwidth stops


_MAX_LABEL = 63
_MAX_NAME = 253


def normalize_domain(domain: str) -> str:
    """One spelling per domain: every label trimmed, NFKC-normalised (fullwidth and other
    compatibility forms become plain letters) and lower-cased, Unicode labels in punycode
    (``xn--``), no empty labels, no trailing dot. Idempotent. Raises UnicodeError for a label
    over 63 characters or a name over 253 (and does so before encoding: punycode is quadratic)."""
    out = []
    for raw in _DOTS.split(unicodedata.normalize("NFKC", domain)):
        label = unicodedata.normalize("NFKC", raw.strip()).lower()
        if not label:
            continue
        if len(label) > _MAX_LABEL:
            raise UnicodeError("a domain label longer than 63 characters")
        if not label.isascii():
            label = "xn--" + label.encode("punycode").decode("ascii")
        out.append(label)
    name = ".".join(out)
    if len(name) > _MAX_NAME:
        raise UnicodeError("a domain name longer than 253 characters")
    return name


def _norm(domain: str) -> str:
    return normalize_domain(domain)


def _unpuny(text: str) -> str:
    """Punycode labels decoded back to Unicode (where a literal could hide)."""
    labels = []
    for label in text.split("."):
        if label.startswith("xn--"):
            with contextlib.suppress(UnicodeError, ValueError):  # not punycode: as written
                label = label[4:].encode("ascii").decode("punycode")
        labels.append(label)
    return ".".join(labels)


def _under(name: str, parent: str) -> bool:
    return name == parent or name.endswith("." + parent)


def _squash(text: str) -> str:
    """Letters and digits only (any script), NFKC-normalised and case-folded: how a name hides
    inside a label."""
    return "".join(c for c in unicodedata.normalize("NFKC", text).casefold() if c.isalnum())
