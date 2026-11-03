"""Identifiers in text (P1, D-075, D-076): what must never reach a model in clear. Shared by
the pseudonymizer (which replaces them) and the egress validator (which blocks any that
remain).

A ``Campus`` says what is internal: private and campus address space, the asset map's
networks, campus domains, and known names (asset names; host and user names of a request).
``find(text, campus)`` returns every identifier with its span and kind:
- an address in any run of dotted or dashed numbers (every window of four parts, so ports,
  OIDs and glued dots hide nothing), with leading zeros, octal or hex parts, inet_aton short
  forms, as one decimal, octal or hex integer, or partial (``10.1.2…``, ``10.1.2.x``);
- IPv6 tried from every colon of a candidate, with IPv4 inside (mapped, compatible, 6to4,
  NAT64, Teredo); ``in-addr.arpa`` and ``ip6.arpa`` forms;
- MAC addresses, campus domains, names, e-mail, ``~user`` paths, credentials and tokens in
  URLs, ≥ 32-hex or UUID strings, roll numbers, secrets;
- copies hidden by percent, HTML, backslash and ``%u`` escapes, Unicode forms, defanging
  (``[.]``), zero-width characters, base64 (also UTF-16), hex strings or punycode, one
  inside another (``DEPTH``).
Every pattern runs in linear time: a model's answer is not length-capped like a request.
"""

from __future__ import annotations

import base64
import binascii
import bisect
import html
import ipaddress
import itertools
import re
import unicodedata
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from functools import cached_property
from typing import Literal
from urllib.parse import unquote

from argus import site

Kind = Literal[
    "ip", "mac", "domain", "name", "email", "user_path", "credentials", "url_token", "hex_id",
    "roll_number", "secret",
]  # fmt: skip
IP = ipaddress.IPv4Address | ipaddress.IPv6Address

# Always internal for privacy, wider than the classifier's (link-local IPv6 can carry a MAC).
PRIVATE = tuple(
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
              "169.254.0.0/16", "fc00::/7", "fe80::/10")
)  # fmt: skip
_NAT64 = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))
# A pseudonym the privacy layer wrote (``IP_3``, ``I2.HOST_1``): never an identifier itself.
PSEUDONYM = r"(?:I\d+\.)?(?:IP|MAC|SITE|HOST|USER|EMAIL|ID|HASH|CRED)_\d+(?![\w-])"
TOKEN = re.compile(rf"(?<![\w.-]){PSEUDONYM}")
# Anything that could be read as one, glued to other text or not: removed from untrusted text.
LOOKALIKE = re.compile(r"(?:I\d+\.)?(?:IP|MAC|SITE|HOST|USER|EMAIL|ID|HASH|CRED)_\d+", re.I)
DEPTH = 3  # encodings undone one inside another
MIN_ASSET_NAME = 3  # shorter asset names are not matched (too many ordinary words)
MIN_NAME = 2  # a request's own host and user names


def _embedded(ip: ipaddress.IPv6Address) -> list[ipaddress.IPv4Address]:
    """IPv4 addresses an IPv6 address carries."""
    out = [a for a in (ip.ipv4_mapped, ip.sixtofour) if a is not None]
    if ip.teredo is not None:
        out.append(ip.teredo[1])
    value = int(ip)
    if value >> 32 == 0 and value > 0xFFFF:  # IPv4-compatible ::a.b.c.d
        out.append(ipaddress.IPv4Address(value))
    if any(ip in n for n in _NAT64):
        out.append(ipaddress.IPv4Address(value & 0xFFFFFFFF))
    return out


def _words(name: str) -> tuple[str, ...]:
    return tuple(re.findall(r"[a-z0-9]+", name.lower()))


@dataclass(frozen=True)
class Campus:
    """What counts as internal. ``networks``: campus public prefixes and the asset map's
    networks (private space is always internal); ``domains``: campus domain suffixes;
    ``assets``: asset names; ``hosts``/``users``: a request's own names. Names match as
    words, ignoring case, their words joined by blanks, ``-`` or ``_``; ``ordinary`` words
    are never taken for a one-word name. Names are never printed (a repr may end up in a
    log)."""

    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
    domains: tuple[str, ...] = field(default_factory=site.own_domains)
    assets: frozenset[str] = field(default_factory=frozenset, repr=False)
    hosts: frozenset[str] = field(default_factory=frozenset, repr=False)
    users: frozenset[str] = field(default_factory=frozenset, repr=False)
    ordinary: frozenset[str] = field(default_factory=frozenset, repr=False)
    is_internal: Callable[[IP], bool] | None = field(default=None, compare=False)

    def internal(self, ip: IP) -> bool:
        if isinstance(ip, ipaddress.IPv6Address) and any(self.internal(a) for a in _embedded(ip)):
            return True
        if any(ip.version == n.version and ip in n for n in (*PRIVATE, *self.networks)):
            return True
        return bool(self.is_internal and self.is_internal(ip))

    def campus_domain(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        return any(host == d or host.endswith("." + d) for d in self.domains)

    def name_kind(self, name: str) -> Literal["host", "user"]:
        return "user" if _words(name) in self._users else "host"

    @cached_property
    def _users(self) -> frozenset[tuple[str, ...]]:
        return frozenset(_words(u) for u in self.users)

    @cached_property
    def name_index(self) -> dict[str, tuple[tuple[str, ...], ...]]:
        """First word → every name (as words) starting with it, longest first."""
        names: set[tuple[str, ...]] = set()
        for pool, least in ((self.assets, MIN_ASSET_NAME), (self.hosts | self.users, MIN_NAME)):
            for name in pool:
                words = _words(name)
                if not words or len(" ".join(words)) < least:
                    continue
                if len(words) == 1 and words[0] in self.ordinary:
                    continue
                names.add(words)
        index: dict[str, list[tuple[str, ...]]] = {}
        for words in names:
            index.setdefault(words[0], []).append(words)
        return {k: tuple(sorted(v, key=len, reverse=True)) for k, v in index.items()}


@dataclass(frozen=True)
class Found:
    start: int
    end: int
    kind: Kind
    value: str  # the identifier as found (decoded where it was encoded)
    encoded: bool = False


_PART = r"(?:0[xX][0-9A-Fa-f]{1,8}|\d{1,12})"
DOTTED = re.compile(rf"{_PART}(?:\.{_PART})+")
DASHED = re.compile(r"(?<!\d)\d{1,3}(?:-\d{1,3}){3,}(?!\d)")
MARK = re.compile(r"\.?(?:…|\.\.\.)|\.(?:x{1,3}|\*)(?![A-Za-z0-9])", re.I)
DECIMAL = re.compile(r"(?<!\d)(\d{8,10})(?!\d)")
OCTAL_INT = re.compile(r"(?<!\d)(0[0-7]{10,11})(?!\d)")
HEX_IP = re.compile(r"(?<![A-Za-z0-9])0[xX]([0-9A-Fa-f]{7,8})(?![0-9A-Fa-f])")
V6RUN = re.compile(r"[0-9A-Fa-f:.]{3,}")
ARPA = re.compile(r"(?<!\d)(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.in-addr\.arpa", re.I)
ARPA6 = re.compile(r"((?:[0-9A-Fa-f]\.){32})ip6\.arpa", re.I)
MACRUN = re.compile(r"[0-9A-Fa-f]{1,4}(?:[:.-][0-9A-Fa-f]{1,4}){2,}")
USER_PATH = re.compile(rf"/~(?!{PSEUDONYM})[A-Za-z0-9._-]+")
CREDENTIALS = re.compile(r"://[^/\s:@]{1,256}:[^/\s@]{1,256}@")
_KEYS = (
    r"access_token|id_token|refresh_token|token|key|api_key|apikey|access_key|sig|signature|"
    r"x-amz-signature|x-amz-credential|x-amz-security-token|session|sessionid|sessid|phpsessid|"
    r"jsessionid|sid|auth|jwt|password|pass|passwd|pwd|code|secret|client_secret"
)
# a value ends at a quote or a backslash too: JSON escapes (``\\"``) never lengthen it
URL_TOKEN = re.compile(rf"[?&;](?:{_KEYS})=(?!{PSEUDONYM})([^&\s#\"'\\]{{4,}})", re.I)
HEX_ID = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{32,}|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-"
                    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})(?![0-9A-Fa-f])")  # fmt: skip
ROLL = re.compile(r"(?<![A-Za-z0-9])\d{2}[A-Za-z]\d{6}(?![A-Za-z0-9])")
SECRET = re.compile(
    r"sk-[A-Za-z0-9_-]{16,}|gsk_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{20,}|xox[bpas]-[A-Za-z0-9-]{10,}"
    r"|gh[pousr]_[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}"
    r"|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.|hooks\.slack\.com/services/[A-Za-z0-9/_-]{8,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----"
    r"|(?i:bearer\s+[A-Za-z0-9._~+/-]{16,})|(?i:(?:basic|apikey)\s+[A-Za-z0-9._~+/=-]{16,})"
    r"|(?i:(?<![A-Za-z0-9])(?:set-)?cookie:[ \t]*[^\r\n]{8,})"
    r"|(?i:(?<![?&;A-Za-z0-9_-])[\"']?[A-Za-z0-9_-]{0,30}"
    r"(?:secret|password|passwd|pwd|pass|token|api[_-]?key|access[_-]?key|session[_-]?id|sessid"
    r"|jwt|auth)[\"']?[ \t]{0,5}[:=][ \t]{0,5}[\"']?"
    rf"(?!{PSEUDONYM})(?=[^\s,;\"'&]{{0,200}}\d|[^\s,;\"'&]{{16}})[^\s,;\"'&]{{6,200}})"
)
B64 = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{10,}={0,2}")
HEXSTR = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){7,}(?![0-9A-Fa-f])")
LABELS = re.compile(r"[A-Za-z0-9.-]+")
WORD = re.compile(r"[A-Za-z0-9]+")
NAME_GAP = re.compile(r"[\s_-]+")
PRINTABLE = re.compile(r"[\x20-\x7e]{7,}")
ESCAPE = re.compile(
    r"\\(?:x([0-9A-Fa-f]{2})|u([0-9A-Fa-f]{4})|u\{([0-9A-Fa-f]{1,6})\}|([0-7]{3}))"
    r"|%u([0-9A-Fa-f]{4})"
)
DEFANG = re.compile(
    r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\[at\]|\(at\)|\[@\]|[\u3002\uff61\uff0e]", re.I
)
_EMAIL_LOCAL = re.compile(r"[\w.%+-]")
_DOMAIN_CHAR = re.compile(r"[A-Za-z0-9.-]")


def _ip(text: str) -> IP | None:
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _part(text: str, octal: bool) -> int | None:
    if text[:2] in ("0x", "0X"):
        return int(text[2:], 16)
    if octal and len(text) > 1 and text.startswith("0"):
        return int(text, 8) if all(c in "01234567" for c in text) else None
    return int(text)


def _aton(parts: Sequence[str]) -> list[ipaddress.IPv4Address]:
    """Every address 1 to 4 dotted parts can be read as (inet_aton: decimal, octal, hex; a
    short form's last part fills the remaining bytes)."""
    out = []
    for octal in (False, True):
        values = [_part(p, octal) for p in parts]
        nums = [v for v in values if v is not None]
        if len(nums) != len(parts) or not 1 <= len(nums) <= 4:
            continue
        last_bits = 8 * (5 - len(nums))
        if any(v > 255 for v in nums[:-1]) or nums[-1] >= 1 << last_bits:
            continue
        value = 0
        for v in nums[:-1]:
            value = value << 8 | v
        out.append(ipaddress.IPv4Address(value << last_bits | nums[-1]))
    return out


def _dotted(text: str, campus: Campus, out: list[Found]) -> None:
    for m in DOTTED.finditer(text):
        parts = m.group(0).split(".")
        value: str | None = None
        for i in range(len(parts) - 3):  # every window of four parts
            window = parts[i : i + 4]
            hits = [a for a in _aton(window) if campus.internal(a)]
            if hits:
                value = str(hits[0])
                break
            head = _aton([*window[:3], "0"])  # ``192.168.12.990``: its network shows
            if not _aton(window) and head and campus.internal(head[0]):
                value = m.group(0)
                break
        if value is None and len(parts) in (2, 3) and (_part(parts[-1], False) or 0) > 255:
            hits = [a for a in _aton(parts) if campus.internal(a)]  # ``10.65538``
            value = str(hits[0]) if hits else None
        mark = MARK.match(text, m.end())
        if value is None and len(parts) == 3:
            head = _aton([*parts, "0"])
            if head and campus.internal(head[0]):
                # a marked prefix (``10.1.2.x``) always; an unmarked one only outside private
                # space, where ``10.0.1`` is far more often a version than a network
                private = any(head[0] in n for n in PRIVATE)
                if mark is not None or not private:
                    value = m.group(0)
        if value is not None:
            end = mark.end() if mark is not None and len(parts) == 3 else m.end()
            out.append(Found(m.start(), end, "ip", value))
    for m in DASHED.finditer(text):
        parts = m.group(0).split("-")
        for i in range(len(parts) - 3):
            hits = [a for a in _aton(parts[i : i + 4])[:1] if campus.internal(a)]
            if hits:
                out.append(Found(m.start(), m.end(), "ip", str(hits[0])))
                break


def _ipv6(text: str, campus: Campus, out: list[Found]) -> None:
    """Every candidate between colons of a hex/colon run, at most 45 characters long."""
    for m in V6RUN.finditer(text):
        run = m.group(0)
        if run.count(":") < 2:
            continue
        # a candidate starts at the run's start or after a colon or dot, and ends at its end
        # or at a colon or dot; ends are looked up within 45 characters (bisect: linear overall)
        starts = [0, *(i + 1 for i, c in enumerate(run) if c in ":.")]
        ends = sorted({len(run), *(i for i, c in enumerate(run) if c in ":.")})
        done = -1
        for s in starts:
            if s < done:
                continue
            lo, hi = bisect.bisect_right(ends, s), bisect.bisect_right(ends, s + 45)
            for e in reversed(ends[lo:hi]):
                candidate = run[s:e].rstrip(".")
                if candidate.count(":") < 2 or ":::" in candidate or candidate.count("::") > 1:
                    continue
                ip = _ip(candidate)
                if isinstance(ip, ipaddress.IPv6Address) and campus.internal(ip):
                    out.append(Found(m.start() + s, m.start() + e, "ip", str(ip)))
                    done = e
                    break
    for m in ARPA6.finditer(text):
        nibbles = m.group(1).replace(".", "")[::-1]
        ip6 = ipaddress.IPv6Address(int(nibbles, 16))
        if campus.internal(ip6):
            out.append(Found(m.start(), m.end(), "ip", str(ip6)))


def _macs(text: str, out: list[Found]) -> None:
    """A MAC address in any run of hex groups: six 2-digit groups joined by one separator
    (``:`` or ``-``), or three 4-digit groups joined by dots; every window, as for IPv4."""
    for m in MACRUN.finditer(text):
        groups = re.split(r"([:.-])", m.group(0))
        parts, seps = groups[0::2], groups[1::2]
        for size, width, joins in ((6, 2, ":-"), (3, 4, ".")):
            for i in range(len(parts) - size + 1):
                window = parts[i : i + size]
                between = set(seps[i : i + size - 1])
                if (
                    len(between) == 1
                    and between <= set(joins)
                    and all(len(g) == width for g in window)
                ):
                    value = between.pop().join(window).lower()
                    out.append(Found(m.start(), m.end(), "mac", value))
                    break


def _domains(text: str, campus: Campus, out: list[Found]) -> None:
    """A campus domain or subdomain, also inside a longer name (``moodle.example.edu.evil.
    example``: its campus part is campus), but not glued to more letters or digits
    (``example.education``) nor another domain ending alike (``xexample.edu``). Found by the
    suffix, then extended to the left: linear time."""
    low = text.lower()
    for domain in campus.domains:
        for hit in re.finditer(re.escape(domain), low):
            at, end = hit.start(), hit.end()
            nxt = text[end : end + 1]
            right = not (nxt.isascii() and nxt.isalnum())
            left = at == 0 or text[at - 1] == "." or not _DOMAIN_CHAR.match(text[at - 1])
            start = at
            if at > 0 and text[at - 1] == ".":
                while start > 0 and _DOMAIN_CHAR.match(text[start - 1]) and at - start < 253:
                    start -= 1
                while start < at and text[start] in ".-":
                    start += 1
            if left and right:
                out.append(Found(start, end, "domain", text[start:end].lower()))


def _emails(text: str, out: list[Found]) -> None:
    for hit in re.finditer("@", text):
        at = hit.start()
        start = at
        while start > 0 and at - start < 64 and _EMAIL_LOCAL.match(text[start - 1]):
            start -= 1
        end = at + 1
        while end < len(text) and end - at < 254 and _DOMAIN_CHAR.match(text[end]):
            end += 1
        labels = text[at + 1 : end].split(".")
        while labels and not re.fullmatch(r"[A-Za-z]{2,63}", labels[-1]):
            labels.pop()  # ``a@b.org.0``: the address ends at its last real label
        local = text[start:at]
        if start < at and len(labels) > 1 and all(labels) and not TOKEN.fullmatch(local):
            stop = at + 1 + len(".".join(labels))
            out.append(Found(start, stop, "email", text[start:stop]))


def _names(text: str, campus: Campus, out: list[Found]) -> None:
    index = campus.name_index
    if not index:
        return
    tokens = [t.span() for t in TOKEN.finditer(text)]
    words = list(WORD.finditer(text))
    for i, w in enumerate(words):
        for name in index.get(w.group(0).lower(), ()):
            span = words[i : i + len(name)]
            if len(span) < len(name):
                continue
            if any(s.group(0).lower() != n for s, n in zip(span, name, strict=True)):
                continue
            gaps = (text[a.end() : b.start()] for a, b in itertools.pairwise(span))
            if not all(NAME_GAP.fullmatch(g) for g in gaps):
                continue
            start, end = span[0].start(), span[-1].end()
            if any(s < end and start < e for s, e in tokens):
                continue
            out.append(Found(start, end, "name", text[start:end]))
            break


def _scan(text: str, campus: Campus) -> list[Found]:
    """Identifiers written in clear (no decoding)."""
    out: list[Found] = []

    def add(m: re.Match[str], kind: Kind, group: int = 0, value: str | None = None) -> None:
        out.append(Found(m.start(group), m.end(group), kind, value or m.group(group)))

    _dotted(text, campus, out)
    _ipv6(text, campus, out)
    for m in ARPA.finditer(text):
        ip = _ip(".".join(reversed(m.groups())))
        if ip is not None and campus.internal(ip):
            add(m, "ip", 0, str(ip))
    for pattern, radix in ((DECIMAL, 10), (OCTAL_INT, 8)):
        for m in pattern.finditer(text):
            number = int(m.group(1), radix)
            if number < 2**32 and campus.internal(ipaddress.IPv4Address(number)):
                add(m, "ip", 1, str(ipaddress.IPv4Address(number)))
    for m in HEX_IP.finditer(text):
        ip4 = ipaddress.IPv4Address(int(m.group(1), 16))
        if campus.internal(ip4):
            add(m, "ip", 0, str(ip4))
    _macs(text, out)
    _domains(text, campus, out)
    _emails(text, out)
    for m in USER_PATH.finditer(text):
        add(m, "user_path")
    for m in CREDENTIALS.finditer(text):
        add(m, "credentials")
    for m in URL_TOKEN.finditer(text):
        add(m, "url_token", 1)
    for m in HEX_ID.finditer(text):
        add(m, "hex_id")
    for m in ROLL.finditer(text):
        add(m, "roll_number")
    for m in SECRET.finditer(text):
        add(m, "secret")
    _names(text, campus, out)
    return out


def unescape(text: str) -> str:
    """Backslash, octal and ``%u`` escapes, also behind doubled backslashes (``\\\\x31``)."""

    def one(m: re.Match[str]) -> str:
        if m.group(4):
            return chr(int(m.group(4), 8))
        code = int(next(g for g in (m.group(1), m.group(2), m.group(3), m.group(5)) if g), 16)
        return chr(code) if code <= 0x10FFFF else m.group(0)

    return ESCAPE.sub(one, re.sub(r"\\{2,}", r"\\", text))


def _defang(text: str) -> str:
    def one(m: re.Match[str]) -> str:
        token = m.group(0).lower()
        return "@" if "at" in token or "@" in token else "."

    return DEFANG.sub(one, text)


def _visible(text: str) -> str:
    return "".join(c for c in text if unicodedata.category(c) != "Cf")


def _nfkc(text: str) -> str:
    return unicodedata.normalize("NFKC", text)


DECODERS: tuple[Callable[[str], str], ...] = (
    unquote, html.unescape, unescape, _nfkc, _defang, _visible,
)  # fmt: skip


def canonical(text: str) -> str:
    """``text`` with every whole-text encoding undone, repeatedly, until it no longer changes
    (at most ``DEPTH`` rounds): percent, HTML, escapes, Unicode forms, defanging, zero-width."""
    for _ in range(DEPTH):
        decoded = text
        for decode in DECODERS:
            try:
                decoded = decode(decoded)
            except (ValueError, OverflowError):
                continue
        if decoded == text:
            break
        text = decoded
    return text


def _printable(raw: bytes) -> list[str]:
    """The printable runs of decoded bytes, also with NULs taken out (UTF-16 text)."""
    runs = PRINTABLE.findall(raw.decode("latin-1"))
    if b"\x00" in raw:
        runs += PRINTABLE.findall(raw.replace(b"\x00", b"").decode("latin-1"))
    return runs


def _base64(chunk: str) -> str | None:
    """The printable text a base64 stretch may hold: both alphabets, every alignment at either
    end (a value glued to other text, like ``id=abcMTAuMS4yLjM`` or ``/a/MTAuMS4yLjM/b``: one
    of the four alignments always meets the value). Runs from every reading are joined, so a
    wrong alignment that happens to look printable hides nothing."""
    bare = chunk.rstrip("=")
    runs: list[str] = []
    for skip in range(4):
        for trim in range(4):
            part = bare[skip : len(bare) - trim]
            if len(part) < 8 or len(part) % 4 == 1:
                continue
            padded = part + "=" * (-len(part) % 4)
            for alt in (b"+/", b"-_"):
                try:
                    raw = base64.b64decode(padded, altchars=alt, validate=True)
                except (binascii.Error, ValueError):
                    continue
                runs.extend(_printable(raw))
    return " ".join(dict.fromkeys(runs)) if runs else None


def _segments(text: str) -> Iterable[tuple[int, int, str]]:
    """(start, end, decoded) for stretches encoded on their own: base64, hex, punycode."""
    for m in B64.finditer(text):
        held = _base64(m.group(0))
        if held is not None:
            yield m.start(), m.end(), held
    for m in HEXSTR.finditer(text):
        runs = _printable(bytes.fromhex(m.group(0)))
        if runs:
            yield m.start(), m.end(), " ".join(runs)
    for m in LABELS.finditer(text):
        if "xn--" not in m.group(0).lower():
            continue
        try:
            plain = ".".join(
                label.encode("ascii").decode("idna") if label.lower().startswith("xn--") else label
                for label in m.group(0).split(".")
            )
        except (UnicodeError, ValueError):
            continue
        yield m.start(), m.end(), plain


def find(text: str, campus: Campus, depth: int = DEPTH) -> list[Found]:
    """Every identifier in ``text``, in clear or encoded (up to ``depth`` encodings deep),
    sorted by position. An encoded one spans the encoded stretch (the whole text for a
    whole-text encoding)."""
    found = _scan(text, campus)
    if depth > 0:
        plain = canonical(text)
        if plain != text:
            found += [Found(0, len(text), f.kind, f.value, True) for f in _scan(plain, campus)]
        for source in dict.fromkeys((text, plain)):
            whole = source is not text
            for start, end, decoded in _segments(source):
                span = (0, len(text)) if whole else (start, end)
                for inner in find(decoded, campus, depth - 1):
                    found.append(Found(*span, inner.kind, inner.value, encoded=True))
    return sorted(set(found), key=lambda f: (f.start, f.end, f.kind, f.value))


def outermost(found: Sequence[Found]) -> list[Found]:
    """Non-overlapping spans, the longest first at each position (for replacement)."""
    out: list[Found] = []
    for item in sorted(found, key=lambda f: (f.start, -(f.end - f.start), f.kind)):
        if out and item.start < out[-1].end:
            continue
        out.append(item)
    return out
