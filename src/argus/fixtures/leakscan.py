"""Prove that no original identifier survives in fixture files (R2 gate, D-030, D-041).

The denylist comes from the raw sources (harvested identifiers, the asset map, policy extras).

* **Files** are read by content, not by name: gzip, bzip2, xz and zip (also nested, with a size
  cap) are decompressed; UTF-8, UTF-16 and UTF-32 (with or without a BOM) are decoded; JSON, JSON
  Lines and plain text are split into strings (duplicate JSON keys kept). A file that cannot be
  read completely (a corrupt stream, binary content, an unknown compressor) is reported as
  unscannable: never passed.
* **Strings** are scanned as stored and in decoded views. Each view decodes to a fixed point
  (URL with and without ``+``, HTML entities, ``\\x``/``\\u``/``\\U``/octal/``\\t`` escapes), and
  single decoders also unwrap base64 and hex payloads and JSON embedded anywhere in a string, each
  inner string separately, under a size budget.
* **Names** are found by a word index: set lookups between ASCII word boundaries, leftmost-longest,
  tried only where some name starts with the word found there. All-capital short codes (EE, META)
  match in their own case only; every other name in any case; a name with edge punctuation
  (``LAB-PC07$``) also matches without it.
* **Addresses** are compared in canonical form, so another spelling of a denylisted address is
  found too (upper-case or expanded IPv6, zero-padded, dashed, ``_``-separated, integer or hex
  IPv4 in a URL, reverse DNS for IPv4 and IPv6, IPv4 inside NAT64, 6to4 and Teredo); any address
  inside a site prefix is a leak by definition (site pseudonyms always move to the site space).
"""

from __future__ import annotations

import base64
import binascii
import bz2
import contextlib
import html
import io
import ipaddress
import itertools
import json
import lzma
import re
import unicodedata
import zipfile
import zlib
from collections import deque
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote, unquote_plus

SHORT_NAME = 5
_ALNUM = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
_WORD_START = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9]")
_WORD_END = re.compile(r"[A-Za-z0-9](?![A-Za-z0-9])")
_FIRST_WORD = re.compile(r"[A-Za-z0-9]+")
_EDGES = re.compile(r"^[^A-Za-z0-9]+|[^A-Za-z0-9]+$")
_V4 = re.compile(r"(?<![0-9])(?=(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2}))?(?![0-9]))")
_V4_SEPARATED = re.compile(
    r"(?<![0-9])(?=((\d{1,3})([-_])(\d{1,3})\3(\d{1,3})\3(\d{1,3}))(?![0-9]))"
)
_V4_IN_URL = re.compile(r"(?i)://(?:[^/@\s]*@)?(0x[0-9a-f]{1,8}|\d{8,10})(?=[/:?#\s\"']|$)")
_V4_REVERSE = re.compile(r"(?i)((?:\d{1,3}\.){1,4})in-addr\.arpa")
_V6_REVERSE = re.compile(r"(?i)((?:[0-9a-f]\.){1,32})ip6\.arpa")
_V6 = re.compile(
    r"(?<![0-9A-Fa-f:])(?=([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,8}(?:\.\d{1,3}){0,3})"
    r"(?:/(\d{1,3}))?)"
)
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_SIX_TO_FOUR = ipaddress.ip_network("2002::/16")
_TEREDO = ipaddress.ip_network("2001::/32")
_ESCAPE = re.compile(
    r"((?:\\x[0-9A-Fa-f]{2})+)|\\u([0-9A-Fa-f]{4})|\\U([0-9A-Fa-f]{8})|\\([0-7]{3})"
    r"|\\([tnrbf\"\\/])"
)
_SIMPLE_ESCAPES = {"t": "\t", "n": "\n", "r": "\r", "b": "\b", "f": "\f"}
_BASE64 = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX_RUN = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Fa-f])")
_SEPARATORS = r"(?:[\s_.+-]|%20)*"
_MAX_VIEWS = 64  # single-decoder views per string, on top of the fixed-point views
_FIXED_POINT_ROUNDS = 16
_EMBEDDED = 64  # JSON documents / base64 or hex runs looked at per string
_MAX_BYTES = 256 * 1024 * 1024  # decompressed size cap (a bomb is reported, not expanded)
_MAX_LAYERS = 4

Address = ipaddress.IPv4Address | ipaddress.IPv6Address
Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class Leak:
    file: str
    identifier: str = field(repr=False)
    form: str  # "raw" | "json" | "decoded" | ... | "file name" | "unscannable: <why>"

    def __str__(self) -> str:
        # Never print the identifier itself: only enough to locate it.
        if self.form.startswith("unscannable"):
            return f"{self.file}: cannot be scanned completely ({self.form})"
        return (
            f"{self.file}: denylisted identifier ({len(self.identifier)} chars) in {self.form} text"
        )


class LeakScanner:
    def __init__(self, identifiers: Iterable[str], networks: Iterable[str] = ()) -> None:
        self._exact: set[str] = set()  # all-capital short codes: EE, CSE, META
        self._folded: set[str] = set()  # every other name, lower-cased
        self._addresses: set[str] = set()  # canonical addresses and networks
        odd: list[str] = []  # names that start or end with a non-alphanumeric character
        phrases: list[str] = []  # names with spaces: any separator run between words
        words: list[str] = []
        idents = {i.strip() for i in identifiers if i and len(i.strip()) >= 2}
        for ident in idents:
            canonical = _canonicals(ident)
            if canonical:
                self._addresses.update(canonical)
            elif any(c.isspace() for c in ident):
                phrases.append(ident)
            elif ident[0] not in _ALNUM or ident[-1] not in _ALNUM:
                core = _EDGES.sub("", ident)
                if len(core) >= 3 and not any(c.isspace() for c in core):
                    words.append(core)  # LAB-PC07$ is found as LAB-PC07 (wherever it is)
                else:
                    odd.append(ident)  # rare: nothing alphanumeric to index it by
            else:
                words.append(ident)
        # First word (lower case) -> every length a name starting with it can have in the text.
        self._first: dict[str, set[int]] = {}
        for name in words:
            if len(name) < SHORT_NAME and name.isalpha() and name.isupper():
                self._exact.add(name)
            else:
                self._folded.add(name.lower())
            first = _FIRST_WORD.match(name)
            if first is not None:
                lengths = self._first.setdefault(first.group(0).lower(), set())
                lengths.update((len(name), len(name.lower())))
        self.size = len(idents)
        # Phrases (names with spaces) by first word: tried only where that word starts.
        self._phrases: dict[str, list[re.Pattern[str]]] = {}
        self._loose: list[re.Pattern[str]] = []  # phrases that start before their first word
        for phrase in sorted(phrases, key=lambda p: (-len(p), p)):
            first = _FIRST_WORD.search(phrase)
            if first is None:
                odd.append(phrase)
                continue
            body = _SEPARATORS.join(re.escape(w) for w in phrase.split())
            pattern = re.compile(body + "(?![A-Za-z0-9])", re.IGNORECASE)
            if first.start():  # Émile Hall, (North Wing: no match starts at the word "mile"
                self._loose.append(pattern)
                continue
            self._phrases.setdefault(first.group(0).lower(), []).append(pattern)
        self._phrase_lengths = sorted({len(w) for w in self._phrases}, reverse=True)
        self._odd = _alternation(odd, "(?<![A-Za-z0-9])", "(?![A-Za-z0-9])")
        self._networks: list[Network] = [ipaddress.ip_network(n, strict=False) for n in networks]

    # ------------------------------------------------------------------ text

    def scan_text(self, text: str) -> list[str]:
        hits = self._words(text)
        if self._odd is not None:
            hits.extend(m.group(0) for m in self._odd.finditer(text))
        if self._phrases:
            hits.extend(self._phrase_hits(text))
        for pattern in self._loose:
            hits.extend(m.group(0) for m in pattern.finditer(text))
        hits.extend(self._address_hits(text))
        return hits

    def _phrase_hits(self, text: str) -> list[str]:
        """Phrases tried only where their first word starts (also glued: CampusUniversity)."""
        hits = []
        lowered = text.lower()
        aligned = len(lowered) == len(text)
        for m in _WORD_START.finditer(text):
            start = m.start()
            for length in self._phrase_lengths:
                word = (
                    lowered[start : start + length]
                    if aligned
                    else text[start : start + length].lower()
                )
                for pattern in self._phrases.get(word, ()):
                    found = pattern.match(text, start)
                    if found is not None:
                        hits.append(found.group(0))
                        break
        return hits

    def scan_name(self, name: str) -> list[str]:
        """A file or directory name: also with ``_`` read as ``-``, ``.`` or a space (``slug``)."""
        hits = self.scan_text(name)
        for separator in ("-", ".", " "):
            if "_" in name:
                hits.extend(self.scan_text(name.replace("_", separator)))
        return hits

    def _words(self, text: str) -> list[str]:
        """Leftmost-longest names between word boundaries, by set lookups; a start is skipped at
        once unless some name begins with the word found there."""
        if not self._first:
            return []
        starts = [m.start() for m in _WORD_START.finditer(text)]
        ends = [m.end() for m in _WORD_END.finditer(text)]
        lowered = text.lower()
        aligned = len(lowered) == len(text)
        hits: list[str] = []
        last = 0
        first_end = 0
        count = len(ends)
        for start in starts:
            while first_end < count and ends[first_end] <= start:
                first_end += 1
            if start < last or first_end >= count:
                continue
            word_end = ends[first_end]
            word = lowered[start:word_end] if aligned else text[start:word_end].lower()
            lengths = self._first.get(word)
            if lengths is None:
                continue
            longest = max(lengths)
            best = 0
            index = first_end
            while index < count:  # no slicing of ``ends``: that would copy it per word
                end = ends[index]
                index += 1
                size = end - start
                if size > longest:
                    break
                if size not in lengths:
                    continue
                piece = text[start:end]
                folded = lowered[start:end] if aligned else piece.lower()
                if folded in self._folded or piece in self._exact:
                    best = end
            if best:
                hits.append(text[start:best])
                last = best
        return hits

    def _address_hits(self, text: str) -> list[str]:
        return [
            written
            for written, address, network in _addresses_in(text)
            if self._address_listed(address, network)
        ]

    def _address_listed(self, address: Address, network: Network | None) -> bool:
        if network is not None and str(network) in self._addresses:
            return True
        host_form = (
            network is None
            or network.prefixlen == network.max_prefixlen
            or address != network.network_address  # interface notation: the host is named
        )
        if host_form and str(address) in self._addresses:
            return True
        return any(address.version == n.version and address in n for n in self._networks)

    # ------------------------------------------------------------------ files

    def scan_file(self, path: Path, label: str | None = None) -> list[Leak]:
        name = label or str(path)
        data, problems = _unwrap(path.read_bytes())
        texts, problem = _texts(data)
        if problem:
            problems.append(problem)
        leaks = [Leak(name, "", f"unscannable: {p}") for p in problems]
        for text in texts:
            leaks.extend(self.scan_document(text, name))
        return leaks

    def scan_document(self, raw: str, label: str) -> list[Leak]:
        """A document's text as stored, then every string in it (JSON, JSON Lines or plain)."""
        leaks = [Leak(label, hit, "raw") for hit in self.scan_text(raw)]
        for value in _document_strings(raw):
            leaks.extend(Leak(label, hit, "json") for hit in self.scan_text(value))
            for form, view in _views(value):
                leaks.extend(Leak(label, hit, form) for hit in self.scan_text(view))
        return leaks


# ---------------------------------------------------------------------- addresses


def _canonicals(text: str) -> list[str]:
    """The canonical forms of an address or network in any spelling, or [] for a name. An
    address written with a prefix (interface notation, 10.1.2.3/24) names both the host and the
    network; a zone id (fe80::1%eth0) is dropped, as the text side drops it."""
    if not text or not (text[0].isdigit() or text[0] == "[" or ":" in text):
        return []
    address, _, prefix = text.partition("/")
    parsed = _parse_address(address.partition("%")[0])
    if parsed is None:
        return []
    if not prefix:
        return [str(parsed)]
    try:
        network = ipaddress.ip_network(f"{parsed}/{int(prefix)}", strict=False)
    except ValueError:
        return []
    return [str(network)] if parsed == network.network_address else [str(network), str(parsed)]


def _parse_address(text: str) -> Address | None:
    parts = text.split(".")
    if len(parts) == 4 and all(p.isdecimal() and len(p) <= 3 for p in parts):
        if all(int(p) <= 255 for p in parts):
            return ipaddress.IPv4Address(".".join(str(int(p)) for p in parts))
        return None
    try:
        return ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        return None


def _addresses_in(text: str) -> Iterator[tuple[str, Address, Network | None]]:
    """(as written, address, network if written as a CIDR) for every address-like run, also
    overlapping ones (``1.10.1.2.3`` holds 10.1.2.3) and IPv4 inside IPv6."""
    for m in _V4.finditer(text):
        address = _parse_address(m.group(1))
        if address is not None:
            yield m.group(1), address, _network(address, m.group(2))
    for m in _V4_SEPARATED.finditer(text):
        address = _parse_address(".".join((m.group(2), m.group(4), m.group(5), m.group(6))))
        if address is not None:
            yield m.group(1), address, None
    for m in _V4_IN_URL.finditer(text):
        written = m.group(1)
        value = int(written, 16) if written.lower().startswith("0x") else int(written)
        if value < 2**32:
            yield written, ipaddress.IPv4Address(value), None
    for m in _V4_REVERSE.finditer(text):
        octets = m.group(1).rstrip(".").split(".")[::-1]
        if all(o.isdigit() and int(o) <= 255 for o in octets):
            filled = octets + ["0"] * (4 - len(octets))
            address = ipaddress.IPv4Address(".".join(str(int(o)) for o in filled))
            yield m.group(0), address, _network(address, str(8 * len(octets)))
    for m in _V6_REVERSE.finditer(text):
        nibbles = m.group(1).rstrip(".").split(".")[::-1]
        v6 = ipaddress.IPv6Address(int("".join(nibbles).ljust(32, "0"), 16))
        yield m.group(0), v6, _network(v6, str(4 * len(nibbles)))
    if ":" in text:
        for m in _V6.finditer(text):
            yield from _v6_forms(m.group(1), m.group(2))


def _v6_forms(candidate: str, prefix: str | None) -> Iterator[tuple[str, Address, Network | None]]:
    """The candidate and every suffix after one of its colons (``[IPv6:2001:db8::5]`` is read
    from ``6:``; ``client:2001:db8::5`` from ``:2001``), with IPv4 embedded in mapped, NAT64,
    6to4 and Teredo addresses."""
    suffixes = [candidate[i + 1 :] for i, c in enumerate(candidate) if c == ":"][:8]
    tries = [candidate, *suffixes]
    for text in tries:
        address = _parse_address(text)
        if not isinstance(address, ipaddress.IPv6Address):
            continue
        yield text, address, _network(address, prefix)
        value = int(address)
        if address.ipv4_mapped is not None:
            yield text, address.ipv4_mapped, None
        elif address in _NAT64:
            yield text, ipaddress.IPv4Address(value & 0xFFFFFFFF), None
        elif address in _SIX_TO_FOUR:
            yield text, ipaddress.IPv4Address((value >> 80) & 0xFFFFFFFF), None
        elif address in _TEREDO:
            yield text, ipaddress.IPv4Address(~value & 0xFFFFFFFF), None


def _network(address: Address, prefix: str | None) -> Network | None:
    if prefix is None:
        return None
    try:
        return ipaddress.ip_network(f"{address}/{int(prefix)}", strict=False)
    except ValueError:
        return None


# ---------------------------------------------------------------------- files: bytes to text


def _unwrap(data: bytes) -> tuple[bytes, list[str]]:
    """Decompress by content (not by name), layer after layer, with a size cap."""
    problems: list[str] = []
    for _ in range(_MAX_LAYERS):
        kind = _compression(data)
        if kind is None:
            break
        data, problem = _decompress(kind, data)
        if problem:
            problems.append(f"{kind}: {problem}")
            break
    return data, problems


def _compression(data: bytes) -> str | None:
    if data.startswith(b"\x1f\x8b"):
        return "gzip"
    if len(data) >= 2 and data[0] == 0x78 and (data[0] << 8 | data[1]) % 31 == 0:
        return "zlib"  # a zlib header (deflate bodies of HTTP, PDFs, git objects)
    if data.startswith(b"BZh"):
        return "bzip2"
    if data.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if data.startswith(b"PK\x03\x04"):
        return "zip"
    if data.startswith(b"\x28\xb5\x2f\xfd"):
        return "zstd"
    return None


def _decompress(kind: str, data: bytes) -> tuple[bytes, str | None]:
    """(what could be read, the problem or None). A corrupt stream yields what it held."""
    if kind == "zip":
        return _unzip(data)
    if kind == "zstd":
        return data, "not supported"
    out = bytearray()
    remaining = data
    while remaining:
        decompressor: Any = (
            zlib.decompressobj(16 + zlib.MAX_WBITS)
            if kind == "gzip"
            else zlib.decompressobj()
            if kind == "zlib"
            else bz2.BZ2Decompressor()
            if kind == "bzip2"
            else lzma.LZMADecompressor()
        )
        try:
            out += decompressor.decompress(remaining, _MAX_BYTES - len(out) + 1)
        except (OSError, EOFError, ValueError, zlib.error, lzma.LZMAError):
            return bytes(out), "corrupt stream"
        if len(out) > _MAX_BYTES:
            return bytes(out[:_MAX_BYTES]), "larger than the size cap"
        if not decompressor.eof:
            return bytes(out), "truncated stream"
        remaining = decompressor.unused_data  # concatenated members
        if remaining and _compression(remaining) != kind:
            return bytes(out), "trailing data after the stream"
    return bytes(out), None


def _unzip(data: bytes) -> tuple[bytes, str | None]:
    """Every member's name and content (each unwrapped again: a .gz inside a zip). A member that
    cannot be read (corrupt, encrypted, an unknown method) makes the archive unscannable; the
    problem never names the member (its name may be an identifier)."""
    out = bytearray()
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for info in archive.infolist():
                out += info.filename.encode() + b"\n"
                if info.file_size + len(out) > _MAX_BYTES:
                    return bytes(out), "larger than the size cap"
                member, problems = _unwrap(archive.read(info))
                out += member + b"\n"
                if problems:
                    return bytes(out), "a member cannot be read"
    except Exception:  # any failure: report it, never crash, never echo a member name
        return bytes(out), "corrupt or encrypted archive"
    return bytes(out), None


_BOMS = (
    (b"\x00\x00\xfe\xff", "utf-32-be"),
    (b"\xff\xfe\x00\x00", "utf-32-le"),
    (b"\xef\xbb\xbf", "utf-8"),
    (b"\xff\xfe", "utf-16-le"),
    (b"\xfe\xff", "utf-16-be"),
)


def _texts(data: bytes) -> tuple[list[str], str | None]:
    """The text(s) of the bytes, and a problem if they are not entirely text. Compressed data
    embedded after a text prefix is decompressed and scanned too."""
    for bom, encoding in _BOMS:
        if data.startswith(bom):
            text = data[len(bom) :].decode(encoding, errors="replace")
            return [text], None if "\ufffd" not in text else f"invalid {encoding}"
    texts: list[str] = []
    if 0 in data:  # UTF-16/32 without a BOM: every reading that is wholly text in few scripts
        for encoding in ("utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"):
            with contextlib.suppress(UnicodeDecodeError):
                reading = data.decode(encoding)
                if _printable(reading) and _few_scripts(reading):
                    texts.append(reading)
    try:
        texts.append(data.decode("utf-8"))
        problem = None
    except UnicodeDecodeError:
        texts.append(data.decode("utf-8", errors="replace"))  # still scanned, but reported
        problem = None if len(texts) > 1 else "binary or non-UTF-8 content"
    if problem is None and texts and not any(_printable(t, 0.95) for t in texts):
        problem = "binary content"
    for offset in _embedded_streams(data):
        inner, problems = _unwrap(data[offset:])
        texts.extend(_texts(inner)[0])
        problem = problem or (problems[0] if problems else None)
    return texts, problem


def _embedded_streams(data: bytes) -> list[int]:
    """Offsets of gzip streams after the start (text followed by a compressed body)."""
    offsets: list[int] = []
    start = 1
    while len(offsets) < _EMBEDDED:
        found = data.find(b"\x1f\x8b\x08", start)
        if found < 0:
            return offsets
        offsets.append(found)
        start = found + 3
    return offsets


def _few_scripts(text: str) -> bool:
    """Real text uses a few Unicode blocks (Latin and Devanagari, say); binary bytes read as
    UTF-16 scatter over many."""
    return len({ord(c) >> 8 for c in text}) <= 4


def _printable(text: str, share: float = 0.9) -> bool:
    """Mostly printable; a replacement character (an undecodable byte) never counts."""
    if not text:
        return False
    good = sum((c.isprintable() and c != "\ufffd") or c in "\t\n\r" for c in text)
    return good >= share * len(text)


# ---------------------------------------------------------------------- strings and views


class _Pairs(list[tuple[str, Any]]):
    """A JSON object as its key/value pairs: duplicate keys are all kept and scanned."""


_DECODER = json.JSONDecoder(object_pairs_hook=_Pairs)


def _document_strings(raw: str) -> list[str]:
    try:
        return list(_strings(_DECODER.decode(raw)))
    except (ValueError, RecursionError):
        pass
    strings: list[str] = []
    for line in raw.splitlines():
        try:
            strings.extend(_strings(_DECODER.decode(line)))
        except (ValueError, RecursionError):
            strings.append(line)  # not JSON: scan the line's decoded views as text
    return strings


def _strings(node: Any) -> Iterator[str]:
    stack = [node]
    while stack:
        current = stack.pop()
        if isinstance(current, str):
            yield current
        elif isinstance(current, _Pairs):
            for key, value in current:
                yield key
                stack.append(value)
        elif isinstance(current, list):
            stack.extend(current)


def _unescape(text: str) -> str:
    if "\\" not in text:
        return text
    return _ESCAPE.sub(_unescape_one, text)


def _unescape_one(m: re.Match[str]) -> str:
    if m.group(1):  # a run of \xHH: the bytes of UTF-8 text (nginx), else one byte per char
        raw = bytes(int(h, 16) for h in m.group(1).split("\\x")[1:])
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("latin-1")
    for group, base in ((2, 16), (3, 16), (4, 8)):
        if m.group(group):
            value = int(m.group(group), base)
            return chr(value) if value <= 0x10FFFF else m.group(0)
    return _SIMPLE_ESCAPES.get(m.group(5), m.group(5))


def _embedded_json(text: str) -> Iterator[str]:
    """Every string of every JSON document embedded anywhere in ``text`` (a syslog line whose
    payload is JSON), and the content of a JSON string literal; each inner string on its own, so
    the next level is parsed too."""
    stripped = text.strip()
    if stripped.startswith('"'):
        with contextlib.suppress(ValueError, RecursionError):
            inner = json.loads(stripped)
            if isinstance(inner, str):
                yield inner
    if "{" not in text and "[" not in text:
        return
    for m in itertools.islice(re.finditer(r"[{\[]", text), _EMBEDDED):
        try:
            document, _ = _DECODER.raw_decode(text, m.start())
        except (ValueError, RecursionError):
            continue
        yield from _strings(document)


def _base64_payloads(text: str) -> Iterator[str]:
    for m in itertools.islice(_BASE64.finditer(text), _EMBEDDED):
        token = m.group(0).rstrip("=").replace("-", "+").replace("_", "/")
        try:  # padding as it should be, whatever was written (none, too little, too much)
            raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        yield from _readable(raw)


def _hex_payloads(text: str) -> Iterator[str]:
    for m in itertools.islice(_HEX_RUN.finditer(text), _EMBEDDED):
        yield from _readable(bytes.fromhex(m.group(0)))


def _readable(raw: bytes) -> Iterator[str]:
    """Bytes as text, if they are text (UTF-8, else UTF-16LE: PowerShell -enc), after
    decompressing them if they are compressed (a base64 gzip body in a cassette). NULs, which
    separate auditd's arguments, read as spaces."""
    if _compression(raw) is not None:
        raw, _problems = _unwrap(raw)
    for encoding in ("utf-8", "utf-16-le"):  # both: UTF-16LE ASCII is also valid UTF-8
        try:
            decoded = raw.decode(encoding).replace("\x00", " ")
        except UnicodeDecodeError:
            continue
        if len(decoded.strip()) >= 4 and _printable(decoded):
            yield decoded


def _single(decode: Callable[[str], str]) -> Callable[[str], Iterator[str]]:
    def run(text: str) -> Iterator[str]:
        yield decode(text)

    return run


def _nfkc(text: str) -> str:
    """Compatibility forms as plain characters: KELVIN SIGN as K, fullwidth letters as ASCII."""
    return unicodedata.normalize("NFKC", text)


_CHAIN_PLUS: tuple[Callable[[str], str], ...] = (html.unescape, unquote_plus, _unescape, _nfkc)
_CHAIN: tuple[Callable[[str], str], ...] = (html.unescape, unquote, _unescape, _nfkc)  # keeps '+'
_TEXT_DECODERS: tuple[tuple[str, Callable[[str], Iterator[str]]], ...] = (
    ("url-decoded", _single(unquote)),
    ("url-decoded", _single(unquote_plus)),
    ("html-decoded", _single(html.unescape)),
    ("escape-decoded", _single(_unescape)),
    ("normalized", _single(_nfkc)),
)
_DECODERS: tuple[tuple[str, Callable[[str], Iterator[str]]], ...] = (
    *_TEXT_DECODERS,
    ("nested-json", _embedded_json),
    ("base64-decoded", _base64_payloads),
    ("hex-decoded", _hex_payloads),
)


def _fixed_point(text: str, chain: tuple[Callable[[str], str], ...]) -> str:
    for _ in range(_FIXED_POINT_ROUNDS):
        decoded = text
        for decode in chain:
            decoded = decode(decoded)
        if decoded == text:
            return text
        text = decoded
    return text


def _views(value: str) -> Iterator[tuple[str, str]]:
    """Distinct decoded forms of ``value``: the fixed points of the decoder chains first (any
    depth, any mix), then single decoders breadth-first, each new view decoded again, within a
    budget of views and characters."""
    seen = {value}
    queue: deque[str] = deque([value])
    queued = {value}
    budget = 8 * len(value) + 65_536
    views = 0
    for form, decode in _TEXT_DECODERS:  # one step of each text decoder, under its own name
        view = next(decode(value))
        if view not in seen:
            seen.add(view)
            yield form, view
    for chain in (_CHAIN_PLUS, _CHAIN):
        view = _fixed_point(value, chain)
        if view not in queued:  # also when a one-step view showed it: base64 behind one %2B
            queued.add(view)
            queue.append(view)
        if view not in seen:
            seen.add(view)
            yield "decoded", view
    while queue and views < _MAX_VIEWS and budget > 0:
        text = queue.popleft()
        for form, decode in _DECODERS:
            for view in decode(text):
                if view in seen or views >= _MAX_VIEWS or budget <= 0:
                    continue
                seen.add(view)
                views += 1
                budget -= len(view)
                queue.append(view)
                yield form, view
                for chain in (_CHAIN_PLUS, _CHAIN):
                    deep = _fixed_point(view, chain)
                    if deep not in seen:
                        seen.add(deep)
                        queue.append(deep)
                        yield form, deep


def _alternation(
    items: list[str], before: str, after: str, render: Any = re.escape
) -> re.Pattern[str] | None:
    if not items:
        return None
    body = "|".join(render(i) for i in sorted(items, key=lambda i: (-len(i), i)))
    return re.compile(f"{before}(?:{body}){after}", re.IGNORECASE)
