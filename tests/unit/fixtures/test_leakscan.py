"""Boundaries of the leak scanner (found missing by mutation testing; all values synthetic)."""

from __future__ import annotations

import base64
import bz2
import dataclasses
import gzip
import io
import json
import lzma
import re
import zipfile
import zlib
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote

import pytest

from argus.fixtures import LeakScanner, leakscan


@pytest.mark.parametrize(
    ("name", "text", "found"),
    [
        ("META", "META", True),
        ("META", "meta", False),  # an all-capital code of up to 4 letters: its own case only
        ("CSE", "Cse", False),
        ("NORTH", "north wing", True),  # 5 letters: any case, like every other name
        ("NORTH", "North", True),
        ("META1", "meta1", True),  # not letters only: any case
    ],
)
def test_short_all_capital_codes_match_in_their_own_case_only(
    name: str, text: str, found: bool
) -> None:
    assert bool(LeakScanner([name]).scan_text(text)) is found


@pytest.mark.parametrize("escape", ["\\t", "\\n", "\\r", "\\b", "\\f"])
def test_a_name_behind_an_escape_is_found(escape: str) -> None:
    """``\\balice`` reads as one word ``balice`` until the escape is decoded."""
    scanner = LeakScanner(["alice"])
    assert not scanner.scan_document("x balice", "f")
    assert [leak.form for leak in scanner.scan_document(f"x {escape}alice", "f")] == [
        "escape-decoded"
    ]


def test_decoding_to_a_fixed_point_stops_after_16_rounds() -> None:
    text = "a b"
    for _ in range(17):
        text = quote(text, safe="")
    assert leakscan._fixed_point(text, (unquote,)) == quote("a b", safe="")
    assert leakscan._fixed_point(unquote(text), (unquote,)) == "a b"


def test_at_most_64_payloads_per_string_are_decoded() -> None:
    payloads = [f"payload number {i:03d}".encode() for i in range(70)]
    base64_runs = " ".join(base64.b64encode(p).decode() for p in payloads)
    hex_runs = " ".join(p.hex() for p in payloads)
    assert len(list(leakscan._base64_payloads(base64_runs))) == 64
    assert len(list(leakscan._hex_payloads(hex_runs))) == 64


def test_at_most_64_single_decoder_views_per_string() -> None:
    # odd byte lengths: no UTF-16 reading, so each run gives exactly one view
    value = " ".join(
        base64.b64encode(f"base64 payload {i:04d}".encode()).decode() for i in range(40)
    )
    value += " " + " ".join(f"hex payloads {i:04d}".encode().hex() for i in range(40))
    forms = [form for form, _ in leakscan._views(value)]
    assert forms.count("base64-decoded") + forms.count("hex-decoded") == 64


def test_a_stream_past_the_size_cap_is_unscannable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(leakscan, "_MAX_BYTES", 1000)
    small, large = tmp_path / "small.json.gz", tmp_path / "large.json.gz"
    small.write_bytes(gzip.compress(b'{"m": "' + b"x" * 900 + b'"}'))
    large.write_bytes(gzip.compress(b'{"m": "' + b"x" * 1000 + b'"}'))
    assert LeakScanner(["alice"]).scan_file(small) == []
    (leak,) = LeakScanner(["alice"]).scan_file(large)
    assert leak.form == "unscannable: gzip: larger than the size cap"


def test_identifiers_shorter_than_two_characters_are_ignored() -> None:
    scanner = LeakScanner(["a", " b ", " ", "", "EE", " EE ", "cd"])
    assert scanner.size == 2  # EE and cd, each once
    assert scanner.scan_text("a b") == []
    assert scanner.scan_text("EE")
    assert scanner.scan_text("cd")


def test_a_stream_nested_past_four_layers_is_unscannable(tmp_path: Path) -> None:
    data = b'{"m": "alice"}'
    for layers in range(1, 6):
        data = gzip.compress(data)
        path = tmp_path / f"{layers}.gz"
        path.write_bytes(data)
        forms = [leak.form for leak in LeakScanner(["alice"]).scan_file(path)]
        if layers <= 4:
            assert forms == ["raw", "json"], layers
        else:
            assert forms, layers
            assert all(f.startswith("unscannable") for f in forms), forms


def test_a_leak_is_frozen_and_never_prints_its_identifier() -> None:
    leak = leakscan.Leak("f.json", "alice", "raw")
    with pytest.raises(dataclasses.FrozenInstanceError):
        leak.form = "json"  # type: ignore[misc]
    assert str(leak) == "f.json: denylisted identifier (5 chars) in raw text"
    assert "alice" not in repr(leak)
    unread = leakscan.Leak("f.gz", "", "unscannable: gzip: larger than the size cap")
    assert str(unread) == (
        "f.gz: cannot be scanned completely (unscannable: gzip: larger than the size cap)"
    )


# ---------------------------------------------------------------------- names


@pytest.mark.parametrize(
    ("name", "text", "hits"),
    [
        ("abc$", "host abc here", ["abc"]),  # 3 characters inside the punctuation: found bare
        ("$ab", "host ab here", []),  # fewer: only as written
        ("$ab", "host $ab here", ["$ab"]),
        ("$ %", "x $ % y", ["$ %"]),  # nothing alphanumeric at all: as written
    ],
)
def test_a_name_with_edge_punctuation(name: str, text: str, hits: list[str]) -> None:
    assert LeakScanner([name]).scan_text(text) == hits


def test_several_names_with_edge_punctuation() -> None:
    assert LeakScanner(["$ab", "#cd"]).scan_text("$ab and #cd") == ["$ab", "#cd"]


def test_a_name_inside_a_found_name_is_not_reported_again() -> None:
    scanner = LeakScanner(["lab-pc07", "pc07"])
    assert scanner.scan_text("lab-pc07 pc07") == ["lab-pc07", "pc07"]


def test_only_the_longest_phrase_with_the_same_first_word_is_reported() -> None:
    scanner = LeakScanner(["north wing", "north wing annex"])
    assert scanner.scan_text("north wing annex") == ["north wing annex"]


def test_phrases_found_at_one_place_are_reported_longest_first_word_first() -> None:
    scanner = LeakScanner(["north wing", "northwing annex"])
    assert scanner.scan_text("northwing annex") == ["northwing annex", "northwing"]


def test_a_phrase_after_a_character_that_lower_cases_to_two() -> None:
    """``İ`` lower-cases to two characters: offsets in the lower-cased text shift."""
    assert LeakScanner(["north wing"]).scan_text("İ north wing") == ["north wing"]


def test_a_file_name_is_also_read_with_underscores_as_separators() -> None:
    assert LeakScanner(["lab-pc07"]).scan_name("lab_pc07.json") == ["lab-pc07"]
    assert LeakScanner(["lab.pc07"]).scan_name("lab_pc07.json") == ["lab.pc07"]
    assert LeakScanner(["north wing"]).scan_name("north_wing") == [
        "north_wing",
        "north-wing",
        "north.wing",
        "north wing",
    ]
    assert LeakScanner(["lab-pc07"]).scan_name("lab-pc07") == ["lab-pc07"]  # read once


# ---------------------------------------------------------------------- addresses


@pytest.mark.parametrize(
    ("ident", "text"),
    [
        ("1.2.3.4", "001.002.003.004"),
        ("10.1.2.255", "010.001.002.255"),
        ("fd00::5", "FD00:0:0:0:0:0:0:5"),  # IPv6 that starts with a letter
    ],
)
def test_a_denylisted_address_is_found_in_another_spelling(ident: str, text: str) -> None:
    assert LeakScanner([ident]).scan_text(text) == [text]


@pytest.mark.parametrize(
    "name",
    [
        "10.1.2",
        "10.1.2.256",
        "10.1.2.0003",
        "10.1.2.3/33",
        "10.1.2.3X",
        "fd00::5X",
        "3rd-floor-lab",
        "svc:backup",
    ],
)
def test_what_only_looks_like_an_address_is_a_name_found_as_written(name: str) -> None:
    assert leakscan._canonicals(name) == []
    assert LeakScanner([name]).scan_text(name) == [name]


def test_a_site_prefix_may_be_written_with_host_bits() -> None:
    assert LeakScanner([], ["10.1.2.3/24"]).scan_text("10.1.2.200") == ["10.1.2.200"]


def test_an_address_in_interface_notation_names_its_network() -> None:
    assert LeakScanner(["10.1.2.0/24"]).scan_text("10.1.2.3/24") == ["10.1.2.3"]


def test_an_address_hit_is_reported_as_written() -> None:
    scanner = LeakScanner(["10.1.2.3"])
    assert scanner.scan_text("host 10-1-2-3 up") == ["10-1-2-3"]
    assert scanner.scan_text("ptr 3.2.1.10.in-addr.arpa") == ["3.2.1.10.in-addr.arpa"]


def test_an_integer_address_in_a_url_is_at_most_32_bits() -> None:
    scanner = LeakScanner([], ["0.0.0.0/0"])
    assert scanner.scan_text("http://4294967295/ http://4294967296/") == ["4294967295"]


def test_reverse_dns_octets_are_at_most_255() -> None:
    assert LeakScanner(["10.1.2.255"]).scan_text("255.2.1.10.in-addr.arpa") == [
        "255.2.1.10.in-addr.arpa"
    ]
    assert LeakScanner(["10.1.2.3"]).scan_text("256.2.1.10.in-addr.arpa") == []


def test_reverse_dns_for_ipv6_names_a_network_of_4_bits_a_nibble() -> None:
    ptr = "2.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
    assert LeakScanner(["2001:db8:1:2::/64"]).scan_text(f"ptr {ptr}") == [ptr]


@pytest.mark.parametrize(
    "text",
    [
        "::ffff:a01:203",  # IPv4-mapped, in hex
        "64:ff9b::a01:203",  # NAT64
        "2002:a01:203::1",  # 6to4
        "2001:0:4136:e378:8000:63bf:f5fe:fdfc",  # Teredo: the client address is inverted
    ],
)
def test_ipv4_inside_ipv6_is_found(text: str) -> None:
    assert LeakScanner(["10.1.2.3"]).scan_text(text) == [text]


# ---------------------------------------------------------------------- files


def _forms(tmp_path: Path, data: bytes) -> list[str]:
    path = tmp_path / "f.bin"
    path.write_bytes(data)
    return [leak.form for leak in LeakScanner(["alice"]).scan_file(path)]


def _zipped(data: bytes, name: str = "f.json") -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, data)
    return buffer.getvalue()


def _bad_checksum(member: bytes) -> bytes:
    return member[:-8] + bytes([member[-8] ^ 1]) + member[-7:]


@pytest.mark.parametrize(
    ("data", "kind"),
    [
        (b"\x1f\x8b", "gzip"),
        (b"\x78\x9c", "zlib"),  # a bare two-byte zlib header
        (b"\x78\x01", "zlib"),
        (b"\x78\xda", "zlib"),
        (b"BZh", "bzip2"),
        (b"\xfd7zXZ\x00", "xz"),
        (b"PK\x03\x04", "zip"),
        (b"\x28\xb5\x2f\xfd", "zstd"),
        (b"\x78", None),
        (b"xyz", None),  # text that starts with x: no zlib header
        (b"\x9c\x78", None),
        (b"{}", None),
    ],
)
def test_compression_is_recognised_by_content(data: bytes, kind: str | None) -> None:
    assert leakscan._compression(data) == kind


@pytest.mark.parametrize(
    "compress",
    [gzip.compress, zlib.compress, bz2.compress, lzma.compress, _zipped],
    ids=["gzip", "zlib", "bzip2", "xz", "zip"],
)
def test_every_supported_compression_is_read(tmp_path: Path, compress: Any) -> None:
    assert _forms(tmp_path, compress(b'{"m": "alice"}')) == ["raw", "json"]


def test_an_unsupported_compression_is_reported_once(tmp_path: Path) -> None:
    assert _forms(tmp_path, b"\x28\xb5\x2f\xfd" + b"abc") == [
        "unscannable: zstd: not supported",
        "unscannable: binary or non-UTF-8 content",
    ]


def test_an_unscannable_file_report_names_no_identifier(tmp_path: Path) -> None:
    path = tmp_path / "f.json.gz"
    path.write_bytes(gzip.compress(b'{"m": "x"}')[:-4])
    assert LeakScanner(["alice"]).scan_file(path, "f.json.gz") == [
        leakscan.Leak("f.json.gz", "", "unscannable: gzip: truncated stream")
    ]


_MEMBER = gzip.compress(b"x" * 10)


@pytest.mark.parametrize(
    ("data", "result"),
    [
        (_MEMBER + _MEMBER, (b"x" * 20, None)),  # concatenated members
        (_bad_checksum(_MEMBER), (b"", "corrupt stream")),
        (_MEMBER + _bad_checksum(_MEMBER), (b"x" * 10, "corrupt stream")),  # the first is kept
        (_MEMBER[:-4], (b"x" * 10, "truncated stream")),
        (_MEMBER + b"junk", (b"x" * 10, "trailing data after the stream")),
    ],
    ids=["members", "corrupt", "corrupt-second", "truncated", "trailing"],
)
def test_what_a_broken_stream_yields(data: bytes, result: tuple[bytes, str | None]) -> None:
    assert leakscan._decompress("gzip", data) == result


def test_a_stream_is_read_up_to_the_size_cap_and_no_further(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Past the cap nothing more is read, so a bad checksum after it is never reached."""
    monkeypatch.setattr(leakscan, "_MAX_BYTES", 1000)
    assert leakscan._decompress("gzip", gzip.compress(b"x" * 1000)) == (b"x" * 1000, None)
    assert leakscan._decompress("gzip", gzip.compress(b"x" * 1001)) == (
        b"x" * 1000,
        "larger than the size cap",
    )
    data = gzip.compress(b"x" * 600) + _bad_checksum(gzip.compress(b"y" * 402))
    assert leakscan._decompress("gzip", data) == (
        b"x" * 600 + b"y" * 400,
        "larger than the size cap",
    )


def test_a_zip_member_name_is_scanned_like_its_content(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("alice.json", b'{"m": "x"}')
        archive.writestr("b.json", b'{"m": "alice"}')
    assert _forms(tmp_path, buffer.getvalue()) == ["raw", "raw", "json", "json"]


def test_a_zip_that_cannot_be_read_completely_is_unscannable(tmp_path: Path) -> None:
    broken_member = _zipped(gzip.compress(b'{"m": "alice"}')[:-4], "f.json.gz")
    assert _forms(tmp_path, broken_member) == [
        "unscannable: zip: a member cannot be read",
        "raw",
        "json",
    ]
    assert _forms(tmp_path, b"PK\x03\x04" + b"junk" * 10) == [
        "unscannable: zip: corrupt or encrypted archive",
        "unscannable: binary content",
    ]


def test_a_zip_past_the_size_cap_is_unscannable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(leakscan, "_MAX_BYTES", 1000)
    assert _forms(tmp_path, _zipped(b"x" * 993)) == []  # with "f.json\n": 1000 bytes
    assert _forms(tmp_path, _zipped(b"x" * 994)) == ["unscannable: zip: larger than the size cap"]


@pytest.mark.parametrize(
    ("bom", "encoding"),
    [
        (b"\x00\x00\xfe\xff", "utf-32-be"),
        (b"\xff\xfe\x00\x00", "utf-32-le"),
        (b"\xef\xbb\xbf", "utf-8"),
        (b"\xff\xfe", "utf-16-le"),
        (b"\xfe\xff", "utf-16-be"),
    ],
    ids=["utf-32-be", "utf-32-le", "utf-8", "utf-16-le", "utf-16-be"],
)
def test_a_file_with_a_byte_order_mark(tmp_path: Path, bom: bytes, encoding: str) -> None:
    assert _forms(tmp_path, bom + '{"m": "alice"}'.encode(encoding)) == ["raw", "json"]
    assert _forms(tmp_path, bom + "alice ".encode(encoding) + b"\xff") == [
        f"unscannable: invalid {encoding}",
        "raw",
        "json",
    ]


@pytest.mark.parametrize("encoding", ["utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"])
def test_a_file_in_utf16_or_utf32_without_a_byte_order_mark(tmp_path: Path, encoding: str) -> None:
    text = '{"m": "alice", "n": "café"}'  # é: the bytes are not UTF-8
    assert _forms(tmp_path, text.encode(encoding)) == ["raw", "json"]


def test_bytes_that_read_as_utf16_in_many_scripts_are_not_text(tmp_path: Path) -> None:
    pairs = enumerate([0xFF, 0x00, 0x10, 0x20, 0x30, 0x40, 0x50])
    data = b"".join(bytes([low, 0x4E + i]) for i, low in pairs)  # 7 blocks in either order
    assert _forms(tmp_path, data) == ["unscannable: binary or non-UTF-8 content"]


@pytest.mark.parametrize(
    ("data", "forms"),
    [
        ("alice café".encode("latin-1"), ["unscannable: binary or non-UTF-8 content"]),
        (b"\x01\x02\x03\x04alice", ["unscannable: binary content"]),
        (
            b"HTTP/1.1 200 OK\r\n\r\n" + gzip.compress(b'{"m": "alice"}'),
            ["unscannable: binary or non-UTF-8 content"],
        ),
    ],
    ids=["latin-1", "control-characters", "text-then-gzip"],
)
def test_a_file_that_is_not_all_text_is_reported_and_still_scanned(
    tmp_path: Path, data: bytes, forms: list[str]
) -> None:
    assert _forms(tmp_path, data) == [*forms, "raw", "json"]


def test_a_broken_stream_inside_utf16_text_is_reported(tmp_path: Path) -> None:
    """The file reads as UTF-16 text (so it is not binary), but its gzip stream is cut off."""
    header = b"\x1f\x8b\x08\x00" + b"A\x00A\x00" + b" \x00"  # no flags; mtime, xfl and os
    stored = b"\x01\x00\x01\xff\xfe"  # a final stored block of 256 bytes: only 9 follow
    data = "a compressed body follows for alice: ".encode("utf-16-le") + header + stored
    data += b"\x00" + "note".encode("utf-16-le")
    # the stream's bytes 01 FF read as U+FF01 (fullwidth "!"): the NFKC view differs, finds it too
    assert _forms(tmp_path, data) == [
        "unscannable: gzip: truncated stream",
        "raw",
        "json",
        "normalized",
    ]


def test_gzip_streams_after_the_start_are_found_at_most_64() -> None:
    magic = b"\x1f\x8b\x08"
    assert leakscan._embedded_streams(magic + b"x") == []  # at the start: unwrapped already
    assert leakscan._embedded_streams(b"x" + magic * 3) == [1, 4, 7]
    assert len(leakscan._embedded_streams(b"x" + magic * 70)) == 64


def test_text_uses_at_most_four_unicode_blocks() -> None:
    assert leakscan._few_scripts("a\u0105\u03b1\u0434")  # Latin, Latin Extended-A, Greek, Cyrillic
    assert not leakscan._few_scripts("a\u0105\u03b1\u0434\u05d0")  # and Hebrew


def test_printable_means_at_least_the_given_share() -> None:
    assert leakscan._printable("abcdefghi\x00")  # 9 of 10
    assert not leakscan._printable("abcdefghi\x00", 0.95)
    assert not leakscan._printable("�" * 9 + "a")  # a replacement character never counts
    assert leakscan._printable("\t\n\r" * 3 + "a")


# ---------------------------------------------------------------------- strings and views


def test_every_key_and_string_of_a_json_document_is_scanned() -> None:
    strings = leakscan._document_strings('{"a": ["b", {"c": "d"}], "a": "e", "n": [1, null]}')
    assert sorted(strings) == ["a", "a", "b", "c", "d", "e", "n"]  # duplicate keys kept


def test_a_pretty_printed_json_document_is_parsed_as_a_whole() -> None:
    leaks = LeakScanner(["alice"]).scan_document('{\n  "m": "al\\u0069ce"\n}', "f")
    assert [leak.form for leak in leaks] == ["json"]


@pytest.mark.parametrize(
    ("text", "strings"),
    [
        ('log {"user": "alice"}', ["user", "alice"]),
        ('list ["alice"]', ["alice"]),
        ('{"a": "b"} and {"c": "d"}', ["a", "b", "c", "d"]),
        ('"quoted \\"alice\\""', ['quoted "alice"']),  # a JSON string literal
        ("no json here", []),
    ],
)
def test_json_embedded_in_a_string(text: str, strings: list[str]) -> None:
    assert list(leakscan._embedded_json(text)) == strings


@pytest.mark.parametrize(
    ("escaped", "decoded"),
    [
        ("\\x61lice", "alice"),
        ("caf\\xc3\\xa9", "café"),  # \x runs are UTF-8 bytes
        ("caf\\xe9", "café"),  # unless they are not: then one byte per character
        ("\\u0061lice", "alice"),
        ("\\U00000061lice", "alice"),
        ("\\141lice", "alice"),  # octal
        ("\\U0010FFFF", "\U0010ffff"),
        ("\\U00110000", "\\U00110000"),  # past Unicode: kept as written
        ("a\\tb\\nc\\rd\\be\\ff", "a\tb\nc\rd\be\ff"),
        ('\\/\\"\\\\', '/"\\'),
    ],
)
def test_escapes_decode_exactly(escaped: str, decoded: str) -> None:
    assert leakscan._unescape(escaped) == decoded


@pytest.mark.parametrize("token", ["PDxhbGljZT4+Pz8/", "PDxhbGljZT4-Pz8_"], ids=["std", "url"])
def test_base64_in_either_alphabet_is_decoded(token: str) -> None:
    assert "<<alice>>???" in leakscan._base64_payloads(f"t={token}")


@pytest.mark.parametrize("text", ["alice is here", "alice is here!", "alice is here ok"])
def test_base64_without_its_padding_is_decoded(text: str) -> None:
    token = base64.b64encode(text.encode()).decode().rstrip("=")  # 18, 19 and 22 characters
    assert text in leakscan._base64_payloads(token)


@pytest.mark.parametrize(
    ("raw", "texts"),
    [
        (gzip.compress(b"alice is here"), ["alice is here"]),  # decompressed first
        (b"cat\x00/home/alice/notes", ["cat /home/alice/notes"]),  # NULs read as spaces
        (b"abcd", ["abcd"]),
        (b"abc", []),  # shorter than 4 characters
    ],
)
def test_decoded_bytes_are_text_only_if_readable(raw: bytes, texts: list[str]) -> None:
    assert list(leakscan._readable(raw)) == texts


@pytest.mark.parametrize(
    ("value", "forms"),
    [
        ("%61lice", ["url-decoded"]),
        ("%61lice+x", ["url-decoded", "url-decoded"]),  # with '+' kept, then read as a space
        ("&#97;lice", ["html-decoded"]),
        ("\\u0061lice", ["escape-decoded"]),
        ("%2561lice", ["decoded"]),  # encoded twice: only the fixed point shows it
        ('log {"u": "alice"}', ["raw", "json", "nested-json"]),
        ("YWxpY2UgaXMgaGVyZQ==", ["base64-decoded"]),
        (b"alice is here!!".hex(), ["hex-decoded"]),
    ],
)
def test_a_leak_names_the_decoding_that_showed_it(value: str, forms: list[str]) -> None:
    leaks = LeakScanner(["alice"]).scan_document(json.dumps({"m": value}), "f")
    assert [leak.form for leak in leaks] == forms


_ALICE_BASE64 = base64.urlsafe_b64encode(b"alice is here").decode()


@pytest.mark.parametrize(
    "value",
    [
        "Y%2557xpY2UgaXMgaGVyZQ==",  # the fixed point of the string is base64
        base64.urlsafe_b64encode(_ALICE_BASE64.encode()).decode(),  # base64 twice
        base64.urlsafe_b64encode(b"%2561lice is here").decode(),  # a payload encoded twice
        base64.urlsafe_b64encode(b"Y%2557xpY2UgaXMgaGVyZQ==").decode(),  # and base64 in that
    ],
    ids=["fixed-point", "base64-twice", "payload-encoded-twice", "base64-in-that"],
)
def test_what_a_decoding_shows_is_decoded_again(value: str) -> None:
    leaks = LeakScanner(["alice"]).scan_document(json.dumps({"m": value}), "f")
    assert [leak.form for leak in leaks] == ["base64-decoded"]


def _bzip2_base64(text: str) -> str:
    return base64.urlsafe_b64encode(bz2.compress(text.encode())).decode()


def _budget_filled(head: str, tail: str, spare: int) -> tuple[str, int]:
    """The payloads of ``head`` and of a filler, then ``tail``: the filler sized so that once the
    views of both payloads are taken, ``spare`` characters of the budget are left (and with no
    run of hex digits, which would add a view). Returns the string and the filler's length."""
    for extra in range(64):  # the payload grows in steps of 4 characters: try other fillers
        size = 30_000
        for _ in range(10):
            filler = "aب" + "c" * extra + "b" * size
            value = f"{_bzip2_base64(head)} {_bzip2_base64(filler)}{tail}"
            left = 8 * len(value) + 65_536 - len(head) - len(filler)
            if left == spare:
                break
            size += left - spare
        if left == spare and not re.search("[0-9A-Fa-f]{16}", value):
            return value, len(filler)
    raise AssertionError("no filler fits the budget")


@pytest.mark.parametrize("nested", [False, True], ids=["same-string", "next-string"])
@pytest.mark.parametrize("spare", [0, 1])
def test_views_stop_once_their_characters_use_up_the_budget(nested: bool, spare: int) -> None:
    """The budget is 8 characters per character of the string plus 65,536; a payload counts
    with its decompressed length. After two payloads come 13 more characters (in the same
    string, or inside the first payload): only a budget left shows them. ``ب`` keeps every
    payload from also reading as UTF-16."""
    head = "aب" + ("." * 30_000 + " " + _ALICE_BASE64 if nested else "a" * 30_000)
    value, filler = _budget_filled(head, "" if nested else " " + _ALICE_BASE64, spare)
    views = [len(view) for _, view in leakscan._views(value)]
    assert views == [len(head), filler, *([13] if spare else [])]


# ---------------------------------------------------------------- misses fixed at the R2 gate


@pytest.mark.parametrize(
    "value",
    [
        "https://www.example.com/r?q=PDxhbGljZT4%2BPz8%2F",  # base64 behind one %2B and %2F
        "Y%57xpY2UgaXMgaGVyZQ==",  # behind one %XX
        "&#89;WxpY2UgaXMgaGVyZQ==",  # behind one HTML entity
        "\\u0059WxpY2UgaXMgaGVyZQ==",  # behind one \u escape
        "YWxpY2UgaXMgaGVyZSE==",  # with more padding than it needs
        "\uff41\uff4c\uff49\uff43\uff45",  # fullwidth letters
    ],
    ids=["percent-plus", "percent", "entity", "escape", "over-padded", "fullwidth"],
)
def test_a_name_behind_an_encoding_and_base64_is_found(value: str) -> None:
    assert LeakScanner(["alice"]).scan_document(json.dumps({"v": value}), "f")


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("Émile Hall", "visitor Émile Hall at gate"),
        ("Åsa Berg", "x åsa  berg"),
        ("(North Wing", "at (North Wing)"),
    ],
)
def test_a_phrase_that_starts_before_its_first_ascii_word_is_found(name: str, text: str) -> None:
    assert LeakScanner([name]).scan_text(text)


def test_a_digit_that_is_no_decimal_digit_makes_a_name_not_a_crash() -> None:
    scanner = LeakScanner(["1.2.3.²"])  # superscript two: isdigit(), but int() refuses it
    assert scanner.size == 1
    assert scanner.scan_text("x 1.2.3.² y")


def test_a_bracketed_address_in_the_denylist_is_found_in_any_spelling() -> None:
    assert LeakScanner(["[10.1.2.3]"]).scan_text("host 010.001.002.003")


def test_a_compatibility_character_does_not_hide_a_name() -> None:
    """KELVIN SIGN lower-cases to k, so "ab\u212acd" reads as "abkcd" only once normalised."""
    assert LeakScanner(["abkcd", "ab-xyz"]).scan_document("x ab\u212acd", "f")


@pytest.mark.parametrize(
    ("listed", "text"),
    [
        ("2001:db8:1:2:3:4:5::", "x 2001:db8:1:2:3:4:5:0 y"),
        ("::2:3:4:5:6:7:8", "z 0:2:3:4:5:6:7:8"),
    ],
)
def test_ipv6_with_seven_groups_and_a_double_colon_is_an_address(listed: str, text: str) -> None:
    assert LeakScanner([listed]).scan_text(text)


def test_a_base64_token_that_ends_in_x_is_decoded_whole() -> None:
    """Only the padding is stripped before re-padding: X is a base64 digit. Here it carries the
    last letter of the name (W), so dropping it would hide the name."""
    token = base64.b64encode(b"host: kioskW").decode()
    assert token == "aG9zdDoga2lvc2tX"
    leaks = LeakScanner(["kioskW"]).scan_document(json.dumps({"v": token}), "f")
    assert [leak.form for leak in leaks] == ["base64-decoded"]


def test_a_name_hidden_by_a_compatibility_character_is_found_only_once_normalised() -> None:
    """The word index reads "ab\u212acd" as the word ab (KELVIN SIGN is no ASCII letter), which
    begins no name of that length: only the NFKC view shows abkcd."""
    leaks = LeakScanner(["abkcd", "ab-xyz"]).scan_document("x ab\u212acd", "f")
    assert [leak.form for leak in leaks] == ["normalized"]
