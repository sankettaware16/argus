"""AR2c (D-168, D-170): the registered parent of a name, from the Public Suffix List snapshot that
ships with the package. The rules (ICANN and private sections) are the list's own; nothing is
fetched, and a name is reduced the same way for any prefix of labels.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.outside import psl
from argus.outside.psl import parse, public_suffix, registered_parent

SMALL = parse(
    """
// a comment
com
co.uk
*.ck
!www.ck
公司.cn
github.io   // trailing comment is not part of the rule

blogspot.com
"""
)


# -- the bundled snapshot -----------------------------------------------------------------------


def test_the_bundled_snapshot_is_the_list_with_both_sections() -> None:
    text = psl.LIST_PATH.read_text(encoding="utf-8")
    assert "// VERSION: 2" in text  # the snapshot says which version it is
    assert "// ===BEGIN ICANN DOMAINS===" in text
    assert "// ===BEGIN PRIVATE DOMAINS===" in text
    rules = psl.bundled()
    assert len(rules.plain) > 8_000
    for rule in ("com", "co.uk", "workers.dev", "vercel.app", "github.io", "blogspot.com"):
        assert rule in rules.plain
    assert "ck" in rules.wildcard
    assert "www.ck" in rules.exception
    assert psl.bundled() is psl.bundled()  # read once


def test_rules_are_in_the_spelling_names_are_keyed_by() -> None:
    assert all(r == r.lower() and r.isascii() for r in psl.bundled().plain)
    assert "xn--55qx5d.cn" in SMALL.plain  # the Chinese rule, as punycode


# -- the reduction ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "parent"),
    [
        ("example.com", "example.com"),
        ("a.b.example.com", "example.com"),
        ("fast-dns-host.com", "fast-dns-host.com"),
        ("x7g2.fast-dns-host.com", "fast-dns-host.com"),
        ("www.example.co.uk", "example.co.uk"),
        ("a.b.c.example.co.uk", "example.co.uk"),
        ("example.edu", "example.edu"),
        ("mail.cse.example.edu", "example.edu"),
        # a hosting service is a suffix: each customer is a parent of its own
        ("x.workers.dev", "x.workers.dev"),
        ("a.b.workers.dev", "b.workers.dev"),
        ("shop.vercel.app", "shop.vercel.app"),
        ("me.github.io", "me.github.io"),
        ("agora.io", "agora.io"),
        ("edge.sd-rtn.com", "sd-rtn.com"),
        # a name that matches no rule has its last label as the suffix
        ("a.b.zzunknown", "b.zzunknown"),
        ("WWW.Example.COM".lower(), "example.com"),
    ],
)
def test_names_reduce_to_their_registered_parent(name: str, parent: str) -> None:
    assert registered_parent(name) == parent


@pytest.mark.parametrize(
    "name", ["com", "co.uk", "workers.dev", "ac.in", "zzunknown", "", "a..com"]
)
def test_a_suffix_or_a_malformed_name_has_no_parent(name: str) -> None:
    assert registered_parent(name) is None


def test_wildcard_and_exception_rules() -> None:
    assert registered_parent("a.b.ck", SMALL) == "a.b.ck"  # *.ck: "b.ck" is the suffix
    assert registered_parent("b.ck", SMALL) is None
    assert registered_parent("www.ck", SMALL) == "www.ck"  # !www.ck: a name, not a suffix
    assert registered_parent("x.www.ck", SMALL) == "www.ck"
    assert public_suffix("x.www.ck", SMALL) == "ck"
    assert registered_parent("a.b.ck") == "a.b.ck"  # the real list says the same
    assert registered_parent("a.www.ck") == "www.ck"


def test_a_name_in_another_script_is_matched_as_punycode() -> None:
    assert registered_parent("a.xn--55qx5d.cn", SMALL) == "a.xn--55qx5d.cn"
    assert registered_parent("a.b.xn--55qx5d.cn", SMALL) == "b.xn--55qx5d.cn"


def test_the_suffix_is_what_the_parent_adds_a_label_to() -> None:
    assert public_suffix("a.b.example.co.uk") == "co.uk"
    assert public_suffix("a.b.workers.dev") == "workers.dev"
    assert public_suffix("x.zzunknown") == "zzunknown"
    assert public_suffix("") is None


def test_the_private_section_is_a_hosting_services() -> None:
    from argus.outside.psl import under_private_suffix

    for name in ("x.workers.dev", "me.github.io", "a.b.workers.dev", "workers.dev",
                 "tok.scf.usercontent.goog", "shop.vercel.app"):  # fmt: skip
        assert under_private_suffix(name), name
    for name in ("example.com", "mail.example.co.uk", "example.edu", "a.b.zzunknown", "com", "",
                 "a..com"):  # fmt: skip
        assert not under_private_suffix(name), name
    assert "workers.dev" in psl.bundled().private
    assert "co.uk" not in psl.bundled().private
    hosted = "// ===BEGIN PRIVATE DOMAINS===\nhosted.example\n// ===END PRIVATE DOMAINS===\n"
    assert under_private_suffix("a.hosted.example", parse(hosted))
    assert not under_private_suffix("a.hosted.example", parse("hosted.example\n"))  # ICANN


# -- properties ---------------------------------------------------------------------------------

LABEL = st.from_regex(r"[a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?", fullmatch=True)
NAMES = st.lists(LABEL, min_size=2, max_size=6).map(".".join)


@given(NAMES)
def test_the_parent_ends_the_name_and_is_stable(name: str) -> None:
    parent = registered_parent(name)
    if parent is None:
        return
    assert name == parent or name.endswith("." + parent)
    assert parent.count(".") >= 1
    assert registered_parent(parent) == parent  # reducing twice changes nothing


@given(NAMES, LABEL)
def test_a_prefix_does_not_change_the_parent(name: str, prefix: str) -> None:
    parent = registered_parent(name)
    if parent is not None:
        assert registered_parent(f"{prefix}.{name}") == parent


@given(NAMES)
def test_case_does_not_matter(name: str) -> None:
    assert registered_parent(name.upper().lower()) == registered_parent(name)


@given(NAMES)
def test_the_suffix_is_part_of_the_name_and_shorter_than_the_parent(name: str) -> None:
    suffix = public_suffix(name)
    assert suffix is not None
    assert name == suffix or name.endswith("." + suffix)
    parent = registered_parent(name)
    if parent is not None:
        assert parent.endswith("." + suffix)
        assert parent.count(".") == suffix.count(".") + 1
