"""P4-D1 part 2 review F15 (D-285): ``argus discover`` proposes a family's ``ignore_above`` from the
mapping it read, so a proposed family does not carry 256 whatever its keyword fields really hold."""

from __future__ import annotations

import pytest

from argus.discover import propose
from argus.discover.classify import Typed
from argus.gateway.discovery import DiscoverFieldMapping
from argus.site import LogFamily, Role

pytestmark = pytest.mark.unit


def leaf(name: str, **mapping: object) -> dict[str, object]:
    return {name: {"mapping": {name.rsplit(".", 1)[-1]: mapping}}}


def body(*leaves: dict[str, object]) -> dict[str, object]:
    merged: dict[str, object] = {}
    for one in leaves:
        merged.update(one)
    return {"idx": {"mappings": merged}}


def test_the_keyword_limit_is_read_from_the_subfield_or_the_keyword_itself() -> None:
    got = DiscoverFieldMapping.limits(
        body(
            leaf("url.original", type="text",
                 fields={"keyword": {"type": "keyword", "ignore_above": 1024}}),
            leaf("url.path", type="keyword", ignore_above=128),
            leaf("event.action", type="text", fields={"keyword": {"type": "keyword"}}),
            leaf("source.ip", type="ip"),
            leaf("bad", type="keyword", ignore_above=True),
            leaf("zero", type="keyword", ignore_above=0),
        )
    )  # fmt: skip
    assert got == {"url.original": 1024, "url.path": 128}
    assert DiscoverFieldMapping.limits("not a mapping") == {}
    assert DiscoverFieldMapping.limits({"idx": {"mappings": 5}}) == {}


def test_a_family_is_proposed_with_the_smallest_limit_of_the_fields_it_queries() -> None:
    mapped = {
        "url.original": Typed("text", True, 1024),
        "event.action": Typed("text", True, 512),
        "something.else": Typed("text", True, 64),  # not a field the evidence queries
        "source.ip": Typed("ip"),
    }
    assert propose._limit(mapped, {}, Role.PROXY) == 512
    assert propose._limit({}, {}, Role.PROXY) == 256
    assert propose._limit(None, {}, Role.PROXY) == 256
    assert propose._limit({"event.action": Typed("text", True)}, {}, Role.PROXY) == 256
    assert propose._limit({"event.action": Typed("text", True, 8)}, {}, Role.PROXY) == 32
    # a renamed field is the one that counts
    assert (
        propose._limit({"x.url": Typed("keyword", False, 100)}, {"url": "x.url"}, Role.PROXY) == 100
    )


def test_the_yaml_entry_names_a_limit_only_when_it_is_not_the_default() -> None:
    assert "ignore_above" not in propose.family_entry(LogFamily(role=Role.PROXY, pattern="p-*"))
    entry = propose.family_entry(LogFamily(role=Role.PROXY, pattern="p-*", ignore_above=512))
    assert entry["ignore_above"] == 512
