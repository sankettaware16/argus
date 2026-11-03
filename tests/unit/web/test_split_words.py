"""The words the pages use for a split (D-211): the source's event names the case the
investigations went to and keeps the person's reason apart from ARGUS's sentence; the target's
opening and linking name where they came from; an event that names a case this page cannot find
still reads."""

from __future__ import annotations

import uuid

from argus.web import casepages

NAMES = {7: "Mina"}
OTHER = uuid.UUID(int=9)


def test_the_source_says_where_the_investigations_went_and_why() -> None:
    said, detail = casepages.event_words(
        "unlinked", {"target": str(OTHER), "reason": "two separate devices"}, "Mina", NAMES,
        {str(OTHER): 12},
    )  # fmt: skip
    assert said == "Mina moved investigations to case 12"
    assert detail == "two separate devices"


def test_the_target_says_where_they_came_from() -> None:
    numbers = {str(OTHER): 6}
    opened, _ = casepages.event_words("opened", {"split_from": str(OTHER)}, "Mina", NAMES, numbers)
    assert opened == "Mina opened the case with investigations moved from case 6"
    linked, _ = casepages.event_words("linked", {"split_from": str(OTHER)}, "Mina", NAMES, numbers)
    assert linked == "Mina moved investigations here from case 6"
    plain, _ = casepages.event_words("linked", {}, "Mina", NAMES, numbers)
    assert plain == "Mina linked more of its investigations or indicators"
    assert casepages.event_words("opened", {}, "Mina", NAMES)[0] == "Mina opened the case"


def test_a_case_the_page_cannot_find_is_another_case() -> None:
    said, _ = casepages.event_words("unlinked", {"target": str(OTHER), "reason": "x"}, "Mina",
                                    NAMES)  # fmt: skip
    assert said == "Mina moved investigations to another case"
    said, _ = casepages.event_words("unlinked", {}, "Mina", NAMES)
    assert said == "Mina moved investigations to another case"


def test_the_case_a_split_names_is_read_from_the_event_that_names_it() -> None:
    assert casepages._other_case("unlinked", {"target": "t", "split_from": "s"}) == "t"
    assert casepages._other_case("opened", {"target": "t", "split_from": "s"}) == "s"
    assert casepages._other_case("merge_requested", {"target": "t"}) is None
    assert casepages._other_case("unlinked", {"target": 5}) is None
