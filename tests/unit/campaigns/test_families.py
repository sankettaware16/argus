"""AR2c (D-168, D-170): domain families. Names are grouped under the registered parent they share;
a family is a candidate for an outside look-up from 3 campus hosts or 20 names; the share of
random-looking labels is a hint, never a verdict.
"""

from __future__ import annotations

import random
import string
import uuid
from math import log2

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.campaigns import families as fam
from argus.campaigns.families import Family, Key, Sighting, candidates, families_of

# -- entropy and random-looking labels ----------------------------------------------------------


def test_entropy_of_simple_texts() -> None:
    assert fam.entropy("") == 0.0
    assert fam.entropy("aaaaaaaa") == 0.0
    assert fam.entropy("abab") == pytest.approx(1.0)
    assert fam.entropy("abcd") == pytest.approx(2.0)
    assert fam.entropy("a" * 7 + "b") == pytest.approx(0.5435644431995964)


@given(st.text(max_size=80))
def test_entropy_is_between_zero_and_the_log_of_the_length(text: str) -> None:
    h = fam.entropy(text)
    assert h >= 0.0
    if text:
        assert h <= log2(len(text)) + 1e-9
    else:
        assert h == 0.0


@pytest.mark.parametrize(
    "label",
    ["a8f3k2m9x1q7", "x7g2b9d4k1m8p3", "dkfjghslqwrt", "q1w2e3r4t5y6", "0a1b2c3d4e5f6a7b"],
)
def test_machine_made_labels_look_random(label: str) -> None:
    assert fam.random_looking(label)


@pytest.mark.parametrize(
    "label",
    ["www", "mail", "internationalization", "windowsupdate", "microsoft", "aaaaaaaaaaaa",
     "cloud-edge-12", "ab_cd_ef_gh12", "api2", "ns1", "download", "", "x" * 3, "1234567890"],
)  # fmt: skip
def test_ordinary_labels_do_not_look_random(label: str) -> None:
    assert not fam.random_looking(label)


@given(st.text(alphabet=string.ascii_letters + string.digits + "-_", max_size=40))
def test_random_looking_is_case_blind_and_never_for_short_or_broken_up_labels(label: str) -> None:
    got = fam.random_looking(label)
    assert got == fam.random_looking(label.lower()) == fam.random_looking(label.upper())
    if len(label) < fam.MIN_RANDOM_LABEL or "-" in label or "_" in label:
        assert not got
    if got:
        text = label.lower()
        assert fam.entropy(text) >= fam.MIN_RELATIVE_ENTROPY * log2(len(text))


def test_a_generator_of_random_labels_is_called_random_most_of_the_time() -> None:
    rnd = random.Random(7)
    labels = [
        "".join(rnd.choices(string.ascii_lowercase + string.digits, k=12)) for _ in range(500)
    ]
    assert sum(fam.random_looking(x) for x in labels) / len(labels) > 0.9
    words = ["download", "support", "internet", "software", "database", "security", "platform"]
    assert not any(fam.random_looking(w) for w in words)


# -- the first label below a parent -------------------------------------------------------------


def test_the_labels_below_a_parent_run_left_to_right() -> None:
    assert fam.labels_below("x7g2.fast-dns-host.com", "fast-dns-host.com") == ["x7g2"]
    assert fam.labels_below("a.b.fast-dns-host.com", "fast-dns-host.com") == ["a", "b"]
    assert fam.labels_below("fast-dns-host.com", "fast-dns-host.com") == []
    assert fam.labels_below("evilfast-dns-host.com", "fast-dns-host.com") == []  # not a suffix


# -- families -----------------------------------------------------------------------------------


def host(n: int) -> Key:
    return ("ip", f"10.1.0.{n}")


def sighting(n: int, names: list[str], h: Key | None = None) -> Sighting:
    return Sighting(
        uuid.UUID(int=n), frozenset() if h is None else frozenset({h}), frozenset(names)
    )


def random_names(n: int, parent: str, seed: int = 1) -> list[str]:
    rnd = random.Random(seed)
    return [
        "".join(rnd.choices(string.ascii_lowercase + string.digits, k=12)) + "." + parent
        for _ in range(n)
    ]


def test_names_are_grouped_under_their_registered_parent() -> None:
    found = families_of(
        [
            sighting(
                1, ["a.fast-dns-host.com", "b.fast-dns-host.com", "www.example.co.uk"], host(1)
            ),
            sighting(2, ["c.fast-dns-host.com", "shop.workers.dev", "x.shop.workers.dev"], host(2)),
            sighting(3, ["com", "co.uk", "workers.dev"], host(3)),  # bare suffixes: no family
        ]
    )
    assert sorted(found) == ["example.co.uk", "fast-dns-host.com", "shop.workers.dev"]
    fast = found["fast-dns-host.com"]
    assert fast.names == {"a.fast-dns-host.com", "b.fast-dns-host.com", "c.fast-dns-host.com"}
    assert fast.hosts == {host(1), host(2)}
    assert fast.investigations == {uuid.UUID(int=1), uuid.UUID(int=2)}
    assert found["shop.workers.dev"].names == {"shop.workers.dev", "x.shop.workers.dev"}
    assert found["shop.workers.dev"].below == 1  # the parent itself has no label below it


def test_a_family_is_a_candidate_from_three_hosts_or_twenty_names() -> None:
    three = families_of([sighting(n, [f"n{n}.example.com"], host(n)) for n in (1, 2, 3)])
    assert three["example.com"].candidate
    assert len(three["example.com"].names) == 3
    two = families_of([sighting(n, [f"n{n}.example.com"], host(n)) for n in (1, 2)])
    assert not two["example.com"].candidate
    many = families_of([sighting(1, random_names(20, "tunnel.example"), host(1))])
    assert many["tunnel.example"].candidate
    assert len(many["tunnel.example"].hosts) == 1
    some = families_of([sighting(1, random_names(19, "tunnel.example"), host(1))])
    assert not some["tunnel.example"].candidate
    assert (fam.MIN_HOSTS, fam.MIN_NAMES) == (3, 20)


def test_a_customer_of_a_hosting_service_is_a_candidate_by_its_names_not_its_devices() -> None:
    """``x.workers.dev`` is one customer of thousands: three devices on its page is ordinary and
    each customer would take a look-up; twenty different names under it is not."""
    three = families_of([sighting(n, [f"n{n}.shop.workers.dev"], host(n)) for n in (1, 2, 3)])
    assert three["shop.workers.dev"].hosted
    assert not three["shop.workers.dev"].candidate
    many = families_of([sighting(1, random_names(20, "shop.workers.dev"), host(1))])
    assert many["shop.workers.dev"].candidate
    plain = families_of([sighting(n, [f"n{n}.shop.example.com"], host(n)) for n in (1, 2, 3)])
    assert not plain["example.com"].hosted
    assert plain["example.com"].candidate


def test_a_name_is_random_when_any_label_below_the_parent_is() -> None:
    """The DNS campaign's names are ``www.google.com.<random>.bad.example``: the random label is
    next to the parent, not at the far left."""
    labels = ("uqamjpskbt1cnd9w", "dufvqi3ljawyet0b", "xnmqkfc7h9wguz40", "ab0824id6nso1z9u")
    names = [f"www.google.com.{label}.bad.example" for label in labels]
    family = families_of([sighting(1, [*names, "www.bad.example"], host(1))])["bad.example"]
    assert (family.random, family.below) == (4, 5)


def test_one_device_asking_three_times_is_not_three_devices() -> None:
    found = families_of([sighting(n, [f"n{n}.example.com"], host(1)) for n in (1, 2, 3)])
    assert len(found["example.com"].hosts) == 1
    assert len(found["example.com"].investigations) == 3
    assert not found["example.com"].candidate


def test_an_investigation_without_a_campus_host_counts_its_names_but_no_host() -> None:
    found = families_of([sighting(1, random_names(25, "attack.example"), None)])
    family = found["attack.example"]
    assert family.hosts == frozenset()
    assert family.candidate


def test_the_random_share_counts_the_names_below_the_parent() -> None:
    names = [*random_names(8, "dga.example"), "www.dga.example", "mail.dga.example", "dga.example"]
    family = families_of([sighting(1, names, host(1))])["dga.example"]
    assert family.below == 10
    looks = sum(fam.random_looking(n.split(".")[0]) for n in names[:8])
    assert looks >= 6  # the hint is not perfect, and the words below it are never random
    assert family.random == looks
    assert family.random_share == pytest.approx(looks / 10)
    assert Family("x.example", frozenset(), frozenset(), frozenset(), 0, 0).random_share == 0.0


def test_candidates_are_the_widest_first() -> None:
    found = families_of(
        [
            *[sighting(n, [f"x{n}.wide.example"], host(n)) for n in range(1, 6)],
            *[sighting(10 + n, [f"y{n}.mid.example"], host(n)) for n in range(1, 4)],
            sighting(20, random_names(30, "long.example"), host(9)),
            sighting(21, ["lone.example"], host(9)),
        ]
    )
    assert [f.parent for f in candidates(found)] == ["wide.example", "mid.example", "long.example"]


# -- properties ---------------------------------------------------------------------------------

LABEL = st.from_regex(r"[a-z0-9]{1,10}", fullmatch=True)
PARENT = st.sampled_from(["a.example", "b.example", "c.co.uk", "d.workers.dev", "e.org"])
NAME = st.builds(lambda label, parent: f"{label}.{parent}", LABEL, PARENT)
SIGHTINGS = st.lists(
    st.builds(
        lambda n, names, h: sighting(n, names, None if h is None else host(h)),
        st.integers(1, 10_000),
        st.lists(NAME, min_size=1, max_size=6),
        st.one_of(st.none(), st.integers(1, 6)),
    ),
    max_size=15,
    unique_by=lambda s: s.investigation_id,
)


@given(SIGHTINGS, st.randoms(use_true_random=False))
def test_families_do_not_depend_on_the_order_of_the_sightings(
    items: list[Sighting], rnd: random.Random
) -> None:
    shuffled = list(items)
    rnd.shuffle(shuffled)
    assert families_of(items) == families_of(shuffled)


@given(SIGHTINGS)
def test_every_name_is_in_exactly_one_family_and_the_counts_agree(items: list[Sighting]) -> None:
    found = families_of(items)
    everything = {n for s in items for n in s.names}
    assert everything == {n for f in found.values() for n in f.names}
    for parent, family in found.items():
        assert all(n == parent or n.endswith("." + parent) for n in family.names)
        assert 0 <= family.random <= family.below <= len(family.names)
        assert 0.0 <= family.random_share <= 1.0
        assert len(family.hosts) <= len(family.investigations)
        wide = len(family.hosts) >= fam.MIN_HOSTS and not family.hosted
        assert family.candidate is (wide or len(family.names) >= fam.MIN_NAMES)


@given(SIGHTINGS, SIGHTINGS)
def test_more_sightings_never_make_a_family_smaller(a: list[Sighting], b: list[Sighting]) -> None:
    more = a + [s for s in b if s.investigation_id not in {x.investigation_id for x in a}]
    before, after = families_of(a), families_of(more)
    for parent, family in before.items():
        bigger = after[parent]
        assert family.names <= bigger.names
        assert family.hosts <= bigger.hosts
        assert family.investigations <= bigger.investigations
