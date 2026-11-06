"""Properties of the incident titles over generated incidents (with hostile values): every claim
is backed by the facts (naming's checker passes), the bounds hold (100 characters stored, 160
UTF-16 units in Kibana's form), the same facts in any order give the same title, the certainty
word is the caller's and leads, "served" only with the checking lane's verified answer, a count
is the incident's own devices, "case N" is another incident's case, and a retitle keeps a
person's title, a person's confirmation and (between material changes) the words."""

from __future__ import annotations

import re
import uuid
from dataclasses import replace

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.cases import naming
from argus.risk import titles
from argus.risk.exposure import PairFacts
from argus.risk.observe import ObjectRef
from argus.risk.titles import GroupFacts, IncidentFacts, LinkFacts, retitle, title_for_incident
from tests.unit.risk.titles_kit import CLASSIFIER

pytestmark = pytest.mark.unit

HOSTILE = st.sampled_from([
    "", " ", "a'b", "x‮y", "evil\nname.example", "a" * 80, "203.0.113.999", "-", "…",
    "Amadey", "PS1Bot loader", "cobalt strike beacon", "'quoted'",
])  # fmt: skip
ADDRESSES = st.sampled_from(
    [f"10.20.4.{i}" for i in range(1, 6)]
    + [f"10.20.9.{i}" for i in (1, 2)]
    + [f"10.30.6.{i}" for i in (1, 2)]
    + ["10.40.1.1", "10.40.2.2"]
)
OUTSIDE_IPS = st.sampled_from([f"203.0.113.{i}" for i in range(1, 7)] + ["198.51.100.9"])
NAMES = st.sampled_from(
    [
        "a1x.rare.example.com",
        "b2y.rare.example.com",
        "c3z.rare.example.com",
        "cdn.other-example.net",
        "api.other-example.net",
        "plain.example.org",
    ]
)
SITES = st.sampled_from(["www.dept-a.example.edu", "lab.example.edu", "blog.example.edu"])
PATHS = st.sampled_from(
    [
        "/.env",
        "/api/*.env",
        "/.git/config",
        "/wp-login.php",
        "/backup.zip",
        "/",
        "/admin/",
        "/../etc/passwd",
        "/config.php",
    ]
)
KINDS = st.sampled_from(
    ["beacon", "ports", "outside", "ti", "operator", "success", "tunnel", "rare_dest"]
)
SOURCES = st.sampled_from(["outside", "ti", "operator", "campaign", "person"])


def _device(address: str, day: int | None, as_host: bool) -> ObjectRef:
    if as_host:
        return ObjectRef("device", f"host:pc-{address.replace('.', '-')}")
    return ObjectRef("device", f"ip:{address}" + (f"@2026-11-0{day}" if day else ""))


@st.composite
def incidents(draw: st.DrawFn) -> IncidentFacts:
    web = draw(st.booleans())
    if web:
        objects = [ObjectRef("site", f"domain:{s}") for s in draw(st.sets(SITES, min_size=1))]
        if draw(st.booleans()):
            objects.append(ObjectRef("site", "ip:10.50.0.9"))
    else:
        raw = draw(st.lists(st.tuples(ADDRESSES, st.none() | st.integers(1, 3), st.booleans()),
                            min_size=1, max_size=8))  # fmt: skip
        objects = list(dict.fromkeys(_device(a, d, h) for a, d, h in raw))
        if draw(st.booleans()):
            objects.append(ObjectRef("account", "student42"))
    threat_values = st.one_of(OUTSIDE_IPS, NAMES, HOSTILE)
    groups = []
    for n in range(draw(st.integers(1, 8))):
        seen = draw(st.lists(st.sampled_from(objects), min_size=1, max_size=3, unique=True))
        entities = [("ip" if v[:1].isdigit() else "domain", v, "threat")
                    for v in draw(st.lists(threat_values, max_size=3))]  # fmt: skip
        entities += [("ip", v, "actor") for v in draw(st.lists(OUTSIDE_IPS, max_size=3))]
        entities += [("url_pattern", p, "threat") for p in draw(st.lists(PATHS, max_size=4))]
        groups.append(GroupFacts(
            uuid.UUID(int=n + 1), draw(st.one_of(HOSTILE, st.just("Proxy rule"))),
            {r: frozenset(draw(st.sets(KINDS, max_size=3))) for r in seen}, tuple(entities),
            tuple(draw(st.lists(st.tuples(SITES, PATHS), max_size=3))),
            frozenset(draw(st.sets(st.sampled_from(["ok", "empty", "skipped_budget"]),
                                   max_size=2))),
        ))  # fmt: skip
    things = st.one_of(OUTSIDE_IPS.map(lambda v: f"ip:{v}"),
                       NAMES.map(lambda v: titles.thing("domain", v)))  # fmt: skip
    links = []
    for _ in range(draw(st.integers(0, 6))):
        a = draw(st.sampled_from(objects))
        b = draw(st.none() | st.sampled_from(objects))
        via = draw(st.sampled_from(["flagged", "rare", "bare_ip", "campaign", "host", "lane"]))
        value = draw(things)
        if via == "campaign":
            value = "campaign:" + ",".join(draw(st.lists(things, min_size=1, max_size=3)))
        links.append(LinkFacts(a, b, via, value))
    bare = st.one_of(OUTSIDE_IPS, NAMES, HOSTILE, st.just("rare.example.com"))
    exposure = []
    if web:
        for _ in range(draw(st.integers(0, 3))):
            exposure.append(PairFacts(
                draw(OUTSIDE_IPS), draw(SITES), served=tuple(draw(st.lists(PATHS, max_size=2))),
                bulk=draw(st.sampled_from([0, 0, 30])), bulk_prefix=draw(st.none() | PATHS),
                through=tuple(draw(st.lists(PATHS, max_size=2))),
            ))  # fmt: skip
    places = {
        r.key[3:].split("@", 1)[0]: titles.place_of(r.key[3:].split("@", 1)[0], CLASSIFIER)
        for r in objects if r.key.startswith("ip:") and r.kind == "device"
    }  # fmt: skip
    return IncidentFacts(
        objects={r: draw(st.sampled_from(["actor", "affected"])) for r in objects},
        groups=tuple(groups),
        links=tuple(links),
        flags=draw(st.dictionaries(things, SOURCES, max_size=4)),
        vt=draw(st.dictionaries(bare, st.integers(0, 90), max_size=4)),
        labels=draw(st.dictionaries(bare, st.lists(HOSTILE, max_size=2).map(tuple), max_size=3)),
        others=draw(st.dictionaries(bare, st.integers(0, 60), max_size=3)),
        follows=draw(st.integers(0, 60)),
        places=places,
        exposure=tuple(exposure),
        catch_all=frozenset(draw(st.lists(st.tuples(SITES, PATHS), max_size=3))),
    )


WORDS = st.sampled_from(naming.CERTAINTIES)


def _checked(f: IncidentFacts, word: str) -> naming.Facts:
    return replace(titles.naming_facts(f), verdict=naming.Verdict(given=word))


@given(incidents(), WORDS)
def test_every_claim_is_backed_and_the_bounds_hold(f: IncidentFacts, word: str) -> None:
    made = title_for_incident(f, word)
    assert naming.check(naming.Titled(made.parts), _checked(f, word)) == []
    assert "".join(p if isinstance(p, str) else p.words for p in made.parts) == made.text
    assert len(made.text) <= naming.MAX_TITLE
    assert len(made.kibana.encode("utf-16-le")) // 2 <= 160
    assert made.text.isprintable()
    if not made.empty:
        assert made.text.startswith(word + (": " if word in naming.COLON else ""))
        assert made.claims[0].slot == "certainty"
        assert not made.kibana.startswith(word)


@given(incidents(), WORDS, st.randoms(use_true_random=False))
def test_the_same_facts_in_any_order_give_the_same_title(
    f: IncidentFacts, word: str, rnd: object
) -> None:
    def shuffled(items: tuple[object, ...]) -> tuple[object, ...]:
        held = list(items)
        rnd.shuffle(held)  # type: ignore[attr-defined]
        return tuple(held)

    objects = list(f.objects.items())
    rnd.shuffle(objects)  # type: ignore[attr-defined]
    other = replace(
        f, objects=dict(objects), groups=shuffled(f.groups),  # type: ignore[arg-type]
        links=shuffled(f.links), exposure=shuffled(f.exposure),  # type: ignore[arg-type]
    )  # fmt: skip
    assert title_for_incident(other, word) == title_for_incident(f, word)
    assert title_for_incident(f, word) == title_for_incident(f, word)


@given(incidents(), WORDS)
def test_served_only_with_the_checking_lanes_verified_answer(f: IncidentFacts, word: str) -> None:
    made = title_for_incident(f, word)
    served = [c for c in made.claims if c.slot == "outcome" and c.words.endswith(" served")]
    if served:
        sites = {r.key.split(":", 1)[1] for r in f.objects if r.kind == "site"}
        assert any((p.served or (p.bulk and p.bulk_prefix)) and p.site in sites
                   for p in f.exposure)  # fmt: skip
    if not f.exposure:
        assert "served" not in made.text


@given(incidents(), WORDS)
def test_a_count_is_the_incidents_own_devices(f: IncidentFacts, word: str) -> None:
    made = title_for_incident(f, word)
    devices = len({name for name, _ in titles._device_names(f).values()})
    for claim in made.claims:
        if (m := re.fullmatch(r"actors:[a-z_]+:(\d+):(\d+)", claim.fact)) is not None:
            n, total = int(m.group(1)), int(m.group(2))
            assert 1 <= n <= total == devices
        if (m := re.fullmatch(r"case:.+:(\d+)", claim.fact)) is not None:
            assert int(m.group(1)) in f.others.values()
            assert int(m.group(1)) != f.follows


@given(incidents(), incidents(), WORDS, WORDS, st.booleans())
def test_a_retitle_keeps_a_persons_title_their_confirmation_and_the_words(
    old: IncidentFacts, new: IncidentFacts, was: str, word: str, material: bool
) -> None:
    current = title_for_incident(old, was)
    if current.empty:
        return
    assert retitle(current.text, new, word, material=material, by_person=True) is None
    made = retitle(current.text, new, word, material=material)
    if made is not None:  # whatever the reason, the stored title keeps the checker's bounds
        assert made.certainty == word
        assert titles.split_certainty(made.text)[0] == word
        _, rest = titles.split_certainty(made.text)
        assert titles.fits(made.text, rest)
        if made.checkable:
            assert naming.check(naming.Titled(made.parts), _checked(new, word)) == []
    if made is not None and not material:
        assert made.reason in ("certainty", "fit")
        if made.reason == "certainty":  # the words stay
            assert titles.split_certainty(made.text)[1] == titles.split_certainty(current.text)[1]
        else:  # they would not fit the new word: the facts' own title
            assert made == replace(title_for_incident(new, word), reason="fit")
    confirmed = retitle(current.text, new, word, material=material, confirmed=True)
    if confirmed is not None:
        assert confirmed.certainty == naming.CONFIRMED
        assert confirmed.text.startswith(("Confirmed ", "Confirmed: alerts "))


@given(incidents())
def test_two_hosts_are_one_device_only_through_host_links(f: IncidentFacts) -> None:
    root = {r: r for r in f.objects if r.kind == "device"}

    def find(r: ObjectRef) -> ObjectRef:
        while root[r] != r:
            r = root[r]
        return r

    for lk in f.links:  # host links alone, never the days of one address
        if lk.via == "host" and lk.b is not None and lk.a in root and lk.b in root:
            root[find(lk.a)] = find(lk.b)
    names = titles._device_names(f)
    hosts = [r for r in names if r.key.startswith("host:")]
    for a in hosts:
        for b in hosts:
            if names[a] == names[b]:
                assert find(a) == find(b)


@given(incidents(), WORDS)
def test_a_family_is_a_flagged_listed_or_bound_things_own(f: IncidentFacts, word: str) -> None:
    made = title_for_incident(f, word)
    family = [c.words for c in made.claims if c.slot == "family"]
    if not family:
        return
    eligible = {titles._bare(t) for t, s in f.flags.items() if s in titles.FLAGGED_BY}
    eligible |= f.listed
    eligible |= {titles._bare(t) for lk in f.links if lk.via == "campaign"
                 and lk.value.startswith(titles.CAMPAIGN_KEY)
                 for t in titles.campaign_threats(lk.value)}  # fmt: skip
    assert any(naming.family_of([label]) == family[0]
               for v in eligible for label in f.labels.get(v, ()))  # fmt: skip
