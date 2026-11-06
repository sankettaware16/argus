"""E3: inbound exposure, pure: sensitive paths, the checks' readers, the facts they verify, an
inbound group's sites, and lane L5 on the campus sites. Made-up sites and addresses (ACME)."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest

from argus.context.batch1 import final_request
from argus.context.packs import TaskSpec
from argus.gateway.gateway import Targets
from argus.risk import exposure, webchecks
from argus.risk import observe as ob
from argus.risk.config import WINDOWS
from argus.risk.exposure import CheckRow, PairFacts
from argus.risk.observe import ObjectRef
from argus.risk.score import Stats, evaluate
from tests.unit.risk.conftest import CONFIG, NOW, context, group, meta

pytestmark = pytest.mark.unit
EX = CONFIG.exposure
DAY = NOW.date()
SCOUT, TAKER, OTHER = "45.138.12.7", "45.138.13.9", "91.208.4.44"
SITE = "dept.example.edu"


def test_sensitive_paths_are_hidden_segments_backups_and_settings_never_common_pages() -> None:
    s = EX.sensitive
    for path in ("/.env", "/~lab/.git/config", "/backup.zip", "/db.SQL", "/wp-config.php",
                 "/a/b/settings.php", "/%2egit/HEAD"):  # fmt: skip
        assert exposure.sensitive(path, s), path
    for path in ("/", "/index.php", "/robots.txt", "/.well-known/security.txt", "/news/2026",
                 "/img/logo.png"):  # fmt: skip
        assert not exposure.sensitive(path, s), path


def test_a_prefix_is_the_path_up_to_its_first_hidden_directory() -> None:
    assert exposure.prefix("/~lab/.git/objects/ab/cdef") == "/~lab/.git/"
    assert exposure.prefix("/.git/HEAD") == "/.git/"
    assert exposure.prefix("/.env") is None  # a file, not a directory
    assert exposure.prefix("/a/b/c.zip") is None


def test_followup_rows_read_the_stored_2xx_answers() -> None:
    snapshot = {"rows": [
        {"_source": {"url": {"domain": "Dept.Example.EDU", "path": "/.env"},
                     "http": {"response": {"status_code": 200}}}},
        {"_source": {"url": {"path": "/x"}}},  # no site: left out
        "junk",
    ]}  # fmt: skip
    assert exposure.followup_rows(snapshot) == [(SITE, "/.env", 200)]
    assert exposure.followup_rows(None) == []
    assert exposure.followup_rows({"rows": "x"}) == []


# --------------------------------------------------------------------------- readers


def _sizes(sizes: dict[int, int], other: int = 0) -> dict[str, Any]:
    return {"sizes": {"buckets": [{"key": k, "doc_count": v} for k, v in sizes.items()],
                      "sum_other_doc_count": other}}  # fmt: skip


def catchall_body(answers: dict[str, dict[int, int]], not_found: dict[int, int],
                  paths: list[str]) -> dict[str, Any]:  # fmt: skip
    aggs: dict[str, Any] = {"requests": {"value": 100}, "not_found": _sizes(not_found)}
    for i, p in enumerate(paths):
        aggs[f"ok_{i}"] = {"doc_count": sum(answers.get(p, {}).values()),
                           **_sizes(answers.get(p, {}))}  # fmt: skip
    return {"aggregations": aggs}


def test_the_soft_404_check_tells_the_catch_all_page_from_a_served_file() -> None:
    paths = sorted(["/.env", "/.git/config", "/backup.zip", "/db.sql"])
    body = catchall_body(
        {"/.env": {5120: 3}, "/.git/config": {5120: 1}, "/backup.zip": {9_000_000: 1},
         "/db.sql": {731: 1}}, {731: 40}, paths,
    )  # fmt: skip
    c = webchecks.read_catchall(body, paths, EX.served_min_bytes)
    assert c.soft_404
    assert c.verdict == "soft_404"
    assert ("/.env", 5120) in c.catch
    assert ("/.git/config", 5120) in c.catch
    assert ("/db.sql", 731) in c.catch  # the not-found page's size
    assert c.served == ("/backup.zip",)
    assert c.is_catch_all("/anything", 5120)
    assert not c.is_catch_all("/backup.zip", 9_000_000)


def test_an_error_page_that_echoes_the_path_is_still_one_page() -> None:
    paths = sorted(["/.env", "/.git/config"])  # 5 and 12 characters
    body = catchall_body({"/.env": {1005: 1}, "/.git/config": {1012: 1}}, {}, paths)
    c = webchecks.read_catchall(body, paths, EX.served_min_bytes)
    assert c.soft_404
    assert c.served == ()


def test_a_tiny_or_unanswered_site_serves_nothing() -> None:
    paths = ["/.env"]
    c = webchecks.read_catchall(catchall_body({"/.env": {12: 1}}, {}, paths), paths, 64)
    assert c.served == ()
    assert not c.soft_404
    empty = webchecks.read_catchall({"aggregations": {"requests": {"value": 0}}}, paths, 64)
    assert empty.verdict == "unknown"


def test_the_site_lookup_says_where_each_source_got_through() -> None:
    body = {"aggregations": {
        "sources": {"buckets": [
            {"key": SCOUT, "sites": {"buckets": [{"key": "A.example.edu", "doc_count": 9},
                                                 {"key": "b.example.edu", "doc_count": 2}]}},
            {"key": OTHER, "sites": {"buckets": [{"key": "a.example.edu", "doc_count": 1}]}},
        ]},
        "ok_sources": {"sources": {"buckets": [{"key": SCOUT}]}},
        "ok_sites": {"sites": {"buckets": [{"key": "a.example.edu"}], "sum_other_doc_count": 0}},
    }}  # fmt: skip
    hits = webchecks.read_sites(body, [SCOUT, OTHER, TAKER])
    assert [(h.site, h.requests, h.ok) for h in hits[SCOUT]] == [
        ("a.example.edu", 9, True), ("b.example.edu", 2, False)]  # fmt: skip
    assert [h.ok for h in hits[OTHER]] == [False]  # no 2xx for it anywhere
    assert hits[TAKER] == []


def test_a_bulk_take_needs_many_paths_many_sizes_and_one_hidden_prefix() -> None:
    top = [[f"/~lab/.git/objects/{i:02x}/abc", 1] for i in range(25)]
    facts = {"paths": 214, "sizes": 180, "bytes": 9_000_000, "top": top}
    assert exposure.bulk_of(facts, EX) == (214, "/~lab/.git/")
    assert exposure.bulk_of({**facts, "sizes": 1}, EX) == (0, None)  # one size: a catch-all
    assert exposure.bulk_of({**facts, "paths": 12}, EX) == (0, None)
    spread = [[f"/page{i}.html", 1] for i in range(25)]
    assert exposure.bulk_of({**facts, "top": spread}, EX) == (0, None)  # ordinary pages


def test_every_template_builds_a_request_the_validator_accepts() -> None:
    start = datetime(2026, 10, 20, 2, 0, tzinfo=UTC)
    tasks = [
        TaskSpec(webchecks.WebSourceSites(), webchecks.SitesParams(
            ips=tuple(f"45.138.14.{i}" for i in range(50)), start=start,
            end=start + timedelta(hours=20))),
        TaskSpec(webchecks.WebCatchall(), webchecks.CatchallParams(
            site=SITE, paths=tuple(f"/.p{i}" for i in range(20)), start=start,
            end=start + timedelta(hours=6))),
        TaskSpec(webchecks.WebBulkTake(), webchecks.TakeParams(
            ip=TAKER, site=SITE, start=start, end=start + timedelta(hours=20))),
    ]  # fmt: skip
    for task in tasks:
        final = final_request(task, Targets(), NOW)
        assert len(final.indices) == 1  # one daily index


@pytest.mark.parametrize(
    ("model", "values"),
    [
        (webchecks.SitesParams, {"ips": tuple(f"45.138.14.{i}" for i in range(51))}),
        (webchecks.SitesParams, {"ips": ("not-an-ip",)}),
        (webchecks.CatchallParams, {"site": SITE, "paths": tuple(f"/{i}" for i in range(21))}),
        (webchecks.CatchallParams, {"site": "a\nb", "paths": ("/.env",)}),
        (webchecks.TakeParams, {"ip": TAKER, "site": SITE, "hours": 23}),
    ],
)
def test_parameters_out_of_bounds_are_refused(model: Any, values: dict[str, Any]) -> None:
    start = datetime(2026, 10, 20, 1, 30, tzinfo=UTC)
    hours = values.pop("hours", 5)
    with pytest.raises(ValueError, match=r"\w"):
        model(**values, start=start, end=start + timedelta(hours=hours))


# --------------------------------------------------------------------------- facts


def row(kind: str, facts: dict[str, Any], *, source: str | None = SCOUT, site: str | None = SITE,
        day: date = DAY, hours: float = 0.0) -> CheckRow:  # fmt: skip
    return CheckRow(kind, source, site, day, "found", facts, NOW + timedelta(hours=hours))


def paths_row(items: list[tuple[str, str, dict[int, int]]], *, source: str = SCOUT,
              rare: list[str] | None = None, hours: float = 0.0) -> CheckRow:  # fmt: skip
    return row("paths", {
        "paths": [{"path": p, "outcome": o, "ok": sum(s.values()),
                   "sizes": {str(k): v for k, v in s.items()}} for p, o, s in items],
        "rare": rare or [],
    }, source=source, hours=hours)  # fmt: skip


def catch_row(catch: list[tuple[str, int]], not_found: dict[int, int] | None = None, *,
              answered: dict[str, dict[int, int]] | None = None,
              pages: dict[int, int] | None = None) -> CheckRow:  # fmt: skip
    return row("catchall", {
        "requests": 50, "catch": [list(c) for c in catch],
        "answered": {p: {str(k): v for k, v in sz.items()} for p, sz in (answered or {}).items()},
        "not_found": {str(k): v for k, v in (not_found or {}).items()},
        "pages": {str(k): v for k, v in (pages or {}).items()}, "served": [],
    }, source=None)  # fmt: skip


def test_served_needs_the_soft_404_check_and_a_size_unlike_the_catch_all_page() -> None:
    got = [("/.env", "success", {2400: 1}), ("/.git/config", "success", {5120: 1})]
    alone = exposure.derive([paths_row(got)], EX)[(SCOUT, SITE)]
    assert alone.served == ()
    assert alone.through == ()  # unverified: the gray band
    checked = exposure.derive([paths_row(got), catch_row([("/x", 5120)])], EX)[(SCOUT, SITE)]
    assert checked.served == ("/.env",)  # /.git/config got the catch-all page
    assert checked.through == ("/.env",)
    assert checked.soft_404
    assert checked.signals == {"exposure.served": 1}


def test_a_catch_all_site_gives_no_served_file_and_no_signal() -> None:
    got = [("/.env", "success", {5120: 1}), ("/backup.zip", "possible", {5120: 2})]
    facts = exposure.derive([paths_row(got), catch_row([("/a", 5120)])], EX)[(SCOUT, SITE)]
    assert facts.served == ()
    assert facts.through == ()
    assert facts.signals == {}


GIT = {"/.git/config": {262: 3}, "/.git/HEAD": {23: 3}, "/.env": {5_120: 1}}


def test_a_bulk_take_is_a_signal_of_its_source_on_its_site() -> None:
    top = [[f"/.git/objects/{i:02x}/x", 1] for i in range(25)]
    take = row("take", {"paths": 214, "sizes": 150, "bytes": 5_000_000, "top": top},
               source=TAKER)  # fmt: skip
    checked = catch_row([], {162: 40}, answered=GIT, pages={9_000: 80})
    facts = exposure.derive([take, checked], EX)
    assert facts[(TAKER, SITE)].bulk == 214
    assert facts[(TAKER, SITE)].bulk_prefix == "/.git/"
    assert facts[(TAKER, SITE)].signals == {"exposure.bulk_take": 214}
    assert exposure.derive([take], EX)[(TAKER, SITE)].bulk == 0  # no soft-404 check: unverified


def test_a_wordlist_scan_of_a_page_that_echoes_the_path_is_no_bulk_take() -> None:
    """24 /.git/ paths, each answered with a 2000-byte page that echoes the path: many paths
    and sizes under one prefix, but the site's soft-404 check shows the page."""
    words = ["HEAD", "config", "index", "description", "packed-refs", "ORIG_HEAD", "FETCH_HEAD",
             "logs/HEAD", "refs/heads/main", "refs/heads/master", "info/exclude", "COMMIT_EDITMSG",
             "hooks/pre-commit", "objects/info/packs", "refs/stash", "refs/remotes/origin/HEAD",
             "logs/refs/heads/main", "branches", "info/refs", "modules", "shallow", "MERGE_HEAD",
             "config.bak", "HEAD.lock"]  # fmt: skip
    top = [[f"/.git/{w}", 1] for w in words]
    take = row("take", {"paths": 24, "sizes": 14, "bytes": 49_000, "top": top}, source=TAKER)
    echo = {"/.git/HEAD": {2_010: 1}, "/.git/config": {2_012: 1}}
    soft = catch_row([("/.git/HEAD", 2_010), ("/.git/config", 2_012)], answered=echo)
    assert exposure.bulk_of(take.facts, EX) == (24, "/.git/")  # the take alone looks bulk
    facts = exposure.derive([take, soft], EX)[(TAKER, SITE)]
    assert facts.bulk == 0
    assert facts.signals == {}
    one = catch_row([], answered={"/.git/config": {2_012: 1}})  # one file: nothing compared
    assert exposure.derive([take, one], EX)[(TAKER, SITE)].bulk == 0


def test_two_sources_sharing_two_rare_paths_that_got_through_share_them() -> None:
    rare = ["/.git/config", "/.git/HEAD"]
    sizes = {"/.git/config": 262, "/.git/HEAD": 23}
    a = paths_row([(p, "success", {sizes[p]: 1}) for p in rare], rare=rare)
    b = paths_row([(p, "success", {sizes[p]: 1}) for p in rare], source=OTHER, rare=rare)
    checked = catch_row([], {162: 40}, pages={9_000: 80})
    facts = exposure.derive([a, b, checked], EX)
    assert (
        facts[(SCOUT, SITE)].shared == facts[(OTHER, SITE)].shared == ("/.git/HEAD", "/.git/config")
    )
    one = paths_row([(rare[0], "success", {262: 1})], source=OTHER, rare=rare)
    assert exposure.derive([a, one, checked], EX)[(SCOUT, SITE)].shared == ()  # one is not two
    common = paths_row([(p, "success", {sizes[p]: 1}) for p in rare], source=OTHER)
    plain = paths_row([(p, "success", {sizes[p]: 1}) for p in rare])
    assert exposure.derive([plain, common, checked],
                           EX)[(SCOUT, SITE)].shared == ()  # not rare: every scanner's  # fmt: skip


def test_rare_paths_on_an_echoing_site_with_no_soft_404_check_are_not_shared() -> None:
    """Two scanners of one botnet try the same rare tail on a page that echoes the path: the
    paths check grades each 'success' (the sizes differ), but nothing verified them."""
    rare = ["/.env.production", "/.aws/credentials"]
    echo = [(p, "success", {2_000 + len(p): 1}) for p in rare]
    a, b = paths_row(echo, rare=rare), paths_row(echo, source=OTHER, rare=rare)
    facts = exposure.derive([a, b], EX)
    assert facts[(SCOUT, SITE)].signals == facts[(OTHER, SITE)].signals == {}
    assert facts[(SCOUT, SITE)].through == ()
    checked = catch_row([], {162: 40}, pages={9_000: 80})  # the check shows the echo now
    assert exposure.derive([a, b, checked], EX)[(SCOUT, SITE)].signals == {}


def test_one_custom_error_page_given_to_two_scanners_at_other_hours_is_not_served() -> None:
    """A busy site's 200 error page is not among its five commonest sizes. The soft-404 check
    saw one probe; a later scanner's /.git/config got the same 1500 bytes: one page, not two
    files."""
    busy = {9_000: 300, 3_000: 90, 4_100: 70, 5_600: 40, 7_400: 30}
    check = catch_row([], {162: 40}, answered={"/.env": {1_500: 1}}, pages=busy)
    first = paths_row([("/.env", "possible", {1_500: 1})])
    later = paths_row([("/.git/config", "possible", {1_500: 1})], source=OTHER, hours=5)
    facts = exposure.derive([check, first, later], EX)
    assert facts[(SCOUT, SITE)].served == facts[(OTHER, SITE)].served == ()
    assert facts[(SCOUT, SITE)].through == facts[(OTHER, SITE)].through == ()
    alone = exposure.derive([check, first], EX)[(SCOUT, SITE)]
    assert alone.served == ()  # one file, compared with nothing: unverified
    assert alone.through == ("/.env",)


def test_a_catch_all_page_whose_size_a_nonce_moves_is_still_one_page() -> None:
    """A page with a per-request nonce under gzip: 182 to 186 bytes for every probe."""
    paths = sorted(["/.env", "/.git/config", "/backup.sql", "/.aws/credentials"])
    body = catchall_body({"/.env": {184: 1}, "/.git/config": {182: 1}, "/backup.sql": {186: 1},
                          "/.aws/credentials": {182: 1}}, {}, paths)  # fmt: skip
    c = webchecks.read_catchall(body, paths, EX.served_min_bytes)
    assert c.verdict == "soft_404"
    assert c.served == ()
    assert len(c.catch) == 4
    got = paths_row([("/.env", "success", {185: 1}), ("/.npmrc", "success", {183: 1})])
    stored = row("catchall", {"requests": 40, "answered": {p: {str(s): 1 for s in sz}
                 for p, sz in c.answered.items()}, "catch": [list(x) for x in c.catch]},
                 source=None)  # fmt: skip
    facts = exposure.derive([got, stored], EX)[(SCOUT, SITE)]
    assert facts.served == facts.through == ()
    assert webchecks.near(182, 186)
    assert not webchecks.near(23, 41)  # two real git files
    assert not webchecks.near(9_000_000, 9_100_000)  # two real dumps: at most 1 KiB apart


def test_two_identical_backup_copies_of_one_file_are_still_served() -> None:
    """``cp .env .env.bak``: the same 812 bytes for two files, but copies of one file; the site
    answers /.git/config with its 404 page."""
    paths = sorted(["/.env", "/.env.bak"])
    body = catchall_body({"/.env": {812: 1}, "/.env.bak": {812: 1}}, {162: 40}, paths)
    body["aggregations"]["home"] = {"doc_count": 30, **_sizes({9_000: 30})}
    c = webchecks.read_catchall(body, paths, EX.served_min_bytes)
    assert c.verdict == "plain"
    assert c.served == ("/.env", "/.env.bak")
    third = sorted([*paths, "/.git/config"])  # a third, unrelated file at 812: the page
    body = catchall_body({"/.env": {812: 1}, "/.env.bak": {812: 1}, "/.git/config": {812: 1}},
                         {162: 40}, third)  # fmt: skip
    assert webchecks.read_catchall(body, third, EX.served_min_bytes).served == ()
    assert webchecks.stem("/.ENV.bak~") == webchecks.stem("//.env.save") == "/.env"
    assert webchecks.stem("/.bak") == "/.bak"
    assert webchecks.stem("/.env.production") == "/.env.production"


def test_a_short_real_file_is_served() -> None:
    """A real /.git/HEAD is 23 bytes ('ref: refs/heads/master'); an empty or 'OK' answer is
    under the floor."""
    got = [("/.git/HEAD", "success", {23: 1}), ("/.git/config", "success", {262: 1})]
    checked = catch_row([], {162: 40}, pages={9_000: 80})
    facts = exposure.derive([paths_row(got), checked], EX)[(SCOUT, SITE)]
    assert facts.served == ("/.git/HEAD", "/.git/config")
    tiny = [("/.git/HEAD", "success", {2: 1}), ("/.git/config", "success", {262: 1})]
    assert exposure.derive([paths_row(tiny), checked], EX)[(SCOUT, SITE)].served == (
        "/.git/config",)  # fmt: skip


def test_rare_paths_are_those_few_sources_got_a_2xx_for() -> None:
    seen = {"/.git/config": {SCOUT, OTHER}, "/.env": {f"45.138.14.{i}" for i in range(9)}}
    assert exposure.rare_paths(seen, EX) == {"/.git/config"}


# --------------------------------------------------------------------------- a group's sites


def test_the_site_comes_from_the_evidence_then_the_lookup() -> None:
    evidence = [(SITE, "/.env", 200), ("www.example.edu", "/", 200)]
    lookups = {(SCOUT, DAY): [{"site": "other.example.edu", "ok": True}]}
    got = exposure.group_sites([SCOUT], DAY, [], evidence, lookups, {}, timedelta(days=7))
    assert got.sites == (SITE, "www.example.edu")
    assert got.origin == "evidence"
    got = exposure.group_sites([SCOUT], DAY, [], [], lookups, {}, timedelta(days=7))
    assert got.sites == ("other.example.edu",)
    assert got.origin == "lookup"
    assert exposure.group_sites([SCOUT], DAY, [], [], {}, {}, timedelta(days=7)).sites == ()


def test_decisive_facts_keep_the_sites_they_were_found_on() -> None:
    evidence = [(SITE, "/.env", 200), ("www.example.edu", "/", 200)]
    facts = {(SCOUT, SITE): PairFacts(SCOUT, SITE, served=("/.env",))}
    got = exposure.group_sites([SCOUT], DAY, [], evidence, {}, facts, timedelta(days=7))
    assert got.sites == (SITE,)
    assert got.signals == {"exposure.served": 1}


def test_an_inbound_group_with_no_target_lands_on_the_sites_it_was_given() -> None:
    g = group(actor=SCOUT, severity="high", signals={"web.successes_after": 3,
                                                       "exposure.served": 1})  # fmt: skip
    plain = ob.observe(g, meta(family="nginx"), context())
    assert plain.direction == "inbound"
    assert plain.objects == ()
    placed = ob.observe(group_with(g, sites=(SITE.upper(),)), meta(family="nginx"), context())
    ref = ObjectRef("site", f"domain:{SITE}")
    assert placed.objects == (ref,)
    assert {o.source_key for o in placed.observations} >= {"ev:success", "ev:served"}
    assert all(o.role == "target" for o in placed.observations)


def group_with(g: ob.Group, **changes: Any) -> ob.Group:
    from dataclasses import replace

    return replace(g, **changes)


# --------------------------------------------------------------------------- the lane


def _site_verdict(*kinds: str) -> tuple[ObjectRef, Any]:
    g = group(actor=SCOUT, severity="high",
              signals={f"exposure.{k}" if k != "success" else "web.successes_after": 2
                       for k in kinds})  # fmt: skip
    seen = ob.observe(group_with(g, sites=(SITE,)), meta(family="nginx"), context())
    ref = seen.objects[0]
    return ref, evaluate(list(seen.observations), NOW, CONFIG, Stats(), role="target", ref=ref)


@pytest.mark.parametrize("kind", ["served", "bulk_take", "shared_paths"])
def test_a_verified_fact_puts_the_site_in_the_exposure_lane(kind: str) -> None:
    ref, v = _site_verdict("success", kind)
    out = exposure.lanes({ref: v}, EX)[ref]
    assert out.lanes == ("exposure",)
    assert out.held == "lane"


def test_an_unverified_2xx_is_a_checking_candidate_and_plain_scanning_is_nothing() -> None:
    ref, v = _site_verdict("success")
    out = exposure.lanes({ref: v}, EX)[ref]
    assert out.lanes == ()
    assert out.gray == ("exposure",)
    assert out.held == "target"
    ref, v = _site_verdict()
    assert exposure.lanes({ref: v}, EX)[ref] == v
    assert set(v.windows) == set(WINDOWS)


def test_devices_are_never_touched_by_the_exposure_lane() -> None:
    seen = ob.observe(group(signals={"exposure.served": 1}), meta(), context())
    ref = seen.objects[0]
    v = evaluate(list(seen.observations), NOW, CONFIG, Stats(), ref=ref)
    assert exposure.lanes({ref: v}, EX)[ref] == v


def test_one_probe_answered_with_the_home_page_or_the_commonest_page_is_not_served() -> None:
    paths = ["/.env"]
    body = catchall_body({"/.env": {18_200: 1}}, {}, paths)
    body["aggregations"]["home"] = {"doc_count": 30, **_sizes({18_200: 30})}
    c = webchecks.read_catchall(body, paths, EX.served_min_bytes)
    assert c.soft_404
    assert c.served == ()
    body["aggregations"]["home"] = {"doc_count": 30, **_sizes({9_100: 30})}
    body["aggregations"]["others"] = {"doc_count": 500, **_sizes({18_200: 420, 77: 3})}
    assert webchecks.read_catchall(body, paths, EX.served_min_bytes).served == ()
    body["aggregations"]["others"] = {"doc_count": 500, **_sizes({4_000: 420})}
    alone = webchecks.read_catchall(body, paths, EX.served_min_bytes)
    assert alone.served == ()  # one file is compared with nothing: a page not in the top five?
    two = ["/.env", "/.git/config"]
    body = catchall_body({"/.env": {18_200: 1}, "/.git/config": {260: 1}}, {}, two)
    body["aggregations"]["others"] = {"doc_count": 500, **_sizes({4_000: 420})}
    assert webchecks.read_catchall(body, two, EX.served_min_bytes).served == tuple(two)
    assert exposure.catchall_of({"requests": 9, "pages": {"9100": 30}}).is_catch_all("/x", 9_100)
