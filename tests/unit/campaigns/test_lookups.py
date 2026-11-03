"""AR2c (D-170): what the family step says of a pass. The database side is in the integration
tests."""

from __future__ import annotations

from argus.assess import raised
from argus.campaigns import lookups
from argus.campaigns.lookups import Report


def test_the_line_says_what_was_asked_and_what_was_flagged() -> None:
    flagged = {raised.OUTSIDE: 12, raised.OPERATOR: 0, raised.CAMPAIGN: 30}
    report = Report(asked=3, found=2, not_found=1, campaigns=1, flagged=flagged)
    assert report.line() == (
        "campaigns: 1 found; looked up 3 (found 2, no record 1, failed 0);"
        " flagged 12 flagged by outside threat intel, 30 many campus devices reach one rare domain"
    )


def test_the_line_says_why_nothing_was_asked_and_why_a_pass_stopped() -> None:
    assert Report(off="no VirusTotal key").line() == (
        "campaigns: 0 found (look-ups off: no VirusTotal key)"
    )
    stopped = Report(asked=1, found=1, stopped="VirusTotal's budget for this use is spent today")
    assert stopped.line() == (
        "campaigns: 0 found; looked up 1 (found 1, no record 0, failed 0);"
        " VirusTotal's budget for this use is spent today"
    )


def test_the_flags_a_campaign_gives_are_written_in_one_order() -> None:
    assert lookups.FLAGS == (raised.OUTSIDE, raised.OPERATOR, raised.CAMPAIGN)
    assert lookups.BATCH == 2  # VirusTotal allows 3 a minute; the step takes two a pass


# -- the order candidates are looked at in (D-174) ----------------------------------------------


def test_candidates_are_looked_at_rare_first_unknown_next_and_popular_last() -> None:
    import uuid
    from datetime import date

    from argus.campaigns.analysis import Reading, World
    from argus.campaigns.families import Sighting, candidates, families_of

    def sighting(n: int, parent: str, hosts: int) -> Sighting:
        names = frozenset(f"x{k}{n}.{parent}" for k in range(25))
        devices = frozenset(("ip", f"10.1.{n}.{h}") for h in range(hosts))
        return Sighting(uuid.UUID(int=n), devices, names)

    items = (
        sighting(1, "popular-site.com", 9),  # the widest of all
        sighting(2, "never-looked-at.com", 6),
        sighting(3, "rare-known.com", 3),
        sighting(4, "detected-known.com", 3),
    )
    readings = {
        "popular-site.com": Reading(True, 0, 0, 90, True, 500, date(2012, 1, 1)),
        "rare-known.com": Reading(True, 0, 0, 90, False, None, date(2020, 1, 1)),
        "detected-known.com": Reading(True, 7, 0, 90, False, None, date(2020, 1, 1)),
    }
    world = World(items, readings)
    found = families_of(items)
    ordered = [
        f.parent for f in sorted(candidates(found), key=lambda f: lookups.order_of(world, f))
    ]
    # the two the cache reads as rare come first (their address is the one request missing), then
    # the one nobody has looked at, and the popular one last (nothing is missing for it)
    assert ordered == ["detected-known.com", "rare-known.com", "never-looked-at.com",
                       "popular-site.com"]  # fmt: skip
