"""What else an incident could be, what ARGUS checked, and its certainty word (E5), pure.

Each **benign alternative** has one deterministic test over what ARGUS's database holds (no SIEM
request, no model), and a state: ``ruled_out`` (the test says it is not that), ``fits`` (the test
says it could be) or ``unknown`` (nothing to test it with yet). Each **check** says what ARGUS
looked at: ``checked`` (it looked and found something that backs the incident), ``ruled_out`` (it
looked and found nothing) or ``unknown`` (it could not look). The **certainty word** comes from
the lanes, the strong facts and the alternatives; "Confirmed" comes only from a person.

The tests key on evidence kinds, object kinds, the asset map's roles and how many campus objects
reach a destination: never on a rule's name."""

from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal

from argus import site

AltState = Literal["ruled_out", "fits", "unknown"]
CheckState = Literal["checked", "ruled_out", "unknown"]
Certainty = Literal["Confirmed", "Likely", "Suspected", "Unclear", "Likely harmless"]
CERTAINTY: tuple[Certainty, ...] = ("Confirmed", "Likely", "Suspected", "Unclear",
                                    "Likely harmless")  # fmt: skip
RARE = 6  # a destination at most this many campus objects reach is rare
COMMON = 20  # one at least this many reach is a common service
SCATTERED = 50  # this many distinct destinations, with no regular timing, is a crawler's shape


@dataclass(frozen=True)
class Alternative:
    name: str
    state: AltState
    test: str


@dataclass(frozen=True)
class Check:
    state: CheckState
    text: str


@dataclass(frozen=True)
class Evidence:
    """What the tests read of an incident."""

    kinds: frozenset[str] = frozenset()  # evidence kinds of its objects (ev:<kind>)
    strong: bool = False  # a strong fact (outside detection, fresh intel, operator)
    stale_intel: bool = False  # threat-list hits from an out-of-date feed only
    object_kinds: frozenset[str] = frozenset()  # device, account, site
    hubs: int = 0  # objects the asset map names a shared gateway (NAT, proxy, resolver)
    named_hosts: int = 0  # devices known by a host name
    objects: int = 1
    reach: Mapping[str, int] = field(default_factory=dict)  # outside value -> campus objects
    signals: frozenset[str] = frozenset()  # dossier signals read (known) for its alert groups
    acting: bool = True  # its objects act (outbound); False: a campus site attacked from outside


def alternatives(e: Evidence) -> list[Alternative]:
    """The benign explanations of the incident, each with its test's result."""
    if not e.acting:
        return [
            Alternative("A soft-404 site (an error page answered with 200)", "unknown",
                        "needs the soft-404 check of the checking lane"),
            Alternative("An authorised scanner", "unknown",
                        "no list of authorised scanners is configured"),
            _noise(e),
        ]  # fmt: skip
    out = [_update(e), _gateway(e), _crawler(e), _noise(e)]
    if "ti" in e.kinds:
        out.append(_old_list(e))
    return out


def _update(e: Evidence) -> Alternative:
    name = "A software update or telemetry service"
    if not e.reach:
        return Alternative(name, "unknown", "no outside destination is named in its alerts")
    rare = sorted(v for v, n in e.reach.items() if n <= RARE)
    if rare:
        n = e.reach[rare[0]]
        plural = "s" if n != 1 else ""
        return Alternative(name, "ruled_out", site.say(f"a destination is reached by only {n}"
                           f" {{own:object{plural}}} (a common service has many)"))  # fmt: skip
    if all(n >= COMMON for n in e.reach.values()):
        least = min(e.reach.values())
        return Alternative(name, "fits", site.say(f"every destination is reached by {least} or more"
                           " {own:objects}, like a common service"))  # fmt: skip
    return Alternative(name, "unknown", "its destinations are neither rare nor common")


def _gateway(e: Evidence) -> Alternative:
    name = "A shared gateway (NAT, proxy or resolver)"
    if e.hubs:
        return Alternative(name, "fits", "the asset map names the address a shared gateway")
    if "device" not in e.object_kinds:
        return Alternative(name, "ruled_out", "it is an account, not an address")
    if e.named_hosts:
        return Alternative(name, "ruled_out", "the device is known by its host name")
    return Alternative(name, "unknown", "an address with no host name: who is behind it is not"
                       " known")  # fmt: skip


def _crawler(e: Evidence) -> Alternative:
    name = "A research crawler or a student project"
    if "beacon" in e.kinds or "persistence" in e.kinds:
        return Alternative(name, "ruled_out", "the contact is regular or repeats on several"
                           " days, not a crawl")  # fmt: skip
    if len(e.reach) >= SCATTERED:
        return Alternative(name, "fits", f"{len(e.reach)} destinations and no regular timing")
    return Alternative(name, "unknown", "no timing test answered for it")


def _noise(e: Evidence) -> Alternative:
    name = "A rule's usual noise"
    facts = sorted(e.kinds)
    if facts:
        return Alternative(name, "ruled_out", f"evidence beyond rule hits: {', '.join(facts)}")
    return Alternative(name, "fits", "only rule hits, no evidence fact")


def _old_list(e: Evidence) -> Alternative:
    name = "An old threat-list entry"
    if e.stale_intel:
        return Alternative(name, "fits", "the threat list that holds it is out of date")
    return Alternative(name, "ruled_out", "the threat list that holds it is current")


def checks(e: Evidence) -> list[Check]:
    """What ARGUS looked at for the incident, and what it found."""
    out: list[Check] = []
    if "ti" in e.kinds:
        out.append(
            Check(
                "checked",
                "on a threat list"
                + (", but the list is out of date" if e.stale_intel else " (current)"),
            )
        )
    elif e.signals & {"ti.listed", "ti.listed_remote"}:
        out.append(Check("ruled_out", "not on a threat list"))
    else:
        out.append(Check("unknown", "threat lists: not read for it"))
    if "outside" in e.kinds:
        out.append(Check("checked", "flagged by outside threat intel"))
    elif "operator" in e.kinds:
        out.append(Check("checked", "the same operator as a flagged server"))
    else:
        out.append(Check("unknown", "outside threat intel: no verdict on its destinations"))
    if e.acting:
        if "beacon" in e.kinds:
            out.append(Check("checked", "regular timing, like a beacon"))
        elif "proxy.regularity" in e.signals:
            out.append(Check("ruled_out", "no regular timing"))
        else:
            out.append(Check("unknown", "timing: not measured for it"))
        others = max(e.reach.values(), default=0) - 1
        if not e.reach:
            out.append(Check("unknown", site.say("other {own:devices}: no destination to compare")))
        elif others <= 0:
            out.append(
                Check("ruled_out", site.say("no other {own:device} reaches its destinations"))
            )
        else:
            many = "s" if others != 1 else ""
            out.append(Check("checked", site.say(
                f"up to {others} other {{own:object{many}}} reach its destinations"
            )))  # fmt: skip
        if "device" in e.object_kinds:
            # the sign-ins ARGUS looked up are on the case, beside this: the engine does not
            # read them (yet), so it says only what it weighed
            out.append(Check("unknown", "who used the device: sign-ins are not part of this"
                             " priority"))  # fmt: skip
    else:
        if "success" in e.kinds:
            out.append(Check("checked", "an answer after the attack (not verified)"))
        else:
            out.append(Check("unknown", "whether anything was served: not checked yet"))
    return out


def certainty(
    *, confirmed: bool, lanes: Collection[str], strong: bool, found: Sequence[Alternative]
) -> Certainty:
    """The certainty word: Confirmed (a person), Likely (decisive with a strong fact and nothing
    benign that fits), Suspected (in a lane), Unclear (a benign explanation fits beside a strong
    fact, or only the gray band holds it), Likely harmless (a benign explanation fits and no
    strong fact)."""
    if confirmed:
        return "Confirmed"
    fits = any(a.state == "fits" for a in found)
    if fits:
        return "Unclear" if strong else "Likely harmless"
    if not lanes:
        return "Unclear"
    if "decisive" in lanes and strong:
        return "Likely"
    return "Suspected"
