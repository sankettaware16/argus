"""What else an incident could be, what ARGUS checked, and its certainty word (E5), pure.

Each **benign alternative** has one deterministic test over what ARGUS's database holds (no SIEM
request, no model), and a state: ``ruled_out`` (the test says it is not that), ``fits`` (the test
says it could be) or ``unknown`` (nothing to test it with yet). Each **check** says what ARGUS
looked at: ``checked`` (it looked and found something that backs the incident), ``ruled_out`` (it
looked and found nothing) or ``unknown`` (it could not look). The **certainty word** comes from
the lanes, the strong facts and the alternatives; "Confirmed" comes only from a person.

The tests key on evidence kinds, object kinds, the asset map's roles and how many internal objects
reach a destination: never on a rule's name. What the checking lane measured for an outbound
incident (:class:`Measured`, D-323: the device's timing to its destination, how many internal
devices reached it that day, its lookups) takes the place of ARGUS's own guess where it answers:
it shows as a check and as an alternative that fits or is ruled out, so a ruling-out moves the
certainty word, never the priority."""

from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from argus import site

AltState = Literal["ruled_out", "fits", "unknown"]
CheckState = Literal["checked", "ruled_out", "unknown"]
Certainty = Literal["Confirmed", "Likely", "Suspected", "Unclear", "Likely harmless"]
CERTAINTY: tuple[Certainty, ...] = ("Confirmed", "Likely", "Suspected", "Unclear",
                                    "Likely harmless")  # fmt: skip
RARE = 6  # a destination at most this many internal objects reach is rare
COMMON = 20  # one at least this many reach is a common service
SCATTERED = 50  # this many distinct destinations, with no regular timing, is a crawler's shape
COMMON_SERVICE = "A common service (an update, telemetry or a popular site)"
ORDINARY_USE = "Ordinary use, not a beacon"


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
class Measured:
    """One answer of the checking lane for an outbound incident (D-323): ``pair`` (a device's
    requests to one destination over some hours), ``contact`` (the internal devices that reached a
    destination in a day) or ``dns`` (a device's lookups around its last alert), with its
    verdict and facts as stored."""

    kind: Literal["pair", "contact", "dns"]
    verdict: str
    device: str | None = None
    destination: str | None = None
    facts: Mapping[str, Any] = field(default_factory=dict)


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
    reach: Mapping[str, int] = field(default_factory=dict)  # outside value -> internal objects
    signals: frozenset[str] = frozenset()  # dossier signals read (known) for its alert groups
    acting: bool = True  # its objects act (outbound); False: an own site attacked from outside
    measured: tuple[Measured, ...] = ()  # what the checking lane measured for it (D-323)


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
    out = [_common(e), _gateway(e), _crawler(e), _noise(e)]
    if "beacon" in e.kinds:  # only a claimed rhythm can be ordinary use instead
        out.insert(1, _ordinary(e))
    if "ti" in e.kinds:
        out.append(_old_list(e))
    return out


def _of(e: Evidence, kind: str) -> list[Measured]:
    return [m for m in e.measured if m.kind == kind]


def _int(facts: Mapping[str, Any], name: str) -> int | None:
    value = facts.get(name)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _seconds(value: int | None) -> str:
    if value is None:
        return "?"
    if value >= 120:
        return f"{round(value / 60, 1):g} min"
    return f"{value} s"


def _size(value: int | None) -> str:
    if value is None:
        return "an unknown size"
    for unit, step in (("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)):
        if value >= step:
            return f"{value / step:.1f} {unit}"
    return f"{value} bytes"


def _devices(n: int) -> str:
    return site.say(f"{n} {{own:device{'' if n == 1 else 's'}}}")


def _day(m: Measured) -> str:
    return str(m.facts.get("day") or "the day checked")


def _so_far(m: Measured) -> bool:
    """A count of a day still going on (asked again once the day is over)."""
    return m.facts.get("complete") is False


def _on(m: Measured) -> str:
    """ "on <day>", or "on <day> up to HH:MM UTC" for a count so far."""
    window = m.facts.get("window")
    if _so_far(m) and isinstance(window, list | tuple) and len(window) == 2:
        end = str(window[1])
        if len(end) >= 16 and end[10] == "T":
            return f"on {_day(m)} up to {end[11:16]} UTC"
    return f"on {_day(m)}"


def _contacts(e: Evidence) -> list[tuple[Measured, int]]:
    """The measured contact counts (a destination's internal devices that day), fewest first."""
    found = [(m, n) for m in _of(e, "contact") if m.verdict != "unknown"
             and (n := _int(m.facts, "devices")) is not None]  # fmt: skip
    return sorted(found, key=lambda c: (c[1], str(c[0].destination)))


def _timing(m: Measured) -> str:
    f = m.facts
    return f"about every {_seconds(_int(f, 'period_s'))} (\u00b1 {_seconds(_int(f, 'jitter_s'))})"


def _hours(m: Measured) -> str:
    return f"{m.facts.get('hours', '?')} h"


def _common(e: Evidence) -> Alternative:
    """A destination many internal devices reach is a common service: the checking lane's count of
    the day when it has one, else how many internal objects ARGUS's own alerts show reaching it."""
    name = COMMON_SERVICE
    measured = _contacts(e)
    # judged: a whole day's count, or one already many; none (traffic the proxy never saw) or a
    # count so far says less, so ARGUS's own reach judges then
    known = [c for c in measured if c[1] > 0 and (c[1] >= COMMON or not _so_far(c[0]))]
    if measured and not known and not e.reach:
        m, n = measured[0]
        dst = m.destination or "its destination"
        if n == 0:
            return Alternative(name, "unknown", site.say(f"no {{own:device}} reached {dst}"
                               f" through the proxy {_on(m)}"))  # fmt: skip
        return Alternative(name, "unknown", f"{_devices(n)} contacted {dst} so far {_on(m)}:"
                           " asked again once the day is over")  # fmt: skip
    if known:
        m, n = known[0]
        dst = m.destination or "its destination"
        if m.facts.get("from") == "argus":
            return Alternative(name, "fits", f"ARGUS's own alerts name {dst} with "
                               f"{_devices(n)}, too many to ask about")  # fmt: skip
        if n <= RARE:
            return Alternative(name, "ruled_out", f"only {_devices(n)} contacted {dst} {_on(m)}"
                               " (a common service has many)")  # fmt: skip
        if n >= COMMON:
            return Alternative(name, "fits", f"{_devices(n)} contacted {dst} {_on(m)}, like a"
                               " common service")  # fmt: skip
        return Alternative(name, "unknown", f"{_devices(n)} contacted {dst} {_on(m)}: neither"
                           " few nor many")  # fmt: skip
    if not e.reach:
        return Alternative(name, "unknown", "no outside destination is named in its alerts")
    rare = sorted(v for v, n in e.reach.items() if n <= RARE)
    common = [n for n in e.reach.values() if n >= COMMON]
    if (
        rare and common
    ):  # one rare destination never outweighs those half the organisation's network reaches
        many, verb = len(common), "is" if len(common) == 1 else "are"
        return Alternative(name, "unknown", site.say(f"{many} of its {len(e.reach)} destinations"
                           f" {verb} reached by {max(common)} or more {{own:objects}}, like a"
                           " common service; the others by only a few"))  # fmt: skip
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


def _ordinary(e: Evidence) -> Alternative:
    """A beacon's even timing against a person's or a program's ordinary use: the checking
    lane's timing of the device's requests to its destination."""
    name = ORDINARY_USE
    pairs = _of(e, "pair")
    regular = [m for m in pairs if m.verdict == "regular"]
    if regular:
        m = regular[0]
        return Alternative(name, "ruled_out", f"requests to {m.destination} {_timing(m)}:"
                           " ordinary use is not this regular")  # fmt: skip
    timed = [m for m in pairs if m.verdict in ("regular", "irregular")]
    if timed:
        m = timed[0]
        requests = _int(m.facts, "requests") or 0
        return Alternative(name, "fits", f"no regular timing to {m.destination} in {requests}"
                           f" requests over {_hours(m)}")  # fmt: skip
    if any(m.verdict == "few" for m in pairs):
        return Alternative(name, "unknown", "too few requests to its destination to judge the"
                           " timing")  # fmt: skip
    silent = next((m for m in pairs if m.verdict == "none"), None)
    if silent is not None:  # its traffic does not pass the proxy (another port or protocol)
        return Alternative(name, "unknown", f"no request to {silent.destination} in the proxy"
                           f" logs over {_hours(silent)}, so its timing could not be measured"
                           " there")  # fmt: skip
    return Alternative(name, "unknown", "the device's timing to its destination is not measured"
                       " yet")  # fmt: skip


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
    name = "A research crawler or a personal project"
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
        timing = _timing_check(e)
        if timing is not None:
            out.append(timing)
        elif "beacon" in e.kinds:
            out.append(Check("checked", "regular timing, like a beacon"))
        elif "proxy.regularity" in e.signals:
            out.append(Check("ruled_out", "no regular timing"))
        else:
            out.append(Check("unknown", "timing: not measured for it"))
        others = max(e.reach.values(), default=0) - 1
        reached = _contact_checks(e)
        if reached:
            out += reached
        elif not e.reach:
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
        out += _dns_checks(e)
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


def _timing_check(e: Evidence) -> Check | None:
    """The most telling timing the checking lane measured (regular, then not regular, then too
    few requests, then none, then a check that did not answer), or None."""
    pairs = _of(e, "pair")
    for verdict in ("regular", "irregular", "few", "none", "unknown"):
        m = next((p for p in pairs if p.verdict == verdict), None)
        if m is None:
            continue
        dev, dst, f = m.device, m.destination, m.facts
        requests = _int(f, "requests") or 0
        if verdict == "regular":
            return Check("checked", f"regular requests from {dev} to {dst} {_timing(m)}:"
                         f" {requests} requests, {_size(_int(f, 'bytes'))} in {_hours(m)}"
                         " (proxy logs)")  # fmt: skip
        if verdict == "irregular":
            return Check("ruled_out", f"no regular timing from {dev} to {dst}: {requests}"
                         f" requests in {_hours(m)} (proxy logs)")  # fmt: skip
        if verdict == "few":
            return Check("unknown", f"timing from {dev} to {dst}: {requests} requests in"
                         f" {_hours(m)}, too few to tell")  # fmt: skip
        if verdict == "none":
            return Check("unknown", f"timing: no request from {dev} to {dst} in the"
                         f" {_hours(m)} checked (proxy logs)")  # fmt: skip
        return Check("unknown", f"timing from {dev} to {dst}: {f.get('reason') or 'no answer'}")
    return None


def _contact_checks(e: Evidence) -> list[Check]:
    """How many internal devices reached each destination the checking lane asked about."""
    out: list[Check] = []
    for m in _of(e, "contact"):
        dst, n = m.destination, _int(m.facts, "devices")
        if m.verdict == "unknown" or n is None:
            out.append(Check("unknown", site.say(f"other {{own:devices}} reaching {dst}:"
                             f" {m.facts.get('reason') or 'no answer'}")))  # fmt: skip
        elif m.facts.get("from") == "argus":
            out.append(Check("checked", f"{dst} is too common to ask about: ARGUS's own alerts"
                             f" name it with {_devices(n)}"))  # fmt: skip
        elif n == 0:
            out.append(Check("unknown", site.say(f"no {{own:device}} reached {dst} through the"
                             f" proxy {_on(m)}")))  # fmt: skip
        elif _so_far(m) and n < COMMON:  # the day is not over: asked again once it is
            out.append(Check("unknown", f"{_devices(n)} contacted {dst} so far {_on(m)} (proxy"
                             " logs; the whole day is asked once it is over)"))  # fmt: skip
        elif n == 1:
            out.append(Check("ruled_out", site.say(f"no other {{own:device}} contacted {dst}"
                             f" {_on(m)} (proxy logs)")))  # fmt: skip
        else:
            out.append(Check("checked", f"{_devices(n)} contacted {dst} {_on(m)} (proxy"
                             " logs)"))  # fmt: skip
    return out


def _dns_checks(e: Evidence) -> list[Check]:
    out: list[Check] = []
    for m in _of(e, "dns"):
        f, dev = m.facts, m.device
        said = f"{_int(f, 'lookups') or 0} DNS lookups of {_int(f, 'names') or 0} names by {dev}"
        if m.verdict == "tunnel":
            out.append(Check("checked", f"{said} around its last alert; most rarely asked names"
                             " share one parent, as a tunnel's do"))  # fmt: skip
        elif m.verdict == "plain":
            out.append(Check("ruled_out", f"{said} around its last alert, none shaped like a"
                             " tunnel"))  # fmt: skip
        elif m.verdict == "none":
            out.append(Check("unknown", f"no DNS lookup by {dev} around its last alert"))
        else:
            out.append(Check("unknown", f"DNS lookups of {dev}: {f.get('reason') or 'no answer'}"))
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
