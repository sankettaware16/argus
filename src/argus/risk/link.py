"""Step 6 of the engine (E2): the graph. Campus objects in a lane (and the campaign lane's) are
joined into **components**, one per incident, through what they share. Pure: the pass and the
replay run it unchanged.

**Links**, best first (each pair keeps its best; every link carries a one-sentence reason):

1. the same **host** name (an identity alias of the host's own address), 7 days apart at most;
   never through an address several hosts held (unless the asset map says it is one device:
   then never through one several hosts held on one day), nor a host seen on many addresses;
2. one **account** behind both (a ``likely`` SSO sign-in in the same hour), 24 hours;
3. a **flagged** outside thing (an outside detection, threat intel, an operator's campaign, a
   person), 7 days, reached by at most 500 campus objects;
4. a **rare** domain (or hash, sender, path pattern): reached by at most 6 campus objects and
   not a popular site, 48 hours;
5. a **bare** outside address (not flagged): reached by at most 3 campus objects, 8 hours.

Objects acting on an outside thing and campus targets it acted on are linked apart: targets only
to targets, flagged or rare within the rare limit (threat lists hold every internet scanner),
and never through a bare address (inbound scanning is the digest's until the exposure lane).

**Never:** a hub (an asset-map role, a resolver, or fan-in: an object reaching many outside
things), shared infrastructure (dropped when observed), or a noisy source (its observations add
score, never a link). An object outside every lane joins only through links 1-3 and at most
``depth`` steps from one in a lane. **Caps**: risk objects per incident (devices, accounts and
sites; a campaign may hold more); past a cap a link is kept as a recommendation only. The
**campaign lane** (L4): a flagged outside thing reached by several campus devices, or a campaign
of ``argus.campaigns``, makes its devices candidates bound together.
"""

from __future__ import annotations

import bisect
import itertools
from collections import defaultdict
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Literal

from argus import site
from argus.risk.identity import SignIn, device_of
from argus.risk.incident_config import IncidentConfig
from argus.risk.observe import ObjectRef, Observation
from argus.risk.score import Stats

Via = Literal["host", "account", "flagged", "rare", "bare_ip", "campaign"]
PRIORITY: Mapping[str, int] = {
    "host": 1, "account": 2, "flagged": 3, "campaign": 3, "rare": 4, "bare_ip": 5,
}  # fmt: skip
RARE_KINDS = frozenset({"domain", "hash", "email", "url_pattern"})
FLAG_WORDS: Mapping[str, str] = {
    "outside": "flagged by outside threat intel",
    "ti": "on a threat-intel list",
    "operator": "the same operator as a flagged destination",
    "campaign": "part of a campaign",
    "person": "flagged by a person",
}
KIND_WORDS: Mapping[str, str] = {
    "ip": "outside address", "domain": "domain", "hash": "file", "email": "sender",
    "url_pattern": "path pattern",
}  # fmt: skip


@dataclass(frozen=True)
class Flag:
    """An outside thing marked as bad, and from when (None: known from the start)."""

    source: str
    at: datetime | None = None


@dataclass(frozen=True)
class Binding:
    """A campaign (L4): campus objects bound by flagged outside things."""

    key: str
    objects: frozenset[ObjectRef]
    threats: tuple[str, ...]
    reason: str


@dataclass(frozen=True, order=True)
class Link:
    """Why two objects are in one incident (``b`` None: why ``a`` is in it at all)."""

    a: ObjectRef
    b: ObjectRef | None
    via: Via | Literal["lane"]
    value: str
    priority: int
    delta: timedelta
    reason: str
    kept: bool = True


@dataclass(frozen=True)
class Component:
    """One incident's objects at this pass: those in a lane, those pulled in, and the links."""

    objects: tuple[ObjectRef, ...]
    lanes: Mapping[ObjectRef, tuple[str, ...]]
    links: tuple[Link, ...]
    campaign: bool
    recommended: tuple[Link, ...] = ()

    @property
    def devices(self) -> int:
        return len({device_of(o) for o in self.objects if o.kind == "device"})

    @property
    def size(self) -> int:
        """Its risk objects, as the caps count them (a device's days are one)."""
        return len({device_of(o) for o in self.objects})


@dataclass(frozen=True)
class World:
    """What linking reads beyond the observations."""

    flags: Mapping[str, Flag] = field(default_factory=dict)  # threat -> its flag
    popular: Collection[str] = frozenset()  # threats a web-popularity list ranks
    hubs: Mapping[ObjectRef, str] = field(default_factory=dict)  # object -> why it is a hub
    sign_ins: Sequence[SignIn] = ()
    hosts: Sequence[tuple[ObjectRef, ObjectRef, datetime, datetime]] = ()  # (ip, host, from, to)
    bindings: Sequence[Binding] = ()  # campaigns of argus.campaigns
    # the asset map says the address is one device (a /32, or stated static); None: none is
    one_device: Callable[[ObjectRef], bool] | None = None


def short(value: str, keep: int = 60) -> str:
    return value if len(value) <= keep else value[: keep - 1] + "…"


def _gap(delta: timedelta) -> str:
    hours = delta.total_seconds() / 3600
    if hours < 1:
        return "within the hour"
    if hours < 48:
        return f"{round(hours)} h apart"
    return f"{round(hours / 24)} days apart"


def reason_of(via: str, value: str, delta: timedelta, flag: Flag | None = None,
              reach: int = 0) -> str:  # fmt: skip
    """The link's one sentence, at most 200 characters."""
    kind, _, bare = value.partition(":")
    noun = KIND_WORDS.get(kind, kind)
    if via == "host":
        text = f"the same host {short(bare)}, {_gap(delta)}"
    elif via == "account":
        text = f"the same account {short(bare)} signed in from both, {_gap(delta)}"
    elif via == "signin":
        text = f"the account {short(bare)} signed in from this device (likely, the same hour)"
    elif via == "flagged":
        words = FLAG_WORDS.get(flag.source, "flagged") if flag else "flagged"
        text = f"the same {noun} {short(bare)} ({words}), {_gap(delta)}"
    elif via == "campaign":
        text = f"one campaign: {short(bare, 120)}"
    elif via == "rare":
        text = site.say(
            f"the same rare {noun} {short(bare)} (reached by {reach} {{own:objects}}), "
            f"{_gap(delta)}"
        )
    else:
        text = site.say(
            f"the same {noun} {short(bare)} (reached by {reach} {{own:objects}}), {_gap(delta)}"
        )
    return text[:200]


# --------------------------------------------------------------------------- what is linkable


def flagged_at(flag: Flag | None, at: datetime) -> bool:
    return flag is not None and (flag.at is None or flag.at <= at)


def fan_in(obs: Iterable[Observation], now: datetime, hours: int) -> dict[ObjectRef, int]:
    """Distinct outside things each object reached in the last ``hours``."""
    since = now - timedelta(hours=hours)
    seen: dict[ObjectRef, set[str]] = defaultdict(set)
    for o in obs:
        if o.source_kind == "rule" and since <= o.at <= now:
            seen[o.object].update(o.threats)
    return {ref: len(t) for ref, t in seen.items()}


def hubs_of(obs: Sequence[Observation], now: datetime, config: IncidentConfig,
            known: Mapping[ObjectRef, str]) -> dict[ObjectRef, str]:  # fmt: skip
    """The hubs: those the asset map names (``known``), and measured fan-in."""
    out = dict(known)
    for ref, n in fan_in(obs, now, config.hubs.fan_in_hours).items():
        if n >= config.hubs.fan_in and ref not in out:
            out[ref] = f"reached {n} outside things in {config.hubs.fan_in_hours} h"
    return out


@dataclass
class _Carrier:
    times: list[datetime]
    roles: set[str]


def carriers(
    obs: Iterable[Observation], now: datetime, config: IncidentConfig, stats: Stats,
    hubs: Collection[ObjectRef],
) -> dict[str, dict[ObjectRef, _Carrier]]:  # fmt: skip
    """For each outside thing, the objects whose non-noisy rule observations carry it in the
    longest link window (hubs left out), with the times they did."""
    since = now - max(config.links.flagged.span, config.links.rare.span,
                      config.links.bare_ip.span)  # fmt: skip
    out: dict[str, dict[ObjectRef, _Carrier]] = defaultdict(dict)
    for o in obs:
        if o.source_kind != "rule" or not o.threats or not since <= o.at <= now:
            continue
        if o.object in hubs or stats.of(o.source_key, o.role).prevalence < config.noisy_prevalence:
            continue
        for t in o.threats:
            held = out[t].get(o.object)
            if held is None:
                out[t][o.object] = _Carrier([o.at], {o.role})
            else:
                held.times.append(o.at)
                held.roles.add(o.role)
    for per in out.values():
        for c in per.values():
            c.times.sort()
    return out


def _kind_of(threat: str, flag: Flag | None, at: datetime, inbound: bool, reach: int,
             popular: Collection[str], config: IncidentConfig) -> Via | None:  # fmt: skip
    """How the outside thing may link at ``at`` (None: it may not)."""
    kind = threat.split(":", 1)[0]
    links = config.links
    if threat in popular:  # a popular site on a list is a false positive far more often
        return None
    if flagged_at(flag, at):
        limit = links.rare.max_reach if inbound else links.flagged.max_reach
        if reach <= limit:
            return "flagged"
    if kind in RARE_KINDS and reach <= links.rare.max_reach:
        return "rare"
    if kind == "ip" and not inbound and reach <= links.bare_ip.max_reach:
        return "bare_ip"
    return None


def _window(via: str, config: IncidentConfig) -> timedelta:
    return {"flagged": config.links.flagged.span, "rare": config.links.rare.span,
            "bare_ip": config.links.bare_ip.span}[via]  # fmt: skip


def _apart(times: Sequence[datetime], start: datetime, end: datetime) -> timedelta | None:
    """The least time between one of ``times`` and the interval (None: no times)."""
    if not times:
        return None
    return min(max(timedelta(0), start - t, t - end) for t in times)


def linkable_hosts(
    hosts: Iterable[tuple[ObjectRef, ObjectRef, datetime, datetime]], now: datetime,
    config: IncidentConfig, one_device: Callable[[ObjectRef], bool] | None = None,
) -> list[tuple[ObjectRef, ObjectRef, datetime, datetime]]:  # fmt: skip
    """The host aliases that may link at ``now``: known by then, in the host window, and never
    ambiguous. An address two hosts held in the window links neither (a reused address), unless
    the asset map says it is one device (then only two hosts on one day refuse it); a host seen
    on more than ``max_addresses`` addresses links through none of them."""
    span = config.links.host.span
    fresh = [(ip, host, a, b) for ip, host, a, b in hosts if a <= now and now - b <= span]
    held: dict[ObjectRef, set[ObjectRef]] = defaultdict(set)
    a_day: dict[tuple[ObjectRef, date], set[ObjectRef]] = defaultdict(set)
    addresses: dict[ObjectRef, set[str]] = defaultdict(set)
    for ip, host, start, _ in fresh:
        held[ip].add(host)
        a_day[(ip, start.date())].add(host)
        addresses[host].add(device_of(ip))
    out = []
    for ip, host, start, end in fresh:
        if len(addresses[host]) > config.links.host.max_addresses:
            continue
        several = a_day[(ip, start.date())] if one_device and one_device(ip) else held[ip]
        if len(several) > 1:
            continue
        out.append((ip, host, start, end))
    return sorted(out, key=lambda h: (h[0], h[1], h[2]))


def _closest(a: Sequence[datetime], b: Sequence[datetime]) -> timedelta:
    """The least time between a time of ``a`` and one of ``b`` (both sorted)."""
    best = timedelta.max
    for t in a:
        i = bisect.bisect_left(b, t)
        for j in (i - 1, i):
            if 0 <= j < len(b):
                best = min(best, abs(t - b[j]))
    return best


# --------------------------------------------------------------------------- the edges


Edge = tuple[ObjectRef, ObjectRef, Link]


def edges(
    obs: Sequence[Observation], now: datetime, config: IncidentConfig, stats: Stats,
    world: World, hubs: Collection[ObjectRef],
) -> dict[tuple[ObjectRef, ObjectRef], Link]:  # fmt: skip
    """Every pair of objects that may be linked, with its best link. For an outside thing the
    objects carrying it are chained in time order (each to the nearest earlier one in the
    window), so a thing many objects share gives a spanning chain, not every pair."""
    best: dict[tuple[ObjectRef, ObjectRef], Link] = {}

    def offer(a: ObjectRef, b: ObjectRef, link: Link) -> None:
        if a == b or a in hubs or b in hubs:
            return
        pair = (a, b) if a < b else (b, a)
        held = best.get(pair)
        if held is None or (link.priority, link.delta, link.value) < (
            held.priority, held.delta, held.value
        ):  # fmt: skip
            best[pair] = Link(pair[0], pair[1], link.via, link.value, link.priority, link.delta,
                              link.reason)  # fmt: skip

    for threat, everyone in sorted(carriers(obs, now, config, stats, hubs).items()):
        if len(everyone) < 2:
            continue
        flag = world.flags.get(threat)
        # those acting on it (reach: every campus object it touched), and the campus targets it
        # acted on, linked only to one another (reach: the targets)
        acting = {r: c for r, c in everyone.items() if "actor" in c.roles}
        reached = {r: c for r, c in everyone.items() if "actor" not in c.roles}
        for per, inbound, reach in ((acting, False, len(everyone)),
                                    (reached, True, len(reached))):  # fmt: skip
            if len(per) < 2:
                continue
            via = _kind_of(threat, flag, now, inbound, reach, world.popular, config)
            if via is None:
                continue
            span = _window(via, config)
            timeline = sorted((c.times[0], ref) for ref, c in per.items())
            for n in range(1, len(timeline)):
                ref = timeline[n][1]
                for back in range(n - 1, -1, -1):
                    other = timeline[back][1]
                    delta = _closest(per[ref].times, per[other].times)
                    if delta <= span:
                        why = reason_of(via, threat, delta, flag, reach)
                        offer(other, ref, Link(other, ref, via, threat, PRIORITY[via], delta, why))
                        break
                    if timeline[n][0] - timeline[back][0] > span + timedelta(days=30):
                        break
    # identity: a host name seen on an address, and one account behind several devices
    aliases = linkable_hosts(world.hosts, now, config, world.one_device)
    wanted = {ip for ip, _, _, _ in aliases}
    seen_at: dict[ObjectRef, list[datetime]] = defaultdict(list)
    for o in obs:
        if o.object in wanted and o.at <= now:
            seen_at[o.object].append(o.at)
    for ip_ref, host_ref, start, end in aliases:
        # the address's activity against when the host had it (no activity: the alias's age)
        apart = _apart(seen_at.get(ip_ref, ()), start, end)
        gap = max(timedelta(0), now - end) if apart is None else apart
        if gap <= config.links.host.span:
            why = reason_of("host", host_ref.key, gap)
            link = Link(ip_ref, host_ref, "host", host_ref.key, PRIORITY["host"], gap, why)
            offer(ip_ref, host_ref, link)
    by_user: dict[str, list[SignIn]] = defaultdict(list)
    for s in world.sign_ins:
        if s.start <= now:
            by_user[s.user].append(s)
    span = config.links.account.span
    for user, seen in sorted(by_user.items()):
        node = ObjectRef("account", user)  # the account itself, when it is an object
        ordered = sorted(seen, key=lambda s: (s.start, s.device))
        for n, s in enumerate(ordered):
            value = f"user:{user}"
            why = reason_of("signin", value, timedelta(0))
            offer(s.device, node, Link(s.device, node, "account", value, PRIORITY["account"],
                                       timedelta(0), why))  # fmt: skip
            for back in range(n - 1, -1, -1):  # the device the same person used before
                prior = ordered[back]
                if prior.device == s.device:
                    continue
                gap = max(timedelta(0), s.start - prior.end)
                if gap <= span:
                    offer(prior.device, s.device, Link(
                        prior.device, s.device, "account", value, PRIORITY["account"], gap,
                        reason_of("account", value, gap),
                    ))  # fmt: skip
                break
    return best


# --------------------------------------------------------------------------- the campaign lane


def campaign_lane(
    obs: Sequence[Observation], now: datetime, config: IncidentConfig, stats: Stats,
    world: World, hubs: Collection[ObjectRef],
) -> list[Binding]:  # fmt: skip
    """The campaigns: those of ``argus.campaigns`` (``world.bindings``), and each flagged outside
    thing that several campus devices acting outward reached in the campaign window."""
    since = now - timedelta(hours=config.campaign.hours)
    reached: dict[str, set[ObjectRef]] = defaultdict(set)
    for o in obs:
        if (o.source_kind != "rule" or o.role != "actor" or o.object in hubs
                or not since <= o.at <= now):  # fmt: skip
            continue
        if stats.of(o.source_key, o.role).prevalence < config.noisy_prevalence:
            continue
        for t in o.threats:
            if flagged_at(world.flags.get(t), now) and t not in world.popular:
                reached[t].add(o.object)
    out = [b for b in world.bindings if len({device_of(r) for r in b.objects - set(hubs)})
           >= config.campaign.min_devices]  # fmt: skip
    for threat, refs in sorted(reached.items()):
        devices = {device_of(r) for r in refs if r.kind == "device"}
        if len(devices) < config.campaign.min_devices:
            continue
        if len(refs) > config.links.flagged.max_reach:
            continue
        flag = world.flags[threat]
        kind, _, bare = threat.partition(":")
        out.append(Binding(
            f"threat:{threat}", frozenset(refs), (threat,),
            site.say(f"{len(devices)} {{own:devices}} reached the {KIND_WORDS.get(kind, kind)} "
                     f"{short(bare)} ({FLAG_WORDS.get(flag.source, 'flagged')})"),
        ))  # fmt: skip
    return out


# --------------------------------------------------------------------------- the components


def components(
    candidates: Mapping[ObjectRef, tuple[str, ...]],
    pairs: Mapping[tuple[ObjectRef, ObjectRef], Link],
    bindings: Sequence[Binding], config: IncidentConfig, present: Collection[ObjectRef],
    hubs: Collection[ObjectRef], object_cap: Callable[[bool], int] | None = None,
) -> list[Component]:  # fmt: skip
    """Join the candidates (object -> its lanes) into components through ``pairs`` (the best
    link of each pair) and the campaigns. ``present``: objects with an observation in the
    window (only they may be pulled in). Deterministic: candidates in key order, links by
    priority then time, then value."""
    lanes: dict[ObjectRef, tuple[str, ...]] = dict(candidates)  # a hub in a lane stands alone
    campaign_of: dict[ObjectRef, list[Binding]] = defaultdict(list)
    for b in bindings:
        for ref in b.objects:
            if ref in hubs or ref not in present:
                continue
            campaign_of[ref].append(b)
            lanes[ref] = tuple(sorted({*lanes.get(ref, ()), "campaign"}))
    adjacency: dict[ObjectRef, list[tuple[ObjectRef, Link]]] = defaultdict(list)
    for (one, two), link in pairs.items():
        adjacency[one].append((two, link))
        adjacency[two].append((one, link))
    for b in bindings:  # a campaign's objects are bound in a chain through it
        members = sorted(r for r in b.objects if r in lanes)
        for x, y in itertools.pairwise(members):
            link = Link(x, y, "campaign", b.key, PRIORITY["campaign"], timedelta(0), b.reason[:200])
            adjacency[x].append((y, link))
            adjacency[y].append((x, link))
    for ref in adjacency:
        adjacency[ref].sort(key=lambda e: (e[1].priority, e[1].delta, e[1].value, e[0]))
    cap = object_cap or (lambda campaign: config.caps.campaign_objects if campaign
                         else config.caps.objects)  # fmt: skip
    taken: set[ObjectRef] = set()
    out: list[Component] = []
    for start in sorted(lanes):
        if start in taken:
            continue
        campaign = bool(campaign_of.get(start))
        objects = [start]
        held = {start}
        size = {device_of(start)}  # the risk objects, a device's days as one
        links: list[Link] = [Link(start, None, "lane", ",".join(lanes[start]), 0, timedelta(0),
                                  "in a lane: " + ", ".join(lanes[start]))]  # fmt: skip
        recommended: list[Link] = []
        frontier: list[tuple[ObjectRef, int]] = [(start, 0)]
        while frontier:
            here, depth = frontier.pop(0)
            for there, link in adjacency.get(here, ()):
                if there in held or there in hubs or here in hubs:
                    continue
                candidate = there in lanes
                if not candidate:
                    if link.via not in config.pull_in and link.via != "campaign":
                        continue
                    if depth + 1 > config.depth or there not in present:
                        continue
                if here not in lanes and link.via not in config.pull_in:
                    continue  # a pulled-in object brings more only through strong links
                if there in taken:
                    continue
                joins_campaign = campaign or bool(campaign_of.get(there))
                more = {device_of(there)} - size
                if len(size) + len(more) > cap(joins_campaign):
                    recommended.append(Link(
                        link.a, link.b, link.via, link.value, link.priority, link.delta,
                        (f"not joined: the incident holds {cap(joins_campaign)} risk objects; "
                         + link.reason)[:200], kept=False,
                    ))  # fmt: skip
                    continue
                campaign = joins_campaign
                held.add(there)
                size |= more
                objects.append(there)
                links.append(link)
                frontier.append((there, 0 if candidate else depth + 1))
        taken |= held
        if not any(o in lanes for o in objects):
            continue
        out.append(Component(
            tuple(sorted(objects)), {o: lanes[o] for o in objects if o in lanes},
            tuple(links), campaign, tuple(recommended),
        ))  # fmt: skip
    return out


def link_all(
    obs: Sequence[Observation], now: datetime, candidates: Mapping[ObjectRef, tuple[str, ...]],
    config: IncidentConfig, stats: Stats, world: World,
) -> list[Component]:  # fmt: skip
    """The pass's components: hubs found, the edges and the campaigns built, then joined."""
    hubs = hubs_of(obs, now, config, world.hubs)
    pairs = edges(obs, now, config, stats, world, hubs)
    bindings = campaign_lane(obs, now, config, stats, world, hubs)
    present = {o.object for o in obs if o.at <= now}
    return components(candidates, pairs, bindings, config, present, hubs)
