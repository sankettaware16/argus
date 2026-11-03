"""A notified case as a known infection: the pure rules.

Once a person records that a device's owner was told, the case is a **fingerprint**
(:class:`Print`): its devices and its destinations (servers, names, families, evidence flags,
services, data moved). An investigation of its device is **changed** when it brings something new
(raised once, and a change until a person reviews it), **known** when it brings nothing new (joins
silently, counted, never raised), else not the case's. :func:`reminders`, :func:`stopped` and
:func:`moved` are the clock rules: reminders after 7 and 21 days, a proposal to close after 14
quiet days, and a new address with the same indicators as one that went quiet is probably the
same device."""

from __future__ import annotations

import uuid
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from argus import site
from argus.outside.psl import registered_parent

Key = tuple[str, str]
Outcome = Literal["known", "changed"]
Reminder = Literal["notify_again", "network_action"]
REMINDER_KINDS: tuple[Reminder, ...] = ("notify_again", "network_action")
CHANGED = "changed since notice: "
WHY_LIMIT = 500  # the column's limit (case_known_matches.why)
SHOWN = 3  # values a reason names before "and N more"
DEVICE_KINDS = ("ip", "host", "user")
IDENTITY_KINDS = ("ip", "host")  # a device is told by its address or its host name, not a user
DESTINATION_KINDS = ("ip", "domain")
NEW_PER_SUBJECT = 25  # new destinations one investigation adds to the case
NEW_PER_CASE = 500  # new destinations a case keeps (the pass stops adding past it)
# kinds of the keys a notice adds to what the case's rows already hold (``case_known_keys``)
SEED = "seed"
FLAG = "flag"
DESTINATION = "destination"
FAMILY = "family"
SERVICE = "service"
BYTES = "bytes"
NEW_DESTINATION = "new_destination"  # reached, not flagged, not held: counted on the case


class Rules(BaseModel):
    """The days and limits the known infection runs by (the settings' ``notified`` section)."""

    model_config = ConfigDict(frozen=True)

    renotify_days: int = Field(default=7, ge=1)
    network_days: int = Field(default=21, ge=1)
    quiet_days: int = Field(default=14, ge=1)
    active_days: int = Field(default=3, ge=1)
    move_window: timedelta = timedelta(hours=72)
    move_gap: timedelta = timedelta(hours=2)
    move_similarity: float = Field(default=0.8, gt=0, le=1)
    volume_factor: float = Field(default=10.0, gt=1)
    managed_types: frozenset[str] = frozenset(
        {"lab", "computer-room"}
    )  # site types that count as managed
    reopen_days: int = Field(default=30, ge=1)  # a "stopped" case still starts a change check


@dataclass(frozen=True)
class Print:
    """What the known infection of a case already holds."""

    devices: frozenset[Key] = frozenset()
    destinations: frozenset[Key] = frozenset()
    families: frozenset[str] = frozenset()
    flags: frozenset[str] = frozenset()
    services: frozenset[Key] = frozenset()
    bytes: int | None = None  # the data level at the notice, or at the last spoken change
    # reached since the notice, not flagged, not held: counted on the case (``Adds.seen``). They
    # are not "held": a later flag on one is a change, and reaching one is no reason to be known.
    seen: frozenset[Key] = frozenset()

    def knows(self, key: Key) -> bool:
        """Whether an address or a name is part of the infection: held itself, or a name under a
        family the case holds."""
        if key in self.destinations:
            return True
        return key[0] == "domain" and parent_of(key[1]) in self.families

    def counted(self, key: Key) -> bool:
        """Whether the case has the destination already, held or noted as new."""
        return key in self.seen or self.knows(key)

    def lone_address(self) -> Key | None:
        """The one address of the case when it holds exactly one device: the only case where a
        new address can be the same device moving. Host and user keys are read as the
        same machine's; a case with two addresses never merges a third."""
        addresses = [k for k in self.devices if k[0] == "ip"]
        return addresses[0] if len(addresses) == 1 else None


@dataclass(frozen=True)
class Subject:
    """An investigation as the known infection sees it."""

    investigation_id: uuid.UUID
    version: int
    devices: frozenset[Key]  # the internal devices and the host and user keys it names
    destinations: frozenset[Key]  # outside addresses and names it involves (never shared or
    # popular ones: those are held by every case)
    flagged: frozenset[Key] = frozenset()  # of them (or their parents), on a list or detected
    flags: tuple[str, ...] = ()  # the evidence flags of its newest dossier
    services: frozenset[Key] = frozenset()  # internal services among its entities
    bytes: int | None = None  # the data its hosts sent, when the evidence carries it
    first_event_at: datetime | None = None
    last_event_at: datetime | None = None
    severity: str = "medium"  # the rule's rating, for the case's severity when it joins


@dataclass(frozen=True)
class Adds:
    """What a change brings, so that it becomes known (a change speaks once)."""

    destinations: frozenset[Key] = frozenset()
    families: frozenset[str] = frozenset()
    flags: frozenset[str] = frozenset()
    services: frozenset[Key] = frozenset()
    bytes: int | None = None  # only a spoken change moves the level, never a known verdict
    seen: frozenset[Key] = frozenset()  # new destinations, not flagged: noted, not raised

    def rows(self) -> list[tuple[str, str]]:
        """(kind, value) rows for ``case_known_keys``."""
        out = [(DESTINATION, join(k)) for k in sorted(self.destinations)]
        out += [(FAMILY, f) for f in sorted(self.families)]
        out += [(FLAG, f) for f in sorted(self.flags)]
        out += [(SERVICE, join(k)) for k in sorted(self.services)]
        out += [(NEW_DESTINATION, join(k)) for k in sorted(self.seen)]
        if self.bytes is not None:
            out.append((BYTES, str(self.bytes)))
        return out


@dataclass(frozen=True)
class Verdict:
    outcome: Outcome | None  # None: not this infection's
    changes: tuple[str, ...] = ()
    adds: Adds = field(default_factory=Adds)
    volume_judged: bool = True  # False: the investigation or the case has no byte count

    @property
    def why(self) -> str | None:
        """ "changed since notice: ..." for a change, else None."""
        if self.outcome != "changed":
            return None
        return (CHANGED + "; ".join(self.changes))[:WHY_LIMIT]


def join(key: Key) -> str:
    """A key as one stored value: ``ip:10.1.2.3``."""
    return f"{key[0]}:{key[1]}"


def split(value: str) -> Key | None:
    kind, sep, rest = value.partition(":")
    return (kind, rest) if sep and rest else None


def parent_of(name: str) -> str | None:
    """The registered parent of a name (its family), or None."""
    return registered_parent(name)


def families_of(destinations: Iterable[Key]) -> frozenset[str]:
    return frozenset(
        p for kind, value in destinations if kind == "domain" and (p := parent_of(value))
    )


def print_of(
    devices: Iterable[Key],
    indicators: Iterable[Key],
    keys: Iterable[tuple[str, str]] = (),
) -> Print:
    """The fingerprint from the case's own rows (its actors and its c2 or other indicators) and
    the keys the notice and the changes added. A device key is an address, a host or a user; a
    destination an address or a name."""
    held = [(k, v) for k, v in keys if k != SEED]
    extra = {
        kind: [value for k, value in held if k == kind]
        for kind in (DESTINATION, FAMILY, FLAG, SERVICE, BYTES, NEW_DESTINATION)
    }
    destinations = {k for k in indicators if k[0] in DESTINATION_KINDS}
    destinations |= {s for v in extra[DESTINATION] if (s := split(v)) is not None}
    sizes = [n for v in extra[BYTES] if v.isdigit() and (n := int(v)) > 0]
    return Print(
        devices=frozenset(k for k in devices if k[0] in DEVICE_KINDS),
        destinations=frozenset(destinations),
        families=families_of(destinations) | frozenset(extra[FAMILY]),
        flags=frozenset(extra[FLAG]),
        services=frozenset(s for v in extra[SERVICE] if (s := split(v)) is not None),
        bytes=max(sizes) if sizes else None,  # a level of 0 is "not judged", as none is
        seen=frozenset(s for v in extra[NEW_DESTINATION] if (s := split(v)) is not None),
    )


def _few(values: Sequence[str]) -> str:
    shown = ", ".join(values[:SHOWN])
    return shown + (f" and {len(values) - SHOWN} more" if len(values) > SHOWN else "")


def own_device(fp: Print, subject: Subject) -> bool:
    """Whether an investigation is the notified device's alone: it names the case's device
    by an address or a host name (a user shared with another machine does not), and every device
    it lists is one the case holds. An internal address the case does not hold is another person's
    laptop or a lateral move: never absorbed, the normal pipeline decides. An internal service
    among the entities is judged by its own rule (:func:`evaluate`), not as a device."""
    if not any(k[0] in IDENTITY_KINDS for k in subject.devices & fp.devices):
        return False
    return not (subject.devices - fp.devices - subject.services)


def evaluate(fp: Print, subject: Subject, *, volume_factor: float = 10.0) -> Verdict:
    """What an investigation is to the known infection of a case (see the module's docstring)."""
    if not own_device(fp, subject):
        return Verdict(None)
    changes: list[str] = []
    new_destinations = sorted(k for k in subject.flagged if not fp.knows(k))
    if new_destinations:
        changes.append("a new flagged destination (" + _few([k[1] for k in new_destinations]) + ")")
    new_flags = sorted(f for f in subject.flags if f not in fp.flags)
    if new_flags:
        changes.append("a kind of evidence the case did not have (" + _few(new_flags) + ")")
    new_services = sorted(
        k for k in subject.services if k not in fp.services and k not in fp.devices
    )
    if new_services:
        changes.append(
            site.say("{a_kind} service is involved (") + _few([k[1] for k in new_services]) + ")"
        )
    # The level is the one at the notice (or at the last spoken change): 0 or none is "not
    # judged", and a known verdict never raises it, so growth by small steps cannot creep past it.
    level = fp.bytes
    judged = subject.bytes is not None and level is not None and level > 0
    more = False
    if judged:
        assert subject.bytes is not None
        assert level is not None
        more = subject.bytes >= volume_factor * level and subject.bytes > level
        if more:
            times = round(subject.bytes / level)
            changes.append(f"much more traffic than at the notice (about {times} times)")
    unflagged = sorted(
        k for k in subject.destinations if k not in subject.flagged and not fp.counted(k)
    )[:NEW_PER_SUBJECT]
    if changes:
        adds = Adds(
            frozenset(new_destinations),
            families_of(new_destinations),
            frozenset(new_flags),
            frozenset(new_services),
            subject.bytes if more else None,
            frozenset(unflagged),
        )
        return Verdict("changed", tuple(changes), adds, volume_judged=judged)
    if any(fp.knows(k) for k in subject.destinations):
        return Verdict("known", (), Adds(seen=frozenset(unflagged)), volume_judged=judged)
    return Verdict(None, volume_judged=judged)


@dataclass(frozen=True)
class Prior:
    """What the pass decided about an investigation before (its ``case_known_matches`` row)."""

    outcome: Outcome
    why: str | None
    changed_version: int | None  # the version at which the unreviewed change was decided


@dataclass(frozen=True)
class Settled:
    outcome: Outcome
    why: str | None
    changed_version: int | None


def settle(prior: Prior | None, verdict: Verdict, version: int, *, reviewed: bool) -> Settled:
    """What to record for an investigation the pass decided: a change is durable. An
    investigation decided ``changed`` stays changed, with its reason, whatever the next version
    decides, until a person reviews a version of it at or after the change (``reviewed``); only
    then may a later version be known. A later change adds its reason to the one kept.
    ``verdict`` is a decision (known or changed)."""
    assert verdict.outcome is not None
    waiting = (
        prior is not None
        and prior.outcome == "changed"
        and prior.changed_version is not None
        and not reviewed
    )
    if waiting:
        assert prior is not None
        said = prior.why or CHANGED.rstrip(": ")
        fresh = [c for c in verdict.changes if c not in said]
        if fresh and verdict.outcome == "changed":
            said = (said + "; " + "; ".join(fresh))[:WHY_LIMIT]
        return Settled("changed", said, prior.changed_version)
    if verdict.outcome == "changed":
        return Settled("changed", verdict.why, version)
    return Settled("known", None, None)


def resurfaced(subject: Subject, moves: Mapping[str, datetime]) -> list[str]:
    """The old addresses of moves (address -> when the new address first alerted) that the
    investigation lists and that alerted again after the move: the case has two devices,
    not one that moved."""
    if subject.last_event_at is None:
        return []
    return sorted(
        old for old, since in moves.items()
        if ("ip", old) in subject.devices and subject.last_event_at > since
    )  # fmt: skip


def partition(
    fp: Print, subjects: Iterable[Subject], *, volume_factor: float = 10.0
) -> dict[Outcome | None, list[Subject]]:
    """Subjects by their verdict: every one is in exactly one of known, changed and None."""
    out: dict[Outcome | None, list[Subject]] = {"known": [], "changed": [], None: []}
    for subject in subjects:
        out[evaluate(fp, subject, volume_factor=volume_factor).outcome].append(subject)
    return out


def still_active(last_activity: datetime | None, now: datetime, rules: Rules) -> bool:
    """Whether matching activity was seen within the last ``active_days``."""
    return last_activity is not None and now - last_activity <= timedelta(days=rules.active_days)


def reminders(
    now: datetime,
    notified_at: datetime,
    notices: int,
    blocked: bool,
    last_activity: datetime | None,
    rules: Rules,
) -> list[Reminder]:
    """The suggestions a notified case that is still active earns: "notify
    again" once it has been ``renotify_days`` since the only notice, and "ask for network-side
    action" once ``network_days`` have passed, when no block is recorded. Never alarms."""
    if not still_active(last_activity, now, rules):
        return []
    age = now - notified_at
    out: list[Reminder] = []
    if notices == 1 and age >= timedelta(days=rules.renotify_days):
        out.append("notify_again")
    if not blocked and age >= timedelta(days=rules.network_days):
        out.append("network_action")
    return out


def stopped(
    now: datetime, notified_at: datetime, last_activity: datetime | None, rules: Rules
) -> bool:
    """Whether a notified case saw no matching activity for ``quiet_days`` since the notice (or
    since its last activity after it): ARGUS proposes closing it as "stopped after notice"."""
    since = notified_at if last_activity is None else max(notified_at, last_activity)
    return now - since >= timedelta(days=rules.quiet_days)


@dataclass(frozen=True)
class Gone:
    """A device of the case, when it was last seen and the case's destinations it reached."""

    device: Key
    last_seen: datetime
    destinations: frozenset[Key]


def similarity(a: Collection[Key], b: Collection[Key]) -> float:
    """The share two sets have in common (their Jaccard index); 0 for two empty sets."""
    union = set(a) | set(b)
    return len(set(a) & set(b)) / len(union) if union else 0.0


def moved(
    first_seen: datetime,
    destinations: frozenset[Key],
    old: Iterable[Gone],
    rules: Rules,
) -> Gone | None:
    """The device a new address probably is: the one old device that went quiet
    before the new address's first alert, at least ``move_gap`` and no more than ``move_window``
    before it (a device that started an hour after another stopped is more likely a second
    device), with the same set of destinations (``move_similarity``). Two equally good old
    devices, or none, give None: ARGUS never guesses between devices."""
    if not destinations:
        return None
    fits = [
        g for g in old
        if g.destinations
        and rules.move_gap <= first_seen - g.last_seen <= rules.move_window
        and similarity(g.destinations, destinations) >= rules.move_similarity
    ]  # fmt: skip
    return fits[0] if len(fits) == 1 else None


def managed(types: Iterable[str | None], rules: Rules) -> bool:
    """Whether the devices are organisation-managed: every one lies in an asset-map network whose
    ``site.type`` is one of ``managed_types`` (an unknown type, or no map entry, is not)."""
    seen = list(types)
    return bool(seen) and all(t is not None and t.lower() in rules.managed_types for t in seen)


def still_active_line(
    alerts: int, days: int, notified_at: datetime, blocked_at: datetime | None,
    stamp: Callable[[datetime], str],
) -> str:  # fmt: skip
    """The case's status line: "still active, N alerts in D days since
    notice", or, once a block is recorded, "blocked at the network; the device is still infected;
    owner notified on <date>"."""
    told = stamp(notified_at)
    if blocked_at is not None:
        return "blocked at the network; the device is still infected; owner notified on " + told
    many = "alert" if alerts == 1 else "alerts"
    span = "day" if days == 1 else "days"
    return f"still active: {alerts} {many} in {days} {span} since the owner was notified ({told})"


def trend(per_day: Mapping[str, int]) -> str:
    """The alerts a day as a word: more, fewer or about the same in the second half of the days
    as in the first (the weekly report's trend)."""
    days = [per_day[d] for d in sorted(per_day)]
    if len(days) < 2:
        return "too few days to say"
    half = len(days) // 2
    early, late = sum(days[:half]) / half, sum(days[-half:]) / half
    if early == late:
        return "steady"
    if early == 0:
        return "rising"
    ratio = late / early
    return "rising" if ratio > 1.25 else "falling" if ratio < 0.8 else "steady"
