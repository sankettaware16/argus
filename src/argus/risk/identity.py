"""Identity (P4-F E4): which internal device an address is, at a time, and which account was behind
it. Pure, except :func:`signin_accounts`, which reads the stored SSO sign-ins.

- **Device keys.** An address of a /32 (or /128) entry of the asset map is the device itself; so
  is any address whose network the asset map marks ``static``. A **dynamic** address (the asset
  map says so, or its role is a Wi-Fi or VPN pool, or nobody says and ``unknown_addressing`` is
  dynamic) is keyed **per day** (``ip:<address>@<day>``): a reused DHCP address never
  accumulates for the next person. A host name is always the device (``host:<name>``). Only a
  /32 or a stated ``static`` address is **one device** (:meth:`Identity.one_device`): an address
  keyed whole because nobody states its addressing may still be reused (the linker never lets it
  carry a host alias across people).
- **Hubs.** An address whose asset-map role is a NAT, a proxy, a resolver, a mail relay or a
  gateway, or that lies in ``campaigns.resolvers``, is a hub: it never links and gets no
  observation (the digest counts it). Measured fan-in is the linker's (it never links).
- **Accounts.** A ``likely`` SSO attribution in the same hour links an account to a device; a
  generic or service account never links, and neither does an address of a shared role (a lab,
  a Wi-Fi pool, a NAT) or an account seen on more devices a day than the limit.
- **Criticality** from the asset map's optional field (absent: normal, 1).
"""

from __future__ import annotations

import hashlib
import itertools
import json
import re
from collections import defaultdict
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Literal, NamedTuple

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.assets.assetmap import IPNetwork, parse_address
from argus.assets.classify import IpClassifier
from argus.risk.incident_config import Identity as IdentityConfig
from argus.risk.observe import ObjectRef
from argus.risk.roles import GENERIC_ACCOUNTS, OWN_CLASSES, account
from argus.signins import attribute
from argus.signins import model as signin_model
from argus.signins import store as signin_store

Addressing = Literal["static", "dynamic"]
DAY_MARK = "@"
# Service and machine accounts: shared by programs, never one person (compared in lower case).
_SERVICE = re.compile(
    r"^(svc|srv|service|services|sys|app|apps|bot|daemon|batch|backup|scan|scanner|monitor"
    r"|nagios|zabbix|jenkins|git|gitlab|ldap|smtp|imap|mail|cron|sync|api|automation)([-_.0-9]|$)"
    r"|[-_.](svc|service|bot|daemon|sync|api)$|\$$"
)


@dataclass(frozen=True)
class Device:
    """What the asset map says of one address."""

    ref: ObjectRef
    addressing: Addressing
    role: str | None
    hub: str | None  # why it is a hub (None: it is not)
    shared: bool  # many people use it: no account ever links through it
    criticality: float


class _Facts(NamedTuple):
    addressing: Addressing
    role: str | None
    hub: str | None
    shared: bool
    criticality: float
    one_device: bool  # a /32 (or /128) entry, or stated static: never another person's


def address_of(ref: ObjectRef) -> str | None:
    """The address of a device keyed by address (with or without its day), else None."""
    if ref.kind != "device" or not ref.key.startswith("ip:"):
        return None
    return ref.key[3:].split(DAY_MARK, 1)[0]


def device_of(ref: ObjectRef, same: Mapping[ObjectRef, str] | None = None) -> str:
    """The device behind a key: a per-day key and its address's other days are one device (for
    the device caps and counts), and so are the addresses ``same`` reads as one device
    (:func:`same_devices`)."""
    if same:
        held = same.get(ref)
        if held is not None:
            return held
    if ref.kind == "device" and ref.key.startswith("ip:"):
        return ref.key.split(DAY_MARK, 1)[0]
    return f"{ref.kind}:{ref.key}"


SAME = "same:"  # the key of several addresses read as one device: ``same:<account>``


class Used(NamedTuple):
    """One account was the likely user of a device over a span of its activity."""

    device: ObjectRef
    user: str
    start: datetime
    end: datetime


def same_devices(used: Iterable[Used]) -> dict[ObjectRef, str]:
    """The addresses that are most likely **one device that moved** (D-334): each has one likely
    account, the same one, and no two of them were active at the same time. A dynamic address
    changes with the network a laptop joins, so the count of addresses is not a count of devices;
    one account on two addresses at once is two devices, and then none of that account's are
    joined. Returns device -> ``same:<account>`` for the joined ones (two or more)."""
    users: dict[ObjectRef, set[str]] = defaultdict(set)
    spans: dict[ObjectRef, tuple[datetime, datetime]] = {}
    for u in used:
        users[u.device].add(u.user)
        low, high = spans.get(u.device, (u.start, u.end))
        spans[u.device] = (min(low, u.start), max(high, u.end))
    by_user: dict[str, list[ObjectRef]] = defaultdict(list)
    for device, names in users.items():
        if len(names) == 1:  # two accounts on an address: nobody's own device
            by_user[next(iter(names))].append(device)
    out: dict[ObjectRef, str] = {}
    for user, devices in sorted(by_user.items()):
        by_address: dict[str, tuple[datetime, datetime]] = {}
        for d in devices:  # an address's days are one device already
            low, high = by_address.get(device_of(d), spans[d])
            by_address[device_of(d)] = (min(low, spans[d][0]), max(high, spans[d][1]))
        if len(by_address) < 2:
            continue
        ordered = sorted(by_address.values())
        if any(b[0] < a[1] for a, b in itertools.pairwise(ordered)):
            continue  # active on two addresses at once: more than one device
        out.update(dict.fromkeys(devices, SAME + user))
    return out


def service_account(name: str) -> bool:
    """A generic or service account (``root``, ``svc-backup``, ``host$``): never one person."""
    lowered = name.strip().lower()
    local = lowered.split("@", 1)[0].split("\\")[-1]
    return account(lowered) is None or local in GENERIC_ACCOUNTS or bool(_SERVICE.search(local))


class Identity:
    """The asset map's view of addresses, with the engine's identity settings."""

    def __init__(
        self, classifier: IpClassifier, config: IdentityConfig, hub_roles: Collection[str] = (),
        resolvers: Sequence[IPNetwork] = (),
    ) -> None:  # fmt: skip
        self.classifier = classifier
        self.config = config
        self.hub_roles = frozenset(r.lower() for r in hub_roles)
        self.resolvers = tuple(resolvers)
        self._cache: dict[str, _Facts] = {}

    def fingerprint(self) -> str:
        """A digest of what decides device keys and hubs (the settings, the hub roles, the
        resolvers, the internal networks and the asset map): a change reads every group again."""
        assets = self.classifier.assets
        raw = json.dumps([
            self.config.model_dump(mode="json"), sorted(self.hub_roles),
            [str(n) for n in self.resolvers], [str(n) for n in self.classifier.own_prefixes],
            assets.sha256 if assets is not None else None,
        ], sort_keys=True)  # fmt: skip
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _facts(self, address: str) -> _Facts:
        held = self._cache.get(address)
        if held is not None:
            return held
        cfg = self.config
        found = self.classifier.classify(address)
        fields: Mapping[str, str] = {}
        single = False
        if found.asset is not None:
            entry = found.asset.entries[0]  # the map's first entry for the network
            fields = entry.fields
            single = found.asset.network.prefixlen == found.asset.network.max_prefixlen
        role = next(
            (fields[f].strip().lower() for f in cfg.role_fields if fields.get(f, "").strip()),
            None,
        )  # fmt: skip
        stated = fields.get(cfg.addressing_field, "").strip().lower()
        addressing: Addressing
        if single or stated == "static":
            addressing = "static"
        elif stated == "dynamic" or (role is not None and role in cfg.dynamic_roles):
            addressing = "dynamic"
        else:
            addressing = cfg.unknown_addressing
        hub: str | None = None
        if role is not None and role in self.hub_roles:
            hub = f"asset role {role}"
        else:
            ip = parse_address(address)
            if ip is not None and any(ip.version == n.version and ip in n for n in self.resolvers):
                hub = "a resolver"
        level = fields.get(cfg.criticality_field, "").strip().lower()
        criticality = cfg.criticality.get(level, 1.0) if level else 1.0
        shared = role is not None and role in cfg.shared_roles
        held = _Facts(addressing, role, hub, shared, criticality, single or stated == "static")
        if len(self._cache) < 200_000:
            self._cache[address] = held
        return held

    def device(self, address: str, day: date) -> Device:
        """The device an address is on ``day`` (the site's day of its alert group)."""
        f = self._facts(address)
        key = f"ip:{address}" if f.addressing == "static" else f"ip:{address}{DAY_MARK}{day}"
        return Device(ObjectRef("device", key), f.addressing, f.role, f.hub, f.shared,
                      f.criticality)  # fmt: skip

    def devices(self) -> Callable[[str, date], tuple[ObjectRef, str | None]]:
        """:meth:`device` as the observation step reads it: (its key, why it is a hub)."""

        def of(address: str, day: date) -> tuple[ObjectRef, str | None]:
            found = self.device(address, day)
            return found.ref, found.hub

        return of

    def ours(self, address: str) -> bool:
        return self.classifier.classify(address).ip_class in OWN_CLASSES

    def criticality(self, ref: ObjectRef) -> float:
        address = address_of(ref)
        return self._facts(address).criticality if address is not None else 1.0

    def shared(self, ref: ObjectRef) -> bool:
        address = address_of(ref)
        return self._facts(address).shared if address is not None else False

    def hub(self, ref: ObjectRef) -> str | None:
        """Why an address object is a hub by the asset map or a resolver (None: it is not)."""
        address = address_of(ref)
        return self._facts(address).hub if address is not None else None

    def one_device(self, ref: ObjectRef) -> bool:
        """The asset map says the address is one device (a /32 entry, or stated static)."""
        address = address_of(ref)
        if address is None or DAY_MARK in ref.key:
            return False
        return self._facts(address).one_device


# --------------------------------------------------------------------------- sign-ins


@dataclass(frozen=True)
class SignIn:
    """A likely account behind a device in one hour."""

    device: ObjectRef
    user: str
    start: datetime
    end: datetime


def likely_user(
    address: str, records: Mapping[date, signin_model.DayRecord], at: datetime,
    rules: signin_model.Rules, now: datetime,
) -> str | None:  # fmt: skip
    """The one account with a successful sign-in from ``address`` in the hour of ``at`` (the
    sign-ins' ``likely`` state, padded by nothing), or None."""
    hour = at.replace(minute=0, second=0, microsecond=0)
    found = attribute.attribute(
        address, records, hour, hour + timedelta(minutes=59), _no_pad(rules), now=now
    )
    if found.state != "likely" or len(found.accounts) != 1:
        return None
    return found.accounts[0].user.strip().lower()


def _no_pad(rules: signin_model.Rules) -> signin_model.Rules:
    from dataclasses import replace

    return replace(rules, pad=timedelta(0))


def sign_ins(
    wanted: Iterable[tuple[ObjectRef, datetime]], identity: Identity,
    records: Mapping[tuple[str, date], signin_model.DayRecord], rules: signin_model.Rules,
    now: datetime, devices_a_day: Mapping[tuple[str, date], int], max_devices: int,
) -> list[SignIn]:  # fmt: skip
    """The likely accounts behind each (device, time) of ``wanted``: one per device and hour,
    none for a shared role, a generic or service account, or an account seen on more than
    ``max_devices`` addresses that day (``devices_a_day``: (user, UTC day) -> addresses)."""
    by_address: dict[str, dict[date, signin_model.DayRecord]] = defaultdict(dict)
    for (held, day), record in records.items():
        by_address[held][day] = record
    out: dict[tuple[ObjectRef, str, datetime], SignIn] = {}
    for ref, at in wanted:
        address = address_of(ref)
        if address is None or identity.shared(ref):
            continue
        user = likely_user(address, by_address.get(address, {}), at, rules, now)
        if user is None or service_account(user):
            continue
        if devices_a_day.get((user, signin_model.utc_day(at)), 1) > max_devices:
            continue
        hour = at.replace(minute=0, second=0, microsecond=0)
        out.setdefault((ref, user, hour), SignIn(ref, user, hour, hour + timedelta(hours=1)))
    return [out[k] for k in sorted(out, key=lambda k: (k[0], k[1], k[2]))]


def spans_of(
    obs: Iterable[tuple[ObjectRef, datetime]], identity: Identity
) -> dict[ObjectRef, tuple[datetime, datetime]]:
    """When each address that may be a device that moves was active: not a hub, not a shared
    role (a lab machine has many users, and one user many lab machines), not an address the asset
    map says is one device (a /32 or a stated static address is that device, and no other)."""
    out: dict[ObjectRef, tuple[datetime, datetime]] = {}
    for ref, at in obs:
        if address_of(ref) is None:
            continue
        if identity.shared(ref) or identity.hub(ref) or identity.one_device(ref):
            continue
        low, high = out.get(ref, (at, at))
        out[ref] = (min(low, at), max(high, at))
    return out


def used_by(
    spans: Mapping[ObjectRef, tuple[datetime, datetime]],
    records: Mapping[tuple[str, date], signin_model.DayRecord], rules: signin_model.Rules,
    now: datetime,
) -> list[Used]:  # fmt: skip
    """The one account behind each device over the span of its activity (the sign-ins' ``likely``
    state, or the only account seen so far while a day is still being read; with the sign-ins'
    own padding: the reading the incident report gives), never a generic or service account."""
    by_address: dict[str, dict[date, signin_model.DayRecord]] = defaultdict(dict)
    for (held, day), record in records.items():
        by_address[held][day] = record
    out: list[Used] = []
    for ref, (first, last) in sorted(spans.items()):
        address = address_of(ref)
        if address is None:
            continue
        found = attribute.attribute(address, by_address.get(address, {}), first, last, rules,
                                    now=now)  # fmt: skip
        # likely: one account in the window (others may have signed in outside it that day);
        # unknown: a day's sign-ins are not all read yet, and one account is all there is so far
        if len(found.accounts) != 1 or found.state not in ("likely", "unknown"):
            continue
        if found.state == "unknown" and (found.account_count != 1 or found.at_least):
            continue
        user = found.accounts[0].user.strip().lower()
        if user and not service_account(user):
            out.append(Used(ref, user, first, last))
    return out


async def device_users(
    conn: AsyncConnection, spans: Mapping[ObjectRef, tuple[datetime, datetime]],
    rules: signin_model.Rules, now: datetime,
) -> list[Used]:  # fmt: skip
    """:func:`used_by` on the stored sign-ins of the addresses and days of ``spans``."""
    addresses = sorted({a for ref in spans if (a := address_of(ref)) is not None})
    if not addresses:
        return []
    pad = rules.pad
    first = min(s[0] for s in spans.values()) - pad
    last = max(s[1] for s in spans.values()) + pad
    records = await signin_store.records(
        conn, addresses, signin_model.utc_day(first), signin_model.utc_day(last)
    )
    return used_by(spans, records, rules, now)


_USED = text(
    "SELECT device, value, valid_from, valid_to FROM risk_aliases WHERE kind = 'account'"
    " AND device = ANY(CAST(:d AS text[]))"
)


async def read_used(conn: AsyncConnection, devices: Sequence[str]) -> list[Used]:
    """The account the linking pass read behind each of ``devices`` (object keys), with the
    span of the device's activity (``risk_aliases``)."""
    if not devices:
        return []
    rows = await conn.execute(_USED, {"d": list(devices)})
    return [Used(ObjectRef("device", r.device), str(r.value), r.valid_from, r.valid_to)
            for r in rows]  # fmt: skip


async def read_same(conn: AsyncConnection, devices: Sequence[str]) -> dict[ObjectRef, str]:
    """The addresses of ``devices`` that are one device (:func:`same_devices`)."""
    return same_devices(await read_used(conn, devices))


def latest_address(used: Iterable[Used], same: Mapping[ObjectRef, str]) -> dict[str, str]:
    """Each joined device -> the address it was last seen under: the one a person looks for
    today, so the one that names it."""
    last: dict[str, tuple[datetime, str]] = {}
    for u in used:
        key, address = same.get(u.device), address_of(u.device)
        if key is None or address is None:
            continue
        if key not in last or (u.end, address) > last[key]:
            last[key] = (u.end, address)
    return {key: address for key, (_, address) in last.items()}


_DEVICES_A_DAY = text(
    "SELECT lower(user_name) AS u, day, count(DISTINCT address) AS n FROM signin_sightings"
    " WHERE lower(user_name) = ANY(CAST(:users AS text[])) AND day = ANY(CAST(:days AS date[]))"
    " AND successes > 0 GROUP BY 1, 2"
)


async def signin_accounts(
    conn: AsyncConnection, wanted: Sequence[tuple[ObjectRef, datetime]], identity: Identity,
    rules: signin_model.Rules, now: datetime, max_devices: int,
) -> list[SignIn]:  # fmt: skip
    """:func:`sign_ins` on the stored sign-ins of the addresses and days of ``wanted``."""
    addresses = sorted({a for ref, _ in wanted if (a := address_of(ref)) is not None})
    if not addresses:
        return []
    days = sorted({signin_model.utc_day(at) for _, at in wanted})
    records = await signin_store.records(conn, addresses, days[0], days[-1])
    users = sorted({s.user.strip().lower() for r in records.values() for s in r.sightings})
    counts: dict[tuple[str, date], int] = {}
    if users:
        rows = await conn.execute(_DEVICES_A_DAY, {"users": users, "days": days})
        counts = {(r.u, r.day): int(r.n) for r in rows}
    return sign_ins(wanted, identity, records, rules, now, counts, max_devices)
