"""The engine's incidents in the database (P4-F E2 and E4, shadow): after each rescore, the
objects in a lane are linked into incidents (``argus.risk.link``), the incidents advance
(``argus.risk.lifecycle``) and are written to the engine's own tables. Postgres only: no SIEM
request, no model, and nothing of today's queue or cases is written (``case_id`` stays empty).

The **retro-hunt**: an outside thing the engine sees flagged for the first time (an outside
detection, a threat-list hit named by a group, a campaign) is joined against the observations
of ``retro_days`` (a GIN index on their outside things): every alert group that touched it is
read again at the next pass, so its evidence (the flag) is scored, and every campus object that
touched it can link through it."""

from __future__ import annotations

import json
import logging
import time
import uuid
from collections import defaultdict
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from argus.risk import identity as identity_mod
from argus.risk import lifecycle, link
from argus.risk.identity import Identity, SignIn, address_of, signin_accounts
from argus.risk.incident_config import IncidentConfig
from argus.risk.lifecycle import Incident, Material
from argus.risk.link import Binding, Flag, Link
from argus.risk.observe import ObjectRef, Observation
from argus.risk.score import Stats, Verdict
from argus.signins import model as signin_model

log = logging.getLogger("argus.risk")
FLAG_SOURCES = frozenset({"outside", "ti", "operator", "campaign", "person"})
RETRO_SIGNATURE = "0" * 32  # a signature no group's inputs give: it is read again
MAX_SIGNIN_HOURS = 48  # hours of one device's sign-ins read at a pass
Campaigns = Callable[[datetime], Awaitable[Sequence[Any]]]


@dataclass
class LinkSetup:
    """What the linker's pass needs beyond the scores."""

    config: IncidentConfig
    identity: Identity | None = None
    signins: signin_model.Rules | None = None  # None: no account links
    campaigns: Campaigns | None = None  # argus.campaigns' analysis (its campaigns), or None
    threshold: int = 3  # VirusTotal engines that make a detection
    detection_days: int = 30  # how old a cached detection may be
    cache: dict[str, Any] = field(default_factory=dict)  # the campaigns of the last hour
    # the pass's addresses that are one device (identity.same_devices): the ranker reads it
    same: dict[ObjectRef, str] = field(default_factory=dict)


@dataclass
class Report:
    live: int = 0
    opened: int = 0
    requeued: int = 0
    merged: int = 0
    largest: int = 0
    links: int = 0
    flagged: int = 0
    retro_threats: int = 0
    retro_groups: int = 0
    seconds: float = 0.0

    def line(self) -> str:
        return (
            f"incidents (shadow): {self.live} live, {self.opened} new, {self.requeued} changed"
            f" materially, {self.merged} merged; largest {self.largest} devices;"
            f" {self.links} links written; {self.flagged} outside things flagged"
            f" ({self.retro_threats} new: {self.retro_groups} alert groups to read again);"
            f" {self.seconds:.2f} s"
        )


# --------------------------------------------------------------------------- flags


def group_flags(obs: Sequence[Observation], config: IncidentConfig) -> dict[str, Flag]:
    """The outside things a group's strong evidence names: those of its rule observations, when
    it holds at most ``flag_threats`` addresses and domains (else which one is flagged is not
    known). From when the evidence was known."""
    threats: dict[uuid.UUID, set[str]] = defaultdict(set)
    strong: dict[uuid.UUID, tuple[datetime, str]] = {}
    for o in obs:
        if o.source_kind == "rule":
            threats[o.group].update(t for t in o.threats if t.split(":", 1)[0] in ("ip", "domain"))
        elif o.strong:
            kind = o.source_key.split(":", 1)[-1]
            source = kind if kind in FLAG_SOURCES else "outside"
            at = o.seen_at or o.at
            if o.group not in strong or at < strong[o.group][0]:
                strong[o.group] = (at, source)
    out: dict[str, Flag] = {}
    for gid, (at, source) in strong.items():
        named = threats.get(gid, set())
        if 0 < len(named) <= config.flag_threats:
            for t in named:
                held = out.get(t)
                if held is None or (held.at is not None and at < held.at):
                    out[t] = Flag(source, at)
    return out


def merge_flags(*sets: Mapping[str, Flag]) -> dict[str, Flag]:
    """The earliest flag of each thing (one known from the start wins)."""
    out: dict[str, Flag] = {}
    for flags in sets:
        for t, f in flags.items():
            held = out.get(t)
            if held is None or (held.at is not None and (f.at is None or f.at < held.at)):
                out[t] = f
    return out


def bindings_of(campaigns: Sequence[Any], obs: Sequence[Observation]) -> list[Binding]:
    """``argus.campaigns``' campaigns as bindings: their devices (an address or a host name) as
    the window's objects, their parents and flagged addresses as outside things."""
    by_address: dict[str, set[ObjectRef]] = defaultdict(set)
    for o in obs:
        address = address_of(o.object)
        if address is not None:
            by_address[address].add(o.object)
        elif o.object.kind == "device":
            by_address[o.object.key].add(o.object)
    out = []
    for c in campaigns:
        refs: set[ObjectRef] = set()
        for kind, value in c.hosts:
            refs |= by_address.get(value if kind == "ip" else f"host:{value}", set())
        threats = tuple([f"domain:{p}" for p in c.parents] + [f"ip:{s}" for s in c.servers])
        key = ",".join(threats[:3]) or "campaign"
        out.append(Binding(f"campaign:{key}", frozenset(refs), threats, c.reason()[:200]))
    return out


_DETECTIONS = text(
    "SELECT kind, indicator, min(fetched_at) AS at,"
    " bool_or(answer ->> 'ranked' = 'true') AS ranked,"
    " bool_or(CAST(COALESCE(NULLIF(answer ->> 'malicious', ''), '0') AS integer) >= :threshold)"
    " AS detected FROM outside_lookups WHERE source = 'virustotal' AND status = 'found'"
    " AND kind IN ('ip', 'domain') AND indicator = ANY(CAST(:values AS text[]))"
    " AND fetched_at >= :since GROUP BY 1, 2"
)


async def detections(
    conn: AsyncConnection, threats: Sequence[str], now: datetime, setup: LinkSetup
) -> tuple[dict[str, Flag], set[str]]:
    """The window's outside things VirusTotal detects (not ranked popular), and those a
    popularity list ranks."""
    values = sorted({t.split(":", 1)[1] for t in threats if t.split(":", 1)[0] in ("ip", "domain")})
    if not values:
        return {}, set()
    rows = await conn.execute(
        _DETECTIONS,
        {"values": values, "threshold": setup.threshold,
         "since": now - timedelta(days=setup.detection_days)},
    )  # fmt: skip
    flags: dict[str, Flag] = {}
    popular: set[str] = set()
    for r in rows:
        key = f"{r.kind}:{r.indicator}"
        if r.ranked:
            popular.add(key)
        elif r.detected:
            flags[key] = Flag("outside", r.at)
    return flags, popular


# --------------------------------------------------------------------------- reading


_INCIDENTS = text(
    "SELECT r.id, r.state, r.created_at, r.first_seen, r.last_seen, r.version, r.lanes,"
    " r.material, r.changed, r.material_at, r.stop_proposed_at, r.campaign, r.parent_id,"
    " r.follows_id, r.merged_into, r.priority, r.band, c.owner_user_id AS owner,"
    " c.state AS case_state FROM risk_incidents r LEFT JOIN cases c ON c.id = r.case_id"
    " WHERE r.state IN ('active', 'quiet') OR (r.state = 'sealed' AND r.last_seen >= :since)"
)


def decision_of(case_state: str | None) -> str | None:
    """A person's decision on the incident's case, as the merge blocker reads it: ``confirmed``
    (open, assigned or contained), ``closed`` (dismissed, or closed after work); None when there
    is no case or nobody decided it (suspected)."""
    if case_state in ("open", "assigned", "contained"):
        return "confirmed"
    return "closed" if case_state == "closed" else None


async def load_incidents(
    conn: AsyncConnection, now: datetime, config: IncidentConfig, refs: Mapping[int, ObjectRef]
) -> list[Incident]:
    """The live incidents, and the sealed ones recent enough to be followed, each with the
    person's hold on its case (owner, decision) that blocks a merge."""
    since = now - timedelta(days=config.lifecycle.seal_days)
    rows = (await conn.execute(_INCIDENTS, {"since": since})).all()
    if not rows:
        return []
    ids = [int(r.id) for r in rows]
    objects: dict[int, dict[ObjectRef, str]] = defaultdict(dict)
    for r in await conn.execute(
        text(
            "SELECT m.incident_id, m.object_id, m.role, b.kind, b.key FROM risk_incident_objects m"
            " JOIN risk_objects b ON b.id = m.object_id"
            " WHERE m.incident_id = ANY(CAST(:ids AS bigint[]))"
        ),
        {"ids": ids},
    ):
        ref = refs.get(int(r.object_id)) or ObjectRef(r.kind, r.key)
        objects[int(r.incident_id)][ref] = r.role
    groups: dict[int, dict[uuid.UUID, datetime]] = defaultdict(dict)
    for r in await conn.execute(
        text(
            "SELECT incident_id, investigation_id, joined_at FROM risk_incident_groups"
            " WHERE incident_id = ANY(CAST(:ids AS bigint[]))"
        ),
        {"ids": ids},
    ):
        groups[int(r.incident_id)][r.investigation_id] = r.joined_at
    out = []
    for r in rows:
        inc = Incident(
            int(r.id), r.created_at, r.first_seen, r.last_seen, objects[int(r.id)],
            groups[int(r.id)], set(r.lanes), r.state, int(r.version),
            Material.of_json(r.material), list(r.changed), r.material_at, r.stop_proposed_at,
            bool(r.campaign), r.parent_id, None, r.follows_id, r.merged_into,
            owner=r.owner, decision=decision_of(r.case_state),
            priority=int(r.priority), band=r.band,
        )  # fmt: skip
        out.append(inc)
    return out


# --------------------------------------------------------------------------- writing


def _link_rows(
    inc_id: int, links: Sequence[Link], ids: Mapping[ObjectRef, int], now: datetime,
    known: set[tuple[int, int | None, str, str]],
) -> list[dict[str, Any]]:  # fmt: skip
    out = []
    for lk in links:
        a = ids.get(lk.a)
        b = ids.get(lk.b) if lk.b is not None else None
        if a is None or (lk.b is not None and b is None):
            continue
        key = (a, b, lk.via, lk.value)
        if key in known:
            continue
        known.add(key)
        out.append({
            "i": inc_id, "a": a, "b": b, "via": lk.via, "value": lk.value[:600] or "-",
            "p": lk.priority, "d": min(int(lk.delta.total_seconds()), 2**31 - 1),
            "reason": lk.reason[:200] or "-", "kept": lk.kept, "now": now,
        })  # fmt: skip
    return out


def _recommended(inc: Incident) -> str:
    rows = [{"a": lifecycle.label(lk.a), "b": lifecycle.label(lk.b) if lk.b else None,
             "via": lk.via, "reason": lk.reason} for lk in inc.recommended[:20]]  # fmt: skip
    return json.dumps(rows, separators=(",", ":"))


async def write(
    conn: AsyncConnection, outcome: lifecycle.Outcome, ids: Mapping[ObjectRef, int],
    now: datetime,
) -> int:  # fmt: skip
    """Write what the lifecycle changed: new incidents (roots first), their members and links,
    merges, and every live incident's state. Returns the links written."""
    held = outcome.incidents
    for inc in sorted(held, key=lambda i: i.overflow):  # roots before their overflows
        if inc.root is not None and inc.root.id is not None:
            inc.parent = inc.root.id  # a merge may have given an overflow a new root
        if inc.id is not None or inc.state == "merged":
            continue
        row = await conn.execute(
            text(
                "INSERT INTO risk_incidents (state, created_at, first_seen, last_seen, updated_at,"
                " version, lanes, material, material_hash, material_at, changed, campaign,"
                " parent_id, follows_id, devices, groups, priority, band, view, recommended)"
                " VALUES ('active', :now, :first, :last, :now, 1, CAST(:lanes AS text[]),"
                " CAST(:material AS jsonb), :hash, :now, CAST(:changed AS text[]), :campaign,"
                " :parent, :follows, 0, 0, :priority, :band, '{}'::jsonb, '[]'::jsonb)"
                " RETURNING id"
            ),
            {"now": now, "first": inc.first_seen, "last": max(inc.last_seen, inc.first_seen),
             "lanes": sorted(inc.lanes), "material": json.dumps(inc.material.as_json()),
             "hash": inc.material.digest(), "changed": inc.changed, "campaign": inc.campaign,
             "parent": inc.parent, "follows": inc.follows, "priority": inc.priority,
             "band": inc.band},
        )  # fmt: skip
        inc.id = int(row.scalar_one())
    for kept, gone in outcome.merged:
        gone.merged_into = kept.id
        if gone.id is None:
            continue
        await conn.execute(
            text("UPDATE risk_links SET incident_id = :k WHERE incident_id = :g"),
            {"k": kept.id, "g": gone.id},
        )
        for table in ("risk_incident_objects", "risk_incident_groups"):
            await conn.execute(
                text(f"DELETE FROM {table} WHERE incident_id = :g"),  # noqa: S608 - a constant
                {"g": gone.id},
            )
    stored_objects: dict[int, set[int]] = defaultdict(set)
    stored_groups: dict[int, set[uuid.UUID]] = defaultdict(set)
    live_ids = [i.id for i in held if i.id is not None and i.state != "merged"]
    for r in await conn.execute(
        text("SELECT incident_id, object_id FROM risk_incident_objects"
             " WHERE incident_id = ANY(CAST(:ids AS bigint[]))"), {"ids": live_ids},
    ):  # fmt: skip
        stored_objects[int(r.incident_id)].add(int(r.object_id))
    for r in await conn.execute(
        text("SELECT incident_id, investigation_id FROM risk_incident_groups"
             " WHERE incident_id = ANY(CAST(:ids AS bigint[]))"), {"ids": live_ids},
    ):  # fmt: skip
        stored_groups[int(r.incident_id)].add(r.investigation_id)
    known: set[tuple[int, int | None, str, str]] = set()
    for r in await conn.execute(
        text("SELECT incident_id, a_object, b_object, via, value FROM risk_links"
             " WHERE incident_id = ANY(CAST(:ids AS bigint[]))"), {"ids": live_ids},
    ):  # fmt: skip
        known.add((int(r.a_object), r.b_object, r.via, r.value))
    object_rows: list[dict[str, Any]] = []
    group_rows: list[dict[str, Any]] = []
    link_rows: list[dict[str, Any]] = []
    state_rows: list[dict[str, Any]] = []
    for inc in held:
        if inc.id is None:
            continue
        if inc.state == "merged":
            state_rows.append(_state(inc, now))
            continue
        for ref, role in inc.objects.items():
            oid = ids.get(ref)
            if oid is not None and oid not in stored_objects[inc.id]:
                object_rows.append({"i": inc.id, "o": oid, "role": role, "now": now})
        for gid in inc.groups:
            if gid not in stored_groups[inc.id]:
                group_rows.append({"i": inc.id, "g": gid, "now": now})
        link_rows += _link_rows(inc.id, [*inc.links, *inc.recommended], ids, now, known)
        state_rows.append(_state(inc, now))
    if object_rows:
        await conn.execute(
            text(
                "INSERT INTO risk_incident_objects (incident_id, object_id, role, joined_at)"
                " VALUES (:i, :o, :role, :now) ON CONFLICT DO NOTHING"
            ),
            object_rows,
        )
    if group_rows:
        await conn.execute(
            text(
                "INSERT INTO risk_incident_groups (incident_id, investigation_id, joined_at)"
                " SELECT :i, :g, :now WHERE EXISTS (SELECT 1 FROM investigations WHERE id = :g)"
                " ON CONFLICT DO NOTHING"
            ),
            group_rows,
        )
    if link_rows:
        await conn.execute(
            text(
                "INSERT INTO risk_links (incident_id, a_object, b_object, via, value, priority,"
                " delta_seconds, reason, kept, created_at) VALUES (:i, :a, :b, :via, :value, :p,"
                " :d, :reason, :kept, :now)"
            ),
            link_rows,
        )
    if state_rows:
        await conn.execute(
            text(
                "UPDATE risk_incidents SET state = :state, first_seen = :first,"
                " last_seen = :last, updated_at = :now, version = :version,"
                " lanes = CAST(:lanes AS text[]), material = CAST(:material AS jsonb),"
                " material_hash = :hash, material_at = :material_at,"
                " changed = CAST(:changed AS text[]), stop_proposed_at = :stop,"
                " campaign = :campaign, merged_into = :merged, parent_id = :parent,"
                " devices = :devices,"
                " groups = :groups, priority = :priority, band = :band,"
                # the lifecycle's part of the view; the presenter's keys (what a person was
                # shown, seen, told) stay
                " view = view || CAST(:view AS jsonb), recommended = CAST(:recommended AS jsonb)"
                " WHERE id = :id"
            ),
            state_rows,
        )
    return len(link_rows)


def _state(inc: Incident, now: datetime) -> dict[str, Any]:
    return {
        "id": inc.id, "state": inc.state, "first": min(inc.first_seen, inc.last_seen),
        "last": inc.last_seen, "now": now, "version": inc.version, "lanes": sorted(inc.lanes),
        "material": json.dumps(inc.material.as_json()), "hash": inc.material.digest(),
        "material_at": inc.material_at, "changed": inc.changed, "stop": inc.stop_proposed_at,
        "campaign": inc.campaign, "merged": inc.merged_into if inc.state == "merged" else None,
        "parent": inc.parent,
        "devices": inc.devices, "groups": len(inc.groups), "priority": inc.priority,
        "band": inc.band, "view": json.dumps(lifecycle.view_part(inc, now), default=str),
        "recommended": _recommended(inc),
    }  # fmt: skip


# --------------------------------------------------------------------------- the pass


def known_hubs(identity: Identity | None, obs: Sequence[Observation]) -> dict[ObjectRef, str]:
    """The window's address objects the asset map (a hub role) or ``campaigns.resolvers`` make
    hubs: with identity on they get no observation, so these are only the ones observed before
    (they never link either way)."""
    if identity is None:
        return {}
    out: dict[ObjectRef, str] = {}
    for ref in {o.object for o in obs}:
        why = identity.hub(ref)
        if why is not None:
            out[ref] = why
    return out


async def _sign_ins(
    conn: AsyncConnection, setup: LinkSetup, now: datetime, obs: Sequence[Observation],
    wanted_refs: set[ObjectRef],
) -> list[SignIn]:  # fmt: skip
    """The likely accounts behind the devices of ``wanted_refs`` in the hours of their
    observations of the last day (account links reach 24 h)."""
    if setup.signins is None or setup.identity is None or not wanted_refs:
        return []
    since = now - setup.config.links.account.span
    hours: dict[ObjectRef, set[datetime]] = defaultdict(set)
    for o in obs:
        if (o.object in wanted_refs and since <= o.at <= now and address_of(o.object)
                and len(hours[o.object]) < MAX_SIGNIN_HOURS):  # fmt: skip
            hours[o.object].add(o.at.replace(minute=0, second=0, microsecond=0))
    wanted = sorted((ref, at) for ref, times in hours.items() for at in times)
    found = await signin_accounts(conn, wanted, setup.identity, setup.signins, now,
                                  setup.config.links.account.max_devices_a_day)  # fmt: skip
    if found:
        await conn.execute(
            text(
                "INSERT INTO risk_aliases (device, kind, value, valid_from, valid_to, source,"
                " confidence) VALUES (:d, 'account', :v, :f, :t, 'signin', 'likely')"
                " ON CONFLICT DO NOTHING"
            ),
            [{"d": s.device.key, "v": s.user, "f": s.start, "t": s.end} for s in found],
        )
    return found


_SPANS = text(
    "SELECT b.key, min(o.at) AS first, max(o.at) AS last FROM risk_observations o"
    " JOIN risk_objects b ON b.id = o.object_id"
    " WHERE b.kind = 'device' AND b.key = ANY(CAST(:keys AS text[])) AND o.at <= :now"
    " GROUP BY b.key"
)


async def _same(
    conn: AsyncConnection, setup: LinkSetup, now: datetime, wanted_refs: set[ObjectRef],
) -> dict[ObjectRef, str]:  # fmt: skip
    """The addresses of ``wanted_refs`` that are one device that moved (D-334): one likely
    account behind each over its activity, never two at the same time. What was read is kept
    in ``risk_aliases`` (the account of a device over a span), where the presenter and the
    titles read it."""
    if setup.signins is None or setup.identity is None or not wanted_refs:
        return {}
    keys = sorted({r.key for r in wanted_refs if address_of(r) is not None})
    if not keys:
        return {}
    # the whole of each address's kept activity, not the scoring window's 14 days: an incident
    # that runs for weeks has addresses older than that
    rows = await conn.execute(_SPANS, {"keys": keys, "now": now})
    seen = [(ObjectRef("device", r.key), at) for r in rows for at in (r.first, r.last)]
    spans = identity_mod.spans_of(seen, setup.identity)
    used = await identity_mod.device_users(conn, spans, setup.signins, now)
    if used:
        await conn.execute(
            text(
                "INSERT INTO risk_aliases (device, kind, value, valid_from, valid_to, source,"
                " confidence) VALUES (:d, 'account', :v, :f, :t, 'signin', 'likely')"
                " ON CONFLICT (device, kind, value, valid_from) DO UPDATE"
                " SET valid_to = greatest(risk_aliases.valid_to, EXCLUDED.valid_to)"
            ),
            [{"d": u.device.key, "v": u.user, "f": u.start, "t": u.end} for u in used],
        )
    return identity_mod.same_devices(used)


async def _hosts(
    conn: AsyncConnection, now: datetime, config: IncidentConfig
) -> list[tuple[ObjectRef, ObjectRef, datetime, datetime]]:
    rows = await conn.execute(
        text(
            "SELECT device, value, valid_from, valid_to FROM risk_aliases WHERE kind = 'host'"
            " AND valid_to >= :since"
        ),
        {"since": now - config.links.host.span},
    )
    return [(ObjectRef("device", r.device), ObjectRef("device", f"host:{r.value}"),
             r.valid_from, r.valid_to) for r in rows]  # fmt: skip


async def write_aliases(conn: AsyncConnection, observed: Sequence[Any]) -> None:
    """The host names a batch of groups showed on an address (identity), a day each."""
    rows = []
    for group, _, seen in observed:
        for ip_ref, host_ref in getattr(seen, "aliases", ()):
            start = group.first_at
            rows.append({"d": ip_ref.key, "v": host_ref.key.split(":", 1)[1], "f": start,
                         "t": max(group.last_at, start)})  # fmt: skip
    if rows:
        await conn.execute(
            text(
                "INSERT INTO risk_aliases (device, kind, value, valid_from, valid_to, source,"
                " confidence) VALUES (:d, 'host', :v, :f, :t, 'alert', 'certain')"
                " ON CONFLICT (device, kind, value, valid_from) DO UPDATE"
                " SET valid_to = greatest(risk_aliases.valid_to, EXCLUDED.valid_to)"
            ),
            rows,
        )


async def _campaigns(setup: LinkSetup, now: datetime) -> Sequence[Any]:
    if setup.campaigns is None:
        return ()
    every = timedelta(hours=setup.config.campaign.every_hours)
    held = setup.cache.get("campaigns")
    if held is not None and timedelta(0) <= now - held[0] < every:
        return held[1]  # type: ignore[no-any-return]
    try:
        found = await setup.campaigns(now)
    except Exception as exc:  # the campaign lane waits; linking goes on
        log.warning("risk: the campaign analysis failed (%s)", type(exc).__name__)
        return held[1] if held is not None else ()
    setup.cache["campaigns"] = (now, found)
    return found


async def retro_hunt(
    conn: AsyncConnection, new: Sequence[str], now: datetime, config: IncidentConfig
) -> int:
    """Every alert group of ``retro_days`` that touched one of ``new`` is read again at the next
    pass (its stored signature no longer matches). Returns how many."""
    if not new:
        return 0
    result = await conn.execute(
        text(
            "UPDATE risk_groups g SET signature = :sig FROM (SELECT DISTINCT investigation_id"
            " FROM risk_observations WHERE threats && CAST(:threats AS text[]) AND at >= :since)"
            " h WHERE g.investigation_id = h.investigation_id AND g.signature <> :sig"
        ),
        {"sig": RETRO_SIGNATURE, "threats": list(new),
         "since": now - timedelta(days=config.retro_days)},
    )  # fmt: skip
    await conn.execute(
        text("UPDATE risk_threats SET hunted_at = :now WHERE threat = ANY(CAST(:t AS text[]))"),
        {"now": now, "t": list(new)},
    )
    return int(result.rowcount or 0)


async def prune(conn: AsyncConnection, now: datetime, config: IncidentConfig) -> int:
    """Drop what is past ``keep_days``: sealed and merged incidents (with their members and
    links), flags last noticed and aliases last valid that long ago."""
    keep = now - timedelta(days=config.keep_days)
    gone = 0
    for sql in (
        "DELETE FROM risk_incidents WHERE state IN ('sealed', 'merged') AND last_seen < :keep"
        " AND NOT EXISTS (SELECT 1 FROM risk_incidents c WHERE c.follows_id = risk_incidents.id"
        " AND c.state IN ('active', 'quiet'))",
        "DELETE FROM risk_threats WHERE noticed_at < :keep",
        "DELETE FROM risk_aliases WHERE valid_to < :keep",
    ):
        gone += int((await conn.execute(text(sql), {"keep": keep})).rowcount or 0)
    return gone


async def step(
    engine: AsyncEngine, setup: LinkSetup, now: datetime, obs: Sequence[Observation],
    ids: Mapping[ObjectRef, int], verdicts: Mapping[ObjectRef, Verdict], stats: Stats,
    band_of: Callable[[lifecycle.Incident], str] | None = None,
) -> Report:  # fmt: skip
    """One pass of the linker and the lifecycle over the rescored window (see the module).
    ``band_of``: the priority step's (``argus.risk.present.ranker``); None: the provisional."""
    started = time.perf_counter()
    report = Report()
    config = setup.config
    candidates = {ref: tuple(v.lanes) for ref, v in verdicts.items() if v.lanes}
    threats = sorted({t for o in obs for t in o.threats})
    campaigns = await _campaigns(setup, now)
    async with engine.begin() as conn:
        found, popular = await detections(conn, threats, now, setup)
        bindings = bindings_of(campaigns, obs)
        campaign_flags = {t: Flag("campaign", now) for b in bindings for t in b.threats}
        stored = {
            r.threat: Flag(r.flag_source, r.flagged_at)
            for r in await conn.execute(text("SELECT threat, flag_source, flagged_at"
                                             " FROM risk_threats"))
        }  # fmt: skip
        flags = merge_flags(stored, found, group_flags(obs, config), campaign_flags)
        flags = {t: f for t, f in flags.items() if f.at is None or f.at <= now}
        new = sorted(set(flags) - set(stored))
        if new:
            await conn.execute(
                text(
                    "INSERT INTO risk_threats (threat, flag_source, flagged_at, noticed_at)"
                    " VALUES (:t, :s, :at, :now) ON CONFLICT DO NOTHING"
                ),
                [{"t": t[:600], "s": flags[t].source, "at": flags[t].at, "now": now}
                 for t in new if len(t) >= 3],
            )  # fmt: skip
        report.flagged, report.retro_threats = len(flags), len(new)
        report.retro_groups = await retro_hunt(conn, new, now, config)
        refs = {oid: ref for ref, oid in ids.items()}
        held = await load_incidents(conn, now, config, refs)
        lifecycle.seal(held, now, config)  # before the candidates: a sealed one has no members
        live_refs = {r for inc in held if inc.live for r in inc.objects}
        sign_ins = await _sign_ins(conn, setup, now, obs, set(candidates) | live_refs)
        known = known_hubs(setup.identity, obs)
        same = await _same(conn, setup, now, set(candidates) | live_refs)
        setup.same.clear()
        setup.same.update(same)  # the priority step counts them as one device too
        world = link.World(
            flags, frozenset(popular), known, sign_ins, await _hosts(conn, now, config), bindings,
            setup.identity.one_device if setup.identity is not None else None, same,
        )  # fmt: skip
        starts = lifecycle.candidates_of(candidates, held)
        comps = link.link_all(obs, now, starts, config, stats, world)
        score_7d = {ref: v.window("7d").score for ref, v in verdicts.items()}
        facts = lifecycle.facts_of(obs, now, lambda t: link.flagged_at(flags.get(t), now),
                                   score_7d, same)  # fmt: skip
        outcome = lifecycle.advance(held, comps, facts, now, config, band_of)
        report.links = await write(conn, outcome, ids, now)
        await prune(conn, now, config)
        hubs = link.hubs_of(obs, now, config, known)
        if hubs:
            await conn.execute(
                text(
                    "UPDATE risk_objects SET hub = true, hub_reason = :why WHERE id = :o"
                    " AND hub IS DISTINCT FROM true"
                ),
                [{"o": ids[r], "why": why[:200]} for r, why in sorted(hubs.items()) if r in ids],
            )
        if setup.identity is not None:
            changed = [
                {"o": oid, "c": c} for ref, oid in ids.items()
                if (c := setup.identity.criticality(ref)) != 1.0
            ]  # fmt: skip
            if changed:
                await conn.execute(
                    text("UPDATE risk_objects SET criticality = :c WHERE id = :o"
                         " AND criticality <> :c"), changed,
                )  # fmt: skip
    live = [i for i in outcome.incidents if i.live and not i.overflow]
    report.live = len(live)
    report.opened = sum(1 for i in outcome.opened if i.state != "merged")
    report.requeued = len(outcome.requeued)
    report.merged = len(outcome.merged)
    report.largest = max((i.devices for i in live), default=0)
    report.seconds = time.perf_counter() - started
    return report
