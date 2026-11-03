"""A person's "Check more" (Q-F3): one approved template on one entity.

A request names a template of the catalogue and an address or a domain; nothing else comes
from the person. ``validate`` refuses at once what could never be asked (an unapproved template,
a value that is no address or domain, an address of the wrong kind for the template); ``build``
makes the request from the dossier with the same builders the wave uses (the windows, the daily
index, the bounds), and refuses what the rule's own indices or the switches do not allow. The
prevalence gate, the lane and the health rules apply when it is sent, as for a wave.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from collections.abc import Callable
from datetime import UTC, datetime

from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncConnection

from argus import site
from argus.context import batch1, proxy, web
from argus.context.packs import TaskSpec
from argus.investigation import catalogue, store
from argus.reference.templates import LOOKUP_SIZE, TiLookup, lookup_params
from argus.reference.ti import variants
from argus.site import Role

# The checks a person may ask for, and what each takes: a campus host, a destination outside
# the campus, any address, an address or a domain (a threat-list lookup). The rows behind an
# alert (logs.source_events) are asked about an alert, not an entity, so only a wave asks them.
TAKES = {
    "proxy.host": "internal",
    "proxy.destination": "public",
    "proxy.pair": "address",
    "proxy.contact": "public",
    "dns.host_domains": "internal",
    "web.followups": "address",
    "web.path_outcomes": "address",
    "ti.lookup": "indicator",
}
APPROVED = tuple(TAKES)
# The limits on checks are the table's (migration 0040: a trigger, under a lock, so that
# requests at once cannot pass one count together); the numbers are written there too, and a test
# keeps them equal. They are read here first only to say so in the person's words.
OPEN_PER_PERSON = 5  # checks one person may have queued or running at once
OPEN_IN_ALL = 100  # checks anyone may have queued or running at once
PER_PERSON_PER_DAY = 30  # checks one person may ask for in a UTC day
DOMAIN = re.compile(r"(?=.{4,253}$)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}")
# What the table stores (at most 253 characters, no control character), and less: printable
# ASCII alone. An address with a scope id (``fe80::1%eth0``) or a name with a bidirectional
# character is no entity ARGUS asks about.
STORABLE = re.compile(r"[\x21-\x7e]{1,253}")


def clean(entity: str) -> str | None:
    """The address (as Python writes it) or domain (lower case, no dot at the end) that
    ``entity`` is, or None. Only printable ASCII of at most 253 characters, and no ``%``
    (an IPv6 scope id, which Python accepts and the SIEM does not know)."""
    value = entity.strip()
    if not STORABLE.fullmatch(value) or "%" in value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    value = value.lower().rstrip(".")
    return value if DOMAIN.fullmatch(value) else None


def validate(template: str, entity: str) -> str | None:
    """Why this request cannot be asked at all (plain words), or None."""
    if template not in TAKES:
        return "that is not a check a person may ask for"
    value = clean(entity)
    if value is None:
        return "that is neither an address nor a domain"
    is_address = _is_address(value)
    if TAKES[template] != "indicator" and not is_address:
        return "this check takes an address"
    return None


def _is_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def kind_of(value: str, is_campus: Callable[[str], bool]) -> str:
    """internal, public or special (loopback, link-local, multicast, reserved ...) for an
    address; domain for a name."""
    if not _is_address(value):
        return "domain"
    address = ipaddress.ip_address(value)
    if (address.is_loopback or address.is_link_local or address.is_multicast
            or address.is_reserved or address.is_unspecified):  # fmt: skip
        return "special"
    if is_campus(value):
        return "internal"
    return "public" if address.is_global else "special"


def build(
    template: str,
    entity: str,
    material: catalogue.Material,
    switches: catalogue.Switches,
    is_campus: Callable[[str], bool],
) -> TaskSpec | batch1.Refusal:
    """The request of ``template`` about ``entity``, from the dossier's own window and
    subjects; a Refusal says why not (the rule does not read the log, the check is switched
    off, the value is of the wrong kind, there is no window)."""
    problem = validate(template, entity)
    if problem is not None:
        return batch1.Refusal("no_subject", problem)
    value = clean(entity)
    assert value is not None
    spec = catalogue.CHECKS[template]
    sources = catalogue.sources_of(material.indices)
    if not catalogue.reads_needed(spec, sources):
        return batch1.Refusal("no_subject", "the rule does not read the log this check needs")
    kind = kind_of(value, is_campus)
    takes = TAKES[template]
    if (takes == "internal" and kind != "internal") or (takes == "public" and kind != "public"):
        said = {"internal": "an internal", "public": "a public", "special": "a special"}
        return batch1.Refusal(
            "no_subject", f"this check takes {said[takes]} address, not {said[kind]} one"
        )
    if takes in ("address", "internal", "public") and kind == "special":
        return batch1.Refusal("no_subject", "that address is not one ARGUS asks about")
    if not switches.on(template):  # last: a value of the wrong kind is wrong whatever is on
        return batch1.Refusal("off")
    now = material.now.astimezone(UTC)
    facts = material.facts
    if template in ("proxy.host", "proxy.destination"):
        span = proxy.window(facts, now)
        if span is None:
            return batch1.Refusal("no_subject", "the proxy logs for this time are not ready")
        cls = proxy.ProxyHost if template == "proxy.host" else proxy.ProxyDestination
        params = proxy.WindowParams(
            ip=value,
            start=span[0],
            end=span[1],
            source=site.source_param(Role.PROXY, material.indices),
        )
        return TaskSpec(cls(), params)
    if template == "web.followups":
        span = web.follow_window(facts, now)
        if span is None:
            return batch1.Refusal("no_subject", "the web logs after the alert are not ready")
        follow = web.FollowParams(
            ip=value,
            start=span[0],
            end=span[1],
            source=site.source_param(Role.WEB, material.indices),
        )
        return TaskSpec(web.WebFollowups(), follow)
    if template == "proxy.pair":
        other = material.outside() if kind == "internal" else material.hosts()
        if not other:
            return batch1.Refusal("no_subject", "the investigation names no other end")
        host, dest = (value, other[0]) if kind == "internal" else (other[0], value)
        return batch1.pair_task(
            facts,
            {**material.fields, "source.ip": {"top": [[host, 1]]},
             "destination.ip": {"top": [[dest, 1]]}},
            {**material.ips, host: {"class": "campus"}, dest: {"class": "public"}},
            now,
            material.indices,
        )  # fmt: skip
    if template == "proxy.contact":
        return batch1.contact_task(value, now, indices=material.indices)
    if template == "dns.host_domains":
        around = facts.get("last_event_at") or facts.get("first_event_at")
        if not around:
            return batch1.Refusal("no_subject", "the investigation has no time")
        return batch1.dns_task(value, datetime.fromisoformat(str(around)), now, material.indices)
    if template == "web.path_outcomes":
        sites, tried = material.top("url.domain"), material.top("url.path")
        first = facts.get("first_event_at")
        if not sites or not tried or not first:
            return batch1.Refusal("no_subject", "the alerts name no site or path")
        return batch1.paths_task(
            value, sites[0], tried, datetime.fromisoformat(str(first)), now,
            indices=material.indices,
        ).task  # fmt: skip
    # ti.lookup: an indicator, spelled as the lists store it
    lookups = site.active().ti_lookups
    if not lookups:
        return batch1.Refusal("no_subject", "the site names no threat-intel source to look in")
    terms = variants("ip" if _is_address(value) else "domain", value)
    return TaskSpec(TiLookup(), lookup_params(lookups, tuple(sorted(terms)), LOOKUP_SIZE))


async def request(
    conn: AsyncConnection,
    investigation_id: uuid.UUID,
    version: int,
    template: str,
    entity: str,
    requested_by: str,
    now: datetime,
) -> tuple[str, int | str]:
    """A person's "Check more", queued for ARGUS's service: ("queued", the request's id),
    ("open", id) when the same request is queued or running already, or ("refused", why). The
    service plans it again when it runs (the rule's indices, the switches, the prevalence gate
    and the lane decide then); what could never be asked is refused here."""
    problem = validate(template, entity)
    if problem is not None:
        return "refused", problem
    value = clean(entity)
    assert value is not None
    who = requested_by[:120]
    open_ = await store.open_requests(conn, who)
    if open_[0] >= OPEN_PER_PERSON:
        return "refused", f"you have {open_[0]} checks waiting already: wait for them to finish"
    if open_[1] >= OPEN_IN_ALL:
        return "refused", "too many checks are waiting; try again later"
    asked = await store.checks_today(conn, who)
    if asked >= PER_PERSON_PER_DAY:
        return "refused", f"you have asked for {asked} checks today: that is the limit for a day"
    try:
        async with conn.begin_nested():  # a refusal of the table's must not end the caller's work
            queued = await store.enqueue(
                conn, investigation_id, version, "check", "person", now,
                template=template, entity=value, requested_by=who,
            )  # fmt: skip
    except DBAPIError as exc:
        # the table's trigger counts again under a lock: requests at once met the limit together
        said = store.limit_said(exc)
        if said is None:
            raise
        return "refused", said
    if queued is None:
        return "open", "the same request is queued or running already"
    return "queued", queued
