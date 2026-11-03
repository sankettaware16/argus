"""The checks the wave and "Check more" may ask (Q-F3, plan §7.3 point 2): what each template
can close, which of the rule's own log sources it needs, and how its request is built from a
dossier.

Checks are found by what they answer and by the sources the rule itself reads (the alert's
``kibana.alert.rule.indices``), never by a rule's name (D-058, D-060). A check names the *role*
of the log it needs (``proxy``, ``web``, ``dns``); a rule reads sources (the site's families),
each with a role. A gap names what it
needs as a key: ``signal:<name>`` (a signal that could not be told) or ``capability:<name>`` (a
question a note step asks); ``closers`` lists the templates that answer it, best first.

Every check is an existing, registered template, built with the same builders the packs and
the first runs use, so the request is always one the gateway's validator accepts. Nothing here
sends anything.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from argus import site
from argus.context import batch1, intel, proxy, web
from argus.context.packs import TaskSpec
from argus.gateway.templates import REGISTRY, CostClass

INTERNAL = proxy.INTERNAL


def log_sources() -> tuple[str, ...]:
    """The site's log families the investigation can name (the watched ones)."""
    return site.active().watched_sources


def roles_of(sources: Iterable[str]) -> frozenset[str]:
    """The roles of some of the site's log families (source keys); an unknown key has none."""
    families = (site.active().family(name) for name in sources)
    return frozenset(f.role.value for f in families if f is not None)


def reads_needed(spec: CheckSpec, sources: Iterable[str]) -> bool:
    """Whether a rule that reads ``sources`` reads the kind of log ``spec`` needs (a check that
    needs none is always possible)."""
    return not spec.sources or bool(set(spec.sources) & roles_of(sources))


def sources_of(indices: Sequence[str], known: Sequence[str] | None = None) -> frozenset[str]:
    """The log sources a rule reads, from its own indices (``kibana.alert.rule.indices``): see
    ``site.rule_families``, which the evidence templates use to pick the family they read, so the
    two agree."""
    wanted = log_sources() if known is None else known
    return frozenset(f.name for f in site.rule_families(indices, known=wanted))


@dataclass(frozen=True)
class CheckSpec:
    template: str
    sources: tuple[str, ...]  # the rule must read one of them; () for no log source needed
    closes: frozenset[str]
    weight: int  # the cheaper, better-known closer first
    words: str  # what it asks, for a reason a person reads (``site.say`` tokens)

    @property
    def said(self) -> str:
        return site.say(self.words)


def _keys(*names: str) -> frozenset[str]:
    return frozenset(names)


CHECKS: dict[str, CheckSpec] = {
    c.template: c
    for c in (
        CheckSpec(
            "logs.source_events",
            ("proxy", "web", "dns"),
            _keys("signal:source_events.rows", "capability:source_events"),
            5,
            "the log events behind the alert",
        ),
        CheckSpec(
            "ti.lookup",
            (),
            _keys("signal:ti.listed", "signal:ti.listed_remote", "capability:reputation"),
            10,
            "the indicators on the threat-intel lists",
        ),
        CheckSpec(
            "proxy.host",
            ("proxy",),
            _keys(
                "signal:proxy.regularity",
                "signal:proxy.destinations",
                "signal:proxy.bytes",
                "signal:proxy.busy_slots",
                "capability:timeline",
                "capability:log_pivot",
            ),
            10,
            "the host's proxy traffic",
        ),
        CheckSpec(
            "proxy.destination",
            ("proxy",),
            _keys("signal:proxy.hosts_to_destination", "capability:prevalence"),
            10,
            "which {own:hosts} reached the destination",
        ),
        CheckSpec(
            "web.followups",
            ("web",),
            _keys("signal:web.successes_after", "capability:log_pivot"),
            10,
            "the client's successful web answers after the first alert",
        ),
        CheckSpec(
            "proxy.pair",
            ("proxy",),
            _keys(
                "signal:pair.beats",
                "signal:pair.period_s",
                "signal:pair.jitter_s",
                "signal:pair.last_beat",
                "signal:pair.still_active",
                "capability:timeline",
                "capability:still_active",
            ),
            20,
            "how regularly the host reached the destination",
        ),
        CheckSpec(
            "proxy.contact",
            ("proxy",),
            _keys("signal:contact.hosts", "signal:contact.last", "capability:scope"),
            20,
            "which {own:hosts} reached the destination that day",
        ),
        CheckSpec(
            "dns.host_domains",
            ("dns",),
            _keys(
                "signal:dns.lookups",
                "signal:dns.names",
                "signal:dns.tunnel_suspected",
                "capability:name_lookup",
            ),
            30,
            "which names the client looked up in DNS",
        ),
        CheckSpec(
            "web.path_outcomes",
            ("web",),
            _keys(
                "signal:web.paths_success",
                "signal:web.paths_catch_all",
                "signal:web.paths_possible",
                "capability:attack_success",
            ),
            30,
            "whether the attacked paths got a successful answer",
        ),
    )
}
# A conflict between a threat and a calming signal, and a verified true positive's reach, are
# closed by checks that add independent evidence: who else is involved, and how it behaves.
INDEPENDENT = ("proxy.destination", "proxy.contact", "web.path_outcomes", "dns.host_domains",
               "proxy.pair")  # fmt: skip
SCOPE = ("proxy.contact", "proxy.pair")


def closers(key: str, sources: frozenset[str]) -> tuple[str, ...]:
    """The templates that answer ``key`` (``signal:<name>`` or ``capability:<name>``) for a rule
    that reads ``sources``, best first."""
    found = [
        c for c in CHECKS.values()
        if key in c.closes and reads_needed(c, sources)
    ]  # fmt: skip
    return tuple(c.template for c in sorted(found, key=lambda c: (c.weight, c.template)))


def available(templates: Sequence[str], sources: frozenset[str]) -> tuple[str, ...]:
    """Those of ``templates`` a rule that reads ``sources`` can have asked, in the order given."""
    return tuple(t for t in templates if t in CHECKS and reads_needed(CHECKS[t], sources))


def cost_of(template: str) -> CostClass:
    return REGISTRY[template].cost


def is_heavy(template: str) -> bool:
    return cost_of(template) is CostClass.HEAVY


# ----------------------------------------------------------------------------- switches


@dataclass(frozen=True)
class Switches:
    """The settings that decide which templates may be asked at all: the batch-1 list
    (``enrichment.templates``, each after its own first production run), the packs' own
    (``enrichment.proxy_aggregations``, ``enrichment.log_queries``, ``reference.ti_sync``)."""

    templates: frozenset[str] = frozenset()
    proxy_aggregations: bool = False
    log_queries: bool = False
    ti_sync: bool = False

    def on(self, template: str) -> bool:
        if template in batch1.TEMPLATES:
            return template in self.templates
        return {
            "proxy.host": self.proxy_aggregations,
            "proxy.destination": self.proxy_aggregations,
            "web.followups": self.log_queries,
            "ti.lookup": self.ti_sync,
        }.get(template, False)


def switches_of(settings: Any) -> Switches:
    return Switches(
        templates=frozenset(settings.enrichment.templates),
        proxy_aggregations=settings.enrichment.proxy_aggregations,
        log_queries=settings.enrichment.log_queries,
        ti_sync=settings.reference.ti_sync,
    )


# ----------------------------------------------------------------------------- builders


@dataclass(frozen=True)
class Material:
    """What a builder reads of a dossier (its stored facts and pack context) and of the rule
    (its type and the newest threshold or ES|QL alert); pure data, so the same dossier always
    builds the same requests."""

    facts: Mapping[str, Any]
    pack: Mapping[str, Any]  # the dossier's context["pack"]
    now: datetime
    rule_type: str | None = None
    normalized: Mapping[str, Any] | None = None

    @property
    def fields(self) -> Mapping[str, Any]:
        return self.pack.get("fields") or {}

    @property
    def ips(self) -> Mapping[str, Any]:
        return self.pack.get("ips") or {}

    @property
    def indices(self) -> list[str]:
        return [str(i) for i in self.pack.get("indices") or []]

    def top(self, field: str) -> list[str]:
        return [str(v) for v, _ in (self.fields.get(field) or {}).get("top", [])]

    def hosts(self) -> list[str]:
        return [v for v in self.top("source.ip") if self.ips.get(v, {}).get("class") in INTERNAL]

    def outside(self) -> list[str]:
        return [v for v in self.top("destination.ip")
                if self.ips.get(v, {}).get("class") == "public"]  # fmt: skip


def _first(found: Sequence[TaskSpec], template: str) -> TaskSpec | batch1.Refusal:
    task = next((t for t in found if type(t.template).name == template), None)
    return task or batch1.Refusal("no_subject", "no window or subject for it")


def build(template: str, m: Material) -> TaskSpec | batch1.Refusal:
    """The request of ``template`` for a dossier, with the pack's own builders (an earlier
    request of the investigation is planned as it was, D-070), or why it cannot be built."""
    now = m.now.astimezone(UTC)
    earlier = m.pack.get("earlier_logs") or {}
    if template in ("proxy.host", "proxy.destination"):
        return _first(proxy.tasks(m.facts, m.fields, m.ips, now, earlier, m.indices), template)
    if template == "web.followups":
        return _first(web.tasks(m.facts, m.fields, now, earlier, m.indices), template)
    if template == "ti.lookup":
        found = intel.tasks(m.pack.get("ti") or {})
        return found[0] if found else batch1.Refusal("no_subject", "nothing left to look up")
    if template == "proxy.pair":
        return batch1.pair_task(m.facts, m.fields, m.ips, now, m.indices)
    if template == "proxy.contact":
        outside = m.outside()
        return (
            batch1.contact_task(outside[0], now, indices=m.indices)
            if outside
            else batch1.Refusal("no_subject")
        )
    if template == "dns.host_domains":
        hosts = m.hosts()
        around = m.facts.get("last_event_at") or m.facts.get("first_event_at")
        if not hosts or not around:
            return batch1.Refusal("no_subject")
        return batch1.dns_task(hosts[0], datetime.fromisoformat(str(around)), now, m.indices)
    if template == "web.path_outcomes":
        clients, sites, tried = m.top("source.ip"), m.top("url.domain"), m.top("url.path")
        first = m.facts.get("first_event_at")
        if not clients or not sites or not tried or not first:
            return batch1.Refusal("no_subject")
        return batch1.paths_task(
            clients[0], sites[0], tried, datetime.fromisoformat(str(first)), now,
            indices=m.indices,
        ).task  # fmt: skip
    if template == "logs.source_events":
        if m.rule_type not in ("threshold", "esql") or m.normalized is None:
            return batch1.Refusal("no_subject", "not a threshold or ES|QL alert")
        return batch1.source_task(m.normalized, m.indices)
    raise KeyError(f"{template} is not a check of the wave")
