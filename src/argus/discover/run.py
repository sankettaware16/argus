"""The reads of ``argus discover`` (P4-D1): a fixed, short list of metadata requests through the
gateways, collected into ``Inputs`` for ``propose``.

Every request goes through the Elastic Gateway (the ledger, the budget, the health states) or the
Kibana lane; nothing is written anywhere. The reads, in this order:

1. Elasticsearch ``GET /`` (version) and ``GET /_license`` (level and status);
2. the names of indices, aliases and data streams (``discover.indices``: the visible ones, then
   the hidden Security alerts aliases of every space);
3. Kibana ``GET api/status`` (version), ``api/spaces/space`` and ``api/features`` when the
   Kibana lane is available (otherwise a warning says what was not read);
4. the mapping of ``MAX_MAPPINGS`` candidate families at most, the likeliest first: how a few
   well-known fields are mapped in the newest index of each (``discover.field_mapping``). Of the
   data streams of Elastic's Threat Intel integration (``logs-ti_*``) one speaks for the group;
5. when the key holds ``read_ilm`` (asked first: a 403 would stop ARGUS's access), the ILM
   policies' delete ages.

A read that fails is a warning, not the end, except the Elasticsearch listing: without it there
is nothing to propose.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any, Protocol

from argus import site
from argus.config.settings import SiemSettings
from argus.discover import classify
from argus.discover.classify import Typed
from argus.discover.propose import Inputs
from argus.gateway.builtin import ClusterInfo, ClusterLicense
from argus.gateway.discovery import (
    DiscoverFieldMapping,
    DiscoverIlmPolicies,
    DiscoverIndices,
    DiscoverPrivileges,
    IndicesParams,
    MappingParams,
)
from argus.gateway.errors import GatewayError, RefusedError
from argus.gateway.gateway import Gateway, Result
from argus.gateway.health import HealthMemory, effective
from argus.gateway.service import health_config, probe
from argus.gateway.state import DiscoveryStore
from argus.gateway.templates import NoParams, Params, Purpose, Template
from argus.site import DISCOVERY_FIELDS

COMPONENT = "discover"
MAX_MAPPINGS = 12
DEADLINE = timedelta(seconds=45)  # each read, budget waits included
# A health reading is fresh for the collector's probe interval (1 minute,
# ``collector.runner.PROBE_EVERY``) and half a minute of lateness.
FRESH_FOR = timedelta(seconds=90)


async def siem_state(
    es: Gateway, store: DiscoveryStore, siem: SiemSettings, *, clock: Callable[[], datetime]
) -> HealthMemory:
    """The SIEM's health as discovery may trust it (what it is refused on unless NORMAL): the
    stored memory when a probe made it lately, else one probe, taken here and kept only for this
    command (``DiscoveryStore.adopt``), never saved over the real memory (F2). The probe reads
    the index blocks of every family the site names (a site that names none has none to look
    at: node stats only). A probe the gateway refused to send leaves the stored memory, which
    ``effective`` then does not trust."""
    now = clock()
    memory = await store.health()
    if memory.probed_at is None or not timedelta(0) <= now - memory.probed_at < FRESH_FOR:
        memory = await probe(
            es, store, siem, now, component=COMPONENT, indices=bool(site.active().families)
        )
        store.adopt(memory)
    return effective(memory, now, health_config(siem))


class KibanaReads(Protocol):
    """The part of ``KibanaGateway`` discovery uses."""

    async def read(
        self, template: Any, params: Any, *, component: str, deadline: datetime
    ) -> Any: ...


def mapping_params(candidate: classify.Candidate) -> Callable[[], MappingParams]:
    """The parameters of a candidate's mapping read, built when the read is made."""
    return lambda: MappingParams(
        index=str(candidate.sample), fields=tuple(sorted(DISCOVERY_FIELDS))
    )


async def collect(
    es: Gateway,
    kibana: KibanaReads | None,
    *,
    clock: Any,
    max_mappings: int = MAX_MAPPINGS,
    kibana_note: str = "",
) -> Inputs:
    """Make the reads. ``clock`` gives the time (a function returning an aware datetime)."""
    warnings: list[str] = []
    requests = 0

    async def ask(template: Template, params: Params, purpose: Purpose = Purpose.DISCOVER) -> Any:
        nonlocal requests
        requests += 1
        result: Result = await es.run(
            template, params, purpose=purpose, component=COMPONENT, deadline=clock() + DEADLINE
        )
        return result.body

    async def optional(
        label: str, template: Template, params: Params | Callable[[], Params], **kw: Any
    ) -> Any:
        """A read that may fail. The parameters may be a function: building them is inside the
        guard, so a name the template cannot take (it is legal in Elasticsearch, F4) is a warning,
        not the end of the run."""
        try:
            return await ask(template, params() if callable(params) else params, **kw)
        except RefusedError as exc:  # the gateway's own refusal: its message says why
            warnings.append(f"{label} was not read: {exc.reason} ({exc})")
        except GatewayError as exc:
            warnings.append(f"{label} was not read: {exc.reason}")
        except ValueError as exc:  # pydantic's ValidationError is one
            warnings.append(
                f"{label} was not read: not a name ARGUS can ask about ({exc.__class__.__name__})"
            )
        return None

    info = await optional(
        "Elasticsearch's version", ClusterInfo(), NoParams(), purpose=Purpose.SELFTEST
    )
    version = None
    if isinstance(info, dict):
        raw = info.get("version")
        number = raw.get("number") if isinstance(raw, dict) else None
        version = number if isinstance(number, str) else None
    licence = None
    body = await optional("the licence", ClusterLicense(), NoParams())
    if body is not None:
        licence = ClusterLicense.summary(body)
        if licence is None:
            warnings.append("the licence answer was not understood")
    data = await optional("the list of indices", DiscoverIndices(), IndicesParams(scope="data"))
    alerts = await optional(
        "the Security alerts indices", DiscoverIndices(), IndicesParams(scope="alerts")
    )
    for label, listing in (("indices", data), ("alerts indices", alerts)):
        if isinstance(listing, dict) and listing.get("truncated"):
            warnings.append(f"the list of {label} was cut: a very large cluster, check the result")

    kibana_requests = [0]
    kibana_version, spaces, features = await _kibana(
        kibana, kibana_note, clock, warnings, kibana_requests
    )

    mappings: dict[str, dict[str, Typed]] = {}
    if isinstance(data, dict):
        sampled = classify.collapse_ti([c for c in classify.candidates(data) if c.sample])
        wanted = sorted(sampled, key=lambda c: (-classify.name_score(c), c.pattern))[:max_mappings]
        skipped = len(sampled) - len(wanted)
        if skipped > 0:
            warnings.append(
                f"{skipped} candidate families were not examined (--max-mappings {max_mappings});"
                " they are judged by their names alone"
            )
        for candidate in wanted:
            body = await optional(
                f"the mapping of {candidate.pattern}",
                DiscoverFieldMapping(),
                mapping_params(candidate),
            )
            if body is None:
                continue
            limits = DiscoverFieldMapping.limits(body)
            typed = {
                name: Typed(kind, keyword, limits.get(name))
                for name, (kind, keyword) in DiscoverFieldMapping.types(body).items()
            }
            if typed:
                mappings[candidate.pattern] = typed
            else:  # an answer that maps none of the fields is no reading of the mapping (F15)
                warnings.append(
                    f"the mapping of {candidate.pattern} named none of the fields asked about:"
                    " it is judged by its name alone"
                )

    ilm = None
    held = await optional("the cluster privileges", DiscoverPrivileges(), NoParams())
    if held is not None:
        if DiscoverPrivileges.holds(held, "read_ilm"):
            ilm = await optional("the ILM policies", DiscoverIlmPolicies(), NoParams())
        else:
            warnings.append(
                "the key lacks read_ilm: retention is judged from the dated indices alone"
            )
    return Inputs(
        elastic_version=version,
        kibana_version=kibana_version,
        licence=licence,
        data=data if isinstance(data, dict) else None,
        alerts=alerts if isinstance(alerts, dict) else None,
        spaces=spaces,
        features=features,
        mappings=mappings,
        ilm=ilm if isinstance(ilm, dict) else None,
        warnings=tuple(warnings),
        requests=requests + kibana_requests[0],
        now=clock(),
    )


async def _kibana(
    kibana: KibanaReads | None, note: str, clock: Any, warnings: list[str], count: list[int]
) -> tuple[str | None, list[dict[str, str]] | None, list[dict[str, str]] | None]:
    """(Kibana's version, its spaces, its features); None for each that could not be read."""
    from argus.gateway.kibana.templates import KibanaFeatures, KibanaSpaces, KibanaStatus, NoParams

    if kibana is None:
        warnings.append(
            "Kibana was not asked"
            + (f" ({note})" if note else "")
            + ": its version, spaces and feature ids are not proposed"
        )
        return None, None, None

    async def read(template: Any) -> Any:
        count[0] += 1
        try:
            result = await kibana.read(
                template, NoParams(), component=COMPONENT, deadline=clock() + DEADLINE
            )
        except GatewayError as exc:
            warnings.append(f"Kibana's {template.name} was not read: {exc.reason}")
            return None
        return result.body

    status = await read(KibanaStatus())
    version = status[0] if isinstance(status, tuple) and status else None
    return version, await read(KibanaSpaces()), await read(KibanaFeatures())


def nothing_proposed(now: datetime) -> str:
    """Why discovery proposes nothing: the index listing was not read (the warnings say why), and
    in the quiet hours that is expected."""
    text = "the list of indices could not be read: nothing is proposed"
    if site.in_quiet_hours(now):
        hours = site.quiet_hours()
        text += (
            f" (the SIEM's quiet hours, {hours.start}-{hours.end} UTC: ARGUS asks it nothing"
            f" optional now; run this again after {hours.end} UTC)"
        )
    return text
