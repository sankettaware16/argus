"""The factual parts of the incident report: timeline, actors with their roles, affected assets,
evidence with the query behind each line, and the indicators.

Generic signals only: nothing here knows a rule's name. An actor's role comes from counts and order
in time (a *collector* made at least five times the requests of the next actor; a *scout* came
before it with few, a *prober* after it with few); each evidence line is one stored answer of a
check that ran, with that check's own query."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

from argus import site
from argus.incident import discover, evidence, targets
from argus.incident import model as m
from argus.incident.book import Book, cut
from argus.incident.scene import Scene, first_of, is_ip, ours, top
from argus.incident.words import count, dwell, ist_date, ist_moment, plural
from argus.outside import facts as outside_facts
from argus.signins import attribute as attributes
from argus.site import zone_label

MAX_ACTORS = 25
MAX_ASSETS = 500
MAX_EVIDENCE = 14
PER_TEMPLATE = 3
PHASES = 12
COLUMNS = 4
DOMINANT = 5.0  # a collector made this many times the requests of the next actor
SAME_MIN = 3  # addresses one account must be the first account of, to read them as one device
SMALL = 0.2  # a scout or a prober made at most this share of the collector's requests
ROLE_WORDS = {
    "actor": "the actor (a device or address the alerts name)",
    "c2": "command-and-control (the server or name the actor reached)",
    "indicator": "an indicator tied to the case",
}


def timeline(scene: Scene, book: Book) -> m.ReportTimeline:
    f = scene.f
    span = scene.last - scene.first if scene.first and scene.last else None
    ordered = sorted(scene.rules.items(), key=lambda kv: (kv[1][1], kv[0]))
    phases = []
    for name, (n, lo, hi) in ordered[:PHASES]:
        text = f"{name}: {plural(n, 'alert')} from {ist_moment(lo)} to {ist_moment(hi)}."
        sentence = book.say("alerts", text, "ARGUS's stored alerts", (n,))
        phases.append(
            m.ReportPhase(name=cut(name, 300), start=lo, end=hi, alerts=n, sentence=sentence)
        )
    if len(ordered) > PHASES:
        scene.limits.append(f"the timeline lists {PHASES} of the case's {len(ordered)} rules")
    by_size = sorted(scene.rules.items(), key=lambda kv: (-kv[1][0], kv[0]))
    shown = [name for name, _ in by_size[:COLUMNS]]
    columns = tuple(shown) + (("Other rules",) if len(scene.rules) > COLUMNS else ())
    by_day: dict[str, list[int]] = {}
    for d in f.days:
        row = by_day.setdefault(d.day, [0] * len(columns))
        row[shown.index(d.rule) if d.rule in shown else len(columns) - 1] += d.alerts
    days = tuple(
        m.ReportDayRow(day=day, counts=tuple(counts), total=sum(counts))
        for day, counts in sorted(by_day.items())
    )
    notes: list[m.ReportSentence] = []
    case = f.case
    if case.notified_at is not None:
        text = f"The owner was told on {ist_moment(case.notified_at)}."
        notes.append(book.say("notice", text, "the case record"))
    if case.blocked_at is not None:
        text = f"A block at the network was recorded on {ist_moment(case.blocked_at)}."
        notes.append(book.say("notice", text, "the case record"))
    if scene.first and scene.last:
        text = (
            f"All times are {zone_label()}. The first alert was at {ist_moment(scene.first)} and "
            f"the last at {ist_moment(scene.last)}."
        )
        notes.append(book.say("alerts", text, "ARGUS's stored alerts"))
    return m.ReportTimeline(
        first_seen=scene.first,
        last_seen=scene.last,
        dwell_seconds=None if span is None else int(span.total_seconds()),
        dwell_words=None if span is None else dwell(span),
        phases=tuple(phases),
        columns=columns,
        days=days,
        alerts=scene.alerts,
        notes=tuple(notes),
    )


def _requests(scene: Scene, ip: str) -> int | None:
    """The requests a web check counted for this address (the largest stored answer)."""
    best: int | None = None
    for row in scene.f.evidence:
        if row.template != "web.path_outcomes" or row.params.get("ip") != ip:
            continue
        said = evidence.say(row.template, row.params, row.snapshot, row.status)
        if said.count is not None and (best is None or said.count > best):
            best = said.count
    return best


def _docs_of(scene: Scene, ip: str) -> list[Any]:
    return [d for d in scene.f.docs if ip in d.fields.get("source.ip", ())]


def _network(scene: Scene, ip: str) -> tuple[str | None, str | None]:
    """The network's owner and the country of an address: from the alerts' own fields first, then
    from the outside answer ARGUS cached."""
    net = country = None
    for d in _docs_of(scene, ip):
        net = net or first_of(d.fields.get("source.as.organization.name", ()))
        country = country or first_of(d.fields.get("source.geo.country_name", ()))
    for d in scene.f.docs:
        if ip in d.fields.get("destination.ip", ()):
            net = net or first_of(d.fields.get("destination.as.organization.name", ()))
            country = country or first_of(d.fields.get("destination.geo.country_name", ()))
    answer = scene.vt_answer(ip)
    net = net or outside_facts.clean(answer.get("owner"), 80)
    country = country or outside_facts.clean(answer.get("country"), 40)
    return (cut(net, 200) if net else None, cut(country, 100) if country else None)


def reached_servers(scene: Scene, device: str) -> bool:
    """Whether an internal device actually reached one of the case's servers: an investigation that
    names the device also names a command-and-control indicator."""
    servers = set(scene.servers)
    return any(
        value in servers for x in scene.members_naming(device) for _, value in scene.entity_of[x.id]
    )


def roles(scene: Scene, stats: dict[str, dict[str, Any]]) -> dict[str, tuple[str, str]]:
    """A role and its words for each actor, from counts and order in time alone. Actors are
    compared in **one unit**: requests when every outside actor has a request count from a web
    check, else alerts; the words say which."""
    out: dict[str, tuple[str, str]] = {}
    outside = {
        v: st for v, st in stats.items() if st["kind"] == "ip" and not ours(v, scene.ctx.classifier)
    }
    for value, st in stats.items():
        if value in outside:
            continue
        if st["kind"] == "user":
            out[value] = ("account", "An account named in the alerts.")
        elif st["kind"] == "ip" and reached_servers(scene, value):
            out[value] = (
                site.own("device"),
                site.say("{A_own:device} that reached the case's servers."),
            )
        else:
            out[value] = (site.own("device"), site.say("{A_own:device} named in the alerts."))
    by_requests = bool(outside) and all(st["requests"] is not None for st in outside.values())
    unit = "requests" if by_requests else "alerts"
    volume = {
        v: float(st["requests"] if by_requests else st["alerts"]) for v, st in outside.items()
    }
    collector = None
    if len(outside) >= 2:
        ranked = sorted(volume.items(), key=lambda kv: (-kv[1], kv[0]))
        if ranked[0][1] > 0 and ranked[0][1] >= DOMINANT * max(ranked[1][1], 1.0):
            collector = ranked[0][0]
    for value, st in outside.items():
        if len(outside) == 1:
            out[value] = (
                "actor",
                f"The only outside address acting against {site.where()} in this case.",
            )
        elif value == collector:
            nxt = max((v for k, v in volume.items() if k != value), default=0.0)
            verb = "Made" if by_requests else "Raised"
            out[value] = (
                "collector",
                f"{verb} the most {unit} of any actor ({count(int(volume[value]))}, at least "
                f"{DOMINANT:g} times the next actor's {count(int(nxt))}).",
            )
        elif collector is not None and volume[value] <= SMALL * volume[collector]:
            began = outside[collector]["first"]
            before = st["first"] is not None and began is not None and st["first"] < began
            if before:
                out[value] = (
                    "scout",
                    f"Came before the collector, with few {unit}: it looked at the targets first.",
                )
            else:
                out[value] = (
                    "prober",
                    f"Came after the collector began, with few {unit}: it probed the same "
                    "kind of targets.",
                )
        else:
            out[value] = (
                "actor",
                f"An outside address acting against {site.where()} in this case.",
            )
    return out


def actors(scene: Scene, book: Book) -> tuple[tuple[m.ReportActor, ...], int]:
    """The case's actors (at most :data:`MAX_ACTORS`, the busiest first) and how many outside
    addresses the case has in all (the list is cut; the count is not)."""
    f = scene.f
    wanted = [i for i in f.indicators if i.role == "actor" and i.kind in ("ip", "host", "user")]
    stats: dict[str, dict[str, Any]] = {}
    for ind in wanted:
        named = scene.members_naming(ind.value)
        stats[ind.value] = {
            "kind": ind.kind,
            "alerts": sum(x.alerts for x in named),
            "first": min((x.first for x in named if x.first), default=None),
            "last": max((x.last for x in named if x.last), default=None),
            "requests": _requests(scene, ind.value) if ind.kind == "ip" else None,
        }
    named_roles = roles(scene, stats)
    answered = targets.answers(scene)
    outside_ips = [
        st for v, st in stats.items() if st["kind"] == "ip" and not ours(v, scene.ctx.classifier)
    ]
    by_requests = bool(outside_ips) and all(st["requests"] is not None for st in outside_ips)

    def volume(st: dict[str, Any]) -> int:  # one unit for every actor, as the roles use
        return int(st["requests"] if by_requests and st["requests"] is not None else st["alerts"])

    order = sorted(stats.items(), key=lambda kv: (-volume(kv[1]), kv[0]))
    out: list[m.ReportActor] = []
    for value, st in order[:MAX_ACTORS]:
        role, words = named_roles[value]
        kind = st["kind"]
        agents = top(
            (ua for d in _docs_of(scene, value) for ua in d.fields.get("user_agent.original", ())),
            3,
        )
        net, country = _network(scene, value) if kind == "ip" else (None, None)
        outside = kind == "ip" and not ours(value, scene.ctx.classifier)
        got, served, exact = answered.of_ip(value) if outside else (None, (), True)
        text = f"{value} ({role}): {plural(st['alerts'], 'alert')}"
        numbers = [st["alerts"]]
        if st["requests"] is not None:
            text += f" and {plural(st['requests'], 'logged request')}"
            numbers.append(st["requests"])
        if st["first"] is not None:
            text += f", first seen {ist_moment(st['first'])}"
        out.append(
            m.ReportActor(
                value=cut(value, 200),
                kind=kind,
                role=role,
                role_words=cut(words, 400),
                inside=kind != "ip" or ours(value, scene.ctx.classifier),
                network=net,
                country=country,
                user_agents=tuple(cut(a, m.UNTRUSTED) for a in agents),
                first_seen=st["first"],
                last_seen=st["last"],
                alerts=st["alerts"],
                requests=st["requests"],
                listed=value in scene.listed,
                intel=targets.intel_words(scene, value) if outside else None,
                answered=got,
                answered_exact=exact,
                served=served,
                sentence=book.say(
                    "entity",
                    text + ".",
                    "ARGUS's stored alerts" + (" and a web check" if st["requests"] else ""),
                    numbers,
                    from_logs=st["requests"] is not None,
                ),
            )
        )
    if len(stats) > MAX_ACTORS:
        scene.limits.append(f"{MAX_ACTORS} of the case's {len(stats)} actors are listed")
    return tuple(out), len(outside_ips)


def _directories(scene: Scene) -> list[tuple[str | None, str, int]]:
    counts: Counter[tuple[str | None, str]] = Counter()
    for d in scene.f.docs:
        for path in d.fields.get("url.path", ()):
            parts = [p for p in path.split("/") if p]
            if parts:
                counts[(first_of(d.fields.get("url.domain", ())), "/" + parts[0])] += 1
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0][1]))[:20]
    return [(host_site, directory, n) for (host_site, directory), n in ranked]


def assets(scene: Scene) -> tuple[tuple[m.ReportAsset, ...], int]:
    f = scene.f
    destinations = {(i.kind, i.value) for i in f.indicators if i.role in ("c2", "indicator")}
    items: list[m.ReportAsset] = []
    for device in scene.devices:
        named = scene.members_naming(device)
        days = set().union(*(scene.days_of.get(x.id, set()) for x in named)) if named else set()
        reach = Counter(
            v for x in named for kv in scene.entity_of[x.id] if kv in destinations for v in (kv[1],)
        )
        names = sorted(
            ((c, n) for n, c in reach.items() if not is_ip(n)), key=lambda t: (-t[0], t[1])
        )
        label = names[0][1] if names else (sorted(reach)[0] if reach else None)
        items.append(
            m.ReportAsset(
                kind="device",
                value=device,
                label=label,
                alerts=sum(x.alerts for x in named),
                days=len(days),
                first_seen=min((x.first for x in named if x.first), default=None),
                last_seen=max((x.last for x in named if x.last), default=None),
            )
        )
    for ind in f.indicators:
        if ind.role == "actor" and ind.kind == "host":
            items.append(m.ReportAsset(kind="host", value=ind.value))
        if ind.kind == "user":
            items.append(m.ReportAsset(kind="account", value=ind.value))
    for host_site, directory, n in _directories(scene):
        items.append(m.ReportAsset(kind="directory", value=directory, label=host_site, alerts=n))
    items.sort(key=lambda a: (-a.alerts, a.kind, a.value))
    total = len(items)
    if total > MAX_ASSETS:
        scene.limits.append(f"{MAX_ASSETS} of the case's {total} affected assets are listed")
    return tuple(items[:MAX_ASSETS]), total


MAX_USER_DEVICES = 60
MAX_SIGNINS = 40
USERS_SOURCE = "the SSO sign-in logs, as ARGUS kept them"
STATE_ORDER = {"likely": 0, "possible": 1, "unknown": 2, "shared": 3, "none_seen": 4}


def same_account(scene: Scene, book: Book) -> m.ReportSentence | None:
    """One account behind most of the case's addresses: the first account of an address (its
    likely user, or the one with the most sign-ins) is the same on at least :data:`SAME_MIN`
    addresses and on two thirds of those with a sign-in. Then the addresses are most likely one
    device that moved, which the count of addresses alone would read as many devices. A lead from
    the SSO logs, like every account."""
    found = scene.f.users
    if found is None:
        return None
    named = [a for a in found.attributions if a.accounts]
    if len(named) < SAME_MIN:
        return None
    user, n = Counter(a.accounts[0].user for a in named).most_common(1)[0]
    if n < SAME_MIN or 3 * n < 2 * len(named):
        return None
    rest = len(found.attributions) - len(named)
    more = f" No sign-in was seen on {rest} more." if rest else ""
    tail = (
        f"is the probable user on {n} of the {len(named)} addresses with a sign-in: most likely"
        f" one device seen under changing addresses, not {len(named)} separate"
        f" {site.own('devices')}.{more} A lead, not proof."
    )
    numbers = [n, len(named), *([rest] if rest else [])]
    return book.say(
        "entity",
        f"One account, {cut(user, 100)}, {tail}",
        USERS_SOURCE,
        numbers,
        from_logs=True,
        safe=f"One account {tail}",
    )


def users(scene: Scene, book: Book) -> m.ReportUsers:
    """The accounts that signed in from the case's devices, from the stored SSO
    sightings and never from a model. Each device's sentence is a fact read from the logs
    (``from_logs``, no ``safe`` form), so an account without log access sees it hidden and no model
    is ever shown it. Empty when the lookups are off or the case has no internal device."""
    found = scene.f.users
    if found is None or not found.attributions:
        return m.ReportUsers()
    ranked = sorted(found.attributions, key=lambda a: (STATE_ORDER[a.state], a.address))
    devices: list[m.ReportDeviceUsers] = []
    for att in ranked[:MAX_USER_DEVICES]:
        accounts = tuple(
            m.ReportAccount(
                name=cut(a.user, 300),
                device=att.address,
                first_seen=a.first_at,
                last_seen=a.last_at,
                signins=a.events,
                failed=a.failures,
                days=len(a.days),
                browsers=tuple(cut(d, 100) for d in a.devices),
            )
            for a in att.accounts
        )
        say = book.say(
            "entity",
            f"{att.address}: {attributes.sentence(att)}",
            USERS_SOURCE,
            [att.account_count],
            from_logs=True,
        )
        devices.append(
            m.ReportDeviceUsers(
                device=att.address,
                state=att.state,
                sentence=say,
                accounts=accounts,
                account_count=att.account_count,
                at_least=att.at_least,
            )
        )
    if len(ranked) > MAX_USER_DEVICES:
        scene.limits.append(
            f"the accounts of {MAX_USER_DEVICES} of the case's {len(ranked)} devices are listed"
        )
    signins = tuple(
        m.ReportSignin(
            at=e.first_at,
            until=e.last_at if e.last_at != e.first_at else None,
            device=e.address,
            text=cut(attributes.entry_words(e), 600),
        )
        for e in found.entries[:MAX_SIGNINS]
    )
    return m.ReportUsers(
        lead=attributes.LEAD,
        devices=tuple(devices),
        devices_total=found.devices_total,
        signins=signins,
        same=same_account(scene, book),
    )


def _line_text(template: str, version: int) -> str:
    return f"{evidence.SOURCES.get(template, template)} (ARGUS check {template}@{version})"


def evidence_lines(
    scene: Scene, book: Book, incident_id: str
) -> tuple[tuple[m.ReportEvidenceLine, ...], tuple[m.ReportQuery, ...]]:
    """The evidence: the alerts, then the most informative stored answers of the checks that ran
    (at most three of each template, :data:`MAX_EVIDENCE` in all). The queries returned are the
    ones a person runs to verify the case, without repeats."""
    f, cfg = scene.f, scene.ctx.cfg
    lines: list[m.ReportEvidenceLine] = []
    queries: list[m.ReportQuery] = []
    if scene.first and scene.last:
        q = discover.alerts_query(cfg, list(scene.rules), scene.first, scene.last)
        fact = book.add(
            "alerts",
            f"The detection rules raised {plural(scene.alerts, 'alert')} in this case between "
            f"{ist_moment(scene.first)} and {ist_moment(scene.last)}.",
            "ARGUS's stored alerts",
            (scene.alerts,),
            safe=f"The detection rules raised {plural(scene.alerts, 'alert')} in this case.",
        )
        lines.append(
            m.ReportEvidenceLine(
                id="E1",
                fact=fact,
                title="The alerts of the case",
                source="ARGUS's stored alerts",
                status="ok",
                count=scene.alerts,
                at=None,
                query=q,
            )
        )
        queries.append(q)
    chosen: dict[str, list[tuple[evidence.Said, Any, m.ReportQuery]]] = defaultdict(list)
    skipped = 0
    seen: set[tuple[str, str]] = set()
    for row in f.evidence:
        made = evidence.query_for(cfg, row.template, row.version, row.params, row.collected_at)
        if made is None:
            skipped += 1
            continue
        if (row.template, made.text) in seen:
            continue
        seen.add((row.template, made.text))
        said = evidence.say(row.template, row.params, row.snapshot, row.status)
        chosen[row.template].append((said, row, made))
    picked: list[tuple[evidence.Said, Any, m.ReportQuery]] = []
    for template in sorted(chosen):
        ranked = sorted(
            chosen[template],
            key=lambda t: (evidence.sort_key(t[0]), t[1].collected_at, t[2].text),
        )
        picked += ranked[:PER_TEMPLATE]
    picked.sort(key=lambda t: (evidence.sort_key(t[0]), t[1].template, t[2].text))
    kept = picked[: MAX_EVIDENCE - len(lines)]
    kept.sort(key=lambda t: (t[1].template, t[1].collected_at, t[2].text))
    for said, row, q in kept:
        logs = row.template != "ti.lookup"
        found = evidence.shown(row.template, row.params, row.snapshot) if not said.empty else None
        fact = book.add(
            "evidence" if logs else "intel",
            said.text,
            _line_text(row.template, row.version),
            said.numbers,
            from_logs=logs,
        )
        lines.append(
            m.ReportEvidenceLine(
                id=f"E{len(lines) + 1}",
                fact=fact,
                title=evidence.TITLES.get(row.template, row.template),
                source=evidence.SOURCES.get(row.template, row.template),
                status=row.status,
                count=said.count,
                at=row.collected_at,
                query=q,
                from_logs=logs,
                asked=targets.asked(row.template, row.params),
                shows=found.label if found else None,
                details=tuple(m.ReportDetail(text=d.text, count=d.count) for d in found.details)
                if found
                else (),
            )
        )
        queries.append(q)
    left = sum(len(v) for v in chosen.values()) - len(kept)
    if skipped:
        scene.limits.append(
            f"{plural(skipped, 'check')} had no query ARGUS can print and are not listed"
        )
    if left > 0:
        scene.limits.append(f"{plural(left, 'more check')} of the case are not listed")
    if scene.first and scene.last:
        queries.append(discover.tag_query(cfg, incident_id, scene.first, scene.last))
    unique: dict[tuple[str, str, str], m.ReportQuery] = {}
    for q in queries:
        unique.setdefault((q.template, q.index, q.text), q)
    return tuple(lines), tuple(unique.values())


def indicators(scene: Scene) -> tuple[tuple[m.ReportIndicator, ...], int]:
    """The case's own indicators, each with what ARGUS holds about it (the outside answers it
    cached, the local threat lists, when it first appeared on the internal network)."""
    f = scene.f
    first_seen: dict[str, datetime] = {}
    for x in f.members:
        if x.first is None:
            continue
        for _, value in scene.entity_of[x.id]:
            if value not in first_seen or x.first < first_seen[value]:
                first_seen[value] = x.first
    rows: list[m.ReportIndicator] = []
    for ind in f.indicators:
        parts: list[str] = []
        for source in (outside_facts.VIRUSTOTAL, outside_facts.SHODAN, outside_facts.CENSYS):
            found = next(
                (
                    o
                    for o in f.outside
                    if o.source == source and o.kind == ind.kind and o.value == ind.value
                ),
                None,
            )
            if found is not None:
                entry = {
                    "source": found.source,
                    "kind": found.kind,
                    "value": found.value,
                    "status": found.status,
                    "answer": found.answer,
                }
                parts.append(outside_facts.describe(entry))
        if ind.value in scene.listed:
            parts.append("on the local threat lists")
        if ind.value in first_seen:
            parts.append(f"first seen on {site.where()} {ist_date(first_seen[ind.value])}")
        rows.append(
            m.ReportIndicator(
                kind=ind.kind,
                value=cut(ind.value, 512),
                role=ind.role,
                role_words=ROLE_WORDS.get(ind.role, ind.role),
                source=ind.source,
                evidence=cut("; ".join(parts) or "no outside record yet", 500),
            )
        )
    return tuple(rows), f.indicators_total
