"""Planning a post (AR8, D-195): the stored report in, the ordered steps out. Pure: no database,
no clock, no network; the same report and alerts always give the same plan, and the plan's hash is
what a person's approval binds.

* :func:`first_plan` is generation 1: the lead opens the case, attaches and tags the alerts, then
  the owners' comments in the fixed order (evidence, devices, intel when needed, actions, queries),
  the reporter's files and the comment listing them, and the lead's verdict last.
* :func:`update_plan` is a later generation, for a report that got a newer version: only what
  changed, as a new "Update" comment by the owning user; never an edit, never a delete. A file is
  uploaded again only if its bytes changed, under a versioned name.
* :func:`refresh_plan` corrects what was posted, in place (D-236): the lead sets the case's title
  and description, the user who wrote a comment rewrites it. A retitle in ARGUS reaches Kibana
  as the first step of the next update plan; the description and the comments are rewritten only
  when a person asks (``argus case team refresh``). An edit is a value to set against the
  version Kibana holds *now*: the poster reads it first and sends only if Kibana still holds
  what ARGUS last wrote (never over a person's change).
* :func:`note_plan` is the lead's note about what is not the report's: a person's ``Verdict:``
  comment (and what the review path did with it), people who disagree, alerts that could not be
  tagged.

A step is turned into the exact Kibana request by :func:`request_of` (the lane's templates); the
step's ``request_hash`` is the lane's own hash of that request, with a stand-in case id while the
case is not open yet, and the author in it.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, cast

from pydantic import BaseModel

from argus import site
from argus.caseteam import render, visual
from argus.caseteam.model import Author, Plan, Step, text_hash, unit_hash
from argus.gateway.kibana import models, upload
from argus.gateway.kibana.gateway import build_final
from argus.gateway.kibana.templates import (
    KibanaTemplate,
    TeamAlertTags,
    TeamAttachAlerts,
    TeamAttachFile,
    TeamAttachParams,
    TeamComment,
    TeamCommentEditParams,
    TeamCommentParams,
    TeamCreateCase,
    TeamEditCase,
    TeamEditComment,
    TeamFileParams,
)
from argus.gateway.kibana.validator import request_hash
from argus.incident import files as report_files
from argus.incident import model as m
from argus.incident.words import size

REFRESH = "refresh"  # a payload flag: this comment step belongs to a person's refresh
STAND_IN = "NEWCASE"  # the case id in the hashes of a generation planned before the case exists
STAND_IN_VERSION = "WzAsMF0="  # the Kibana version of an edit planned before it is read
PER_CALL = 100  # alerts a call unless the settings say otherwise (case_team.alerts_per_call, D-235)
FILE_KINDS = ("pdf", "dashboard", "indicators", "affected")
FILE_WHAT = {
    "pdf": "Incident report (PDF)",
    "dashboard": "Dashboard, one page (PDF)",
    "indicators": "Indicators (CSV)",
    "affected": "Affected devices (CSV)",
    "accounts": "Affected accounts (CSV)",
}


def kinds_of(report: m.IncidentReport) -> tuple[str, ...]:
    """The files this report has: the three, and the accounts CSV when it names an account
    (AR6, D-216). A report without accounts has exactly the files it always had."""
    return (*FILE_KINDS, "accounts") if report_files.has_accounts(report) else FILE_KINDS


@dataclass(frozen=True)
class AlertRef:
    alert_id: str
    index: str


@dataclass(frozen=True)
class Target:
    """Where the case lives: the space and its alerts' index prefix."""

    space: str = field(default_factory=lambda: site.active().space)  # the site's Kibana space

    @property
    def prefix(self) -> str:
        return site.active().alerts_backing_of(self.space)

    def concrete(self, index: str) -> bool:
        """Whether ``index`` is one of this space's concrete alert indices (what an attach may
        name: the alias, or another space's index, is not)."""
        return (
            index.startswith(self.prefix)
            and index[len(self.prefix) :].isdigit()
            and (len(index) == len(self.prefix) + 6)
        )


@dataclass(frozen=True)
class PostedComment:
    """A comment ARGUS posted, as Kibana holds it now as far as ARGUS knows: the step that made
    it, its Kibana id, its author and the text it last wrote (the first posting, or the newest
    edit of it)."""

    key: str
    part: str
    author: str
    comment_id: str
    text: str


@dataclass(frozen=True)
class Posted:
    """What earlier generations already wrote to the case (from the verified steps)."""

    kibana_case_id: str
    version: int  # the report version of the newest generation
    gen: int  # the newest generation's number
    units: Mapping[str, frozenset[str]] = field(default_factory=dict)  # part -> unit hashes
    files: Mapping[str, str] = field(default_factory=dict)  # file kind -> sha-256 uploaded
    attached: frozenset[str] = frozenset()  # alert ids attached
    verdict: tuple[str | None, float | None] | None = None
    gone: frozenset[str] = frozenset()  # alerts a tag call found no longer in the alerts index
    title: str | None = None  # the title ARGUS last wrote to the case
    title_by_person: bool = False  # a person changed it in Kibana: ARGUS never edits it again
    description: str | None = None  # the description ARGUS last wrote
    comments: Mapping[str, PostedComment] = field(default_factory=dict)  # by the step's key


# --------------------------------------------------------------------------- steps -> requests


_BUNDLES: dict[tuple[str, str, str], dict[str, tuple[str, bytes]]] = {}


def _file_bytes(report: m.IncidentReport) -> dict[str, tuple[str, bytes]]:
    """kind -> (the file's name, its bytes), the three files by their hand-made names. The PDF
    takes a moment to make, so the last few are kept (the same report is the same bytes)."""
    key = (report.header.case_id, report.meta.as_at.isoformat(), m.content_hash(report))
    found = _BUNDLES.get(key)
    if found is None:
        made = report_files.bundle(report)
        names = {
            "pdf": report_files.pdf_name(report),
            "dashboard": report_files.dashboard_name(report),
            "indicators": report_files.indicators_name(report),
            "affected": report_files.affected_name(report),
        }
        if report_files.has_accounts(report):
            names["accounts"] = report_files.accounts_name(report)
        found = {kind: (name, made[name]) for kind, name in names.items()}
        if len(_BUNDLES) >= 6:
            _BUNDLES.pop(next(iter(_BUNDLES)))
        _BUNDLES[key] = found
    return found


def versioned(name: str, version: int | None) -> str:
    """``X_Incident_Report.pdf`` -> ``X_Incident_Report_v3.pdf`` (an update's file name)."""
    if version is None:
        return name
    stem, _, ext = name.rpartition(".")
    return f"{stem}_v{version}.{ext}"


def upload_of(report: m.IncidentReport, kind: str, version: int | None) -> upload.FileUpload:
    name, data = _file_bytes(report)[kind]
    name = versioned(name, version)
    stem, _, ext = name.rpartition(".")
    mime = "application/pdf" if ext == "pdf" else "text/csv"
    return upload.FileUpload(filename=stem, mime=mime, data=data)  # type: ignore[arg-type]


def request_of(
    step: Step,
    kibana_case_id: str | None,
    report: m.IncidentReport | None = None,
    version: str | None = None,
) -> tuple[KibanaTemplate, BaseModel]:
    """The lane's template and parameters for a step. A file step needs the report (its bytes
    are made again from it and must be the ones the plan hashed); an edit needs the Kibana
    version the poster just read (``version``; a stand-in while a plan is only hashed)."""
    case = kibana_case_id or STAND_IN
    p = step.payload
    seen = version or STAND_IN_VERSION
    if step.kind in ("retitle", "redescribe"):
        change = models.CaseChange(
            id=case,
            version=seen,
            title=p["title"] if step.kind == "retitle" else None,
            description=step.text if step.kind == "redescribe" else None,
        )
        return TeamEditCase(), models.TeamCasePatch(cases=(change,))
    if step.kind == "edit_comment":
        return TeamEditComment(), TeamCommentEditParams(
            case_id=case,
            author=step.author.value,
            comment_id=p["comment_id"],
            version=seen,
            comment=step.text or "",
        )
    if step.kind == "open":
        body = models.TeamCaseCreate(
            title=p["title"],
            description=step.text or "",
            tags=tuple(p["tags"]),
            severity=p["severity"],
        )
        return TeamCreateCase(), body
    if step.kind == "attach":
        return TeamAttachAlerts(), TeamAttachParams(
            case_id=case,
            alerts=tuple((a, i) for a, i in p["alerts"]),
            expect_total=int(p["expect_total"]),
        )
    if step.kind == "tag":
        return TeamAlertTags(), models.AlertTagChange(
            ids=tuple(p["ids"]), tags=models.AlertTagSet(tags_to_add=tuple(p["tags"]))
        )
    if step.kind == "comment":
        return TeamComment(), TeamCommentParams(
            case_id=case,
            author=step.author.value,
            comment=step.text or "",
        )
    if step.kind == "file":
        if report is None:
            raise ValueError("a file step is made again from its report")
        made = upload_of(report, p["file_kind"], p.get("version"))
        if made.sha256 != p["sha256"]:
            raise ValueError("the file is not the one the plan hashed (the report changed)")
        return TeamAttachFile(), TeamFileParams(case_id=case, file=made)
    raise ValueError(f"unknown step kind {step.kind}")


def hash_step(
    step: Step, target: Target, kibana_case_id: str | None, report: m.IncidentReport
) -> str:
    template, params = request_of(step, kibana_case_id, report)
    return request_hash(build_final(template, params, target.space, target.prefix))


def sealed(
    steps: Sequence[Step], target: Target, kibana_case_id: str | None, report: m.IncidentReport
) -> tuple[Step, ...]:
    return tuple(s.with_hash(hash_step(s, target, kibana_case_id, report)) for s in steps)


# --------------------------------------------------------------------------- generation 1


def _batches(alerts: Sequence[AlertRef], per_call: int = PER_CALL) -> list[list[AlertRef]]:
    return [list(alerts[i : i + per_call]) for i in range(0, len(alerts), per_call)]


def verdict_payload(report: m.IncidentReport) -> dict[str, Any]:
    """The verdict a verdict comment states (an update posts one only if this changes)."""
    c = report.verdict.confidence
    return {"outcome": report.verdict.outcome, "confidence": None if c is None else round(c, 2)}


def alert_steps(
    alerts: Sequence[AlertRef], tags: Sequence[str], already: int = 0, per_call: int = PER_CALL
) -> list[Step]:
    """The lead's attach calls (``per_call`` alerts each) and then the calls that tag the same
    alerts."""
    out: list[Step] = []
    batches = _batches(alerts, per_call)
    total = already
    for n, batch in enumerate(batches, 1):
        total += len(batch)
        out.append(
            Step(
                f"attach:{n}",
                "attach",
                Author.LEAD,
                "alerts",
                payload={"alerts": [[a.alert_id, a.index] for a in batch], "expect_total": total},
            )
        )
    for n, batch in enumerate(batches, 1):
        out.append(
            Step(
                f"tag:{n}",
                "tag",
                Author.LEAD,
                "tags",
                payload={"ids": [a.alert_id for a in batch], "tags": list(tags)},
            )
        )
    return out


def comment_steps(
    part: render.Part,
    *,
    heading: str | None = None,
    intro: Sequence[str] | None = None,
    units: Sequence[str] | None = None,
) -> list[Step]:
    texts, _ = render.comments_of(part, units, heading=heading, intro=intro)
    hashes = tuple(unit_hash(u) for u in (part.units if units is None else units))
    return [
        Step(
            f"comment:{part.name}:{i}",
            "comment",
            part.author,
            part.name,
            text=text,
            units=hashes if i == 1 else (),
        )
        for i, text in enumerate(texts, 1)
    ]


def file_steps(
    report: m.IncidentReport, kinds: Sequence[str], version: int | None
) -> tuple[list[Step], list[tuple[str, str, int, str]]]:
    """The reporter's upload steps and the rows its listing comment shows."""
    steps: list[Step] = []
    rows: list[tuple[str, str, int, str]] = []
    for kind in kinds:
        made = upload_of(report, kind, version)
        steps.append(
            Step(
                f"file:{kind}",
                "file",
                Author.REPORTER,
                "files",
                payload={
                    "file_kind": kind,
                    "filename": made.filename,
                    "name": made.full_name,
                    "mime": made.mime,
                    "sha256": made.sha256,
                    "size": len(made.data),
                    "version": version,
                },
            )
        )
        rows.append((made.full_name, FILE_WHAT[kind], len(made.data), made.sha256))
    return steps, rows


def first_plan(
    report: m.IncidentReport,
    version: int,
    alerts: Sequence[AlertRef],
    ctx: render.Context,
    target: Target = Target(),  # noqa: B008
    per_call: int = PER_CALL,
) -> Plan:
    """Generation 1: the case, its alerts, every part by its owner, the files, the verdict."""
    steps: list[Step] = [
        Step(
            "open",
            "open",
            Author.LEAD,
            "open",
            text=render.description(report, ctx, attached=len(alerts)),
            payload={
                "title": render.title_of(report),
                "tags": list(render.tags_of(report)),
                "severity": report.header.severity,
            },
        )
    ]
    steps += alert_steps(alerts, render.alert_tags_of(report), per_call=per_call)
    for part in render.parts_of(report, ctx):
        steps += comment_steps(part)
        if part.name == "evidence":  # AR10: the visualiser follows the evidence comment
            steps += visual.steps(report, target.space)
    file_list, rows = file_steps(report, kinds_of(report), None)
    steps += file_list
    steps.append(
        Step(
            "comment:files",
            "comment",
            Author.REPORTER,
            "files",
            text=render.files_comment(report, rows),
        )
    )
    steps.append(
        Step(
            "comment:verdict",
            "comment",
            Author.LEAD,
            "verdict",
            text=render.verdict_comment(report, ctx),
            payload=verdict_payload(report),
        )
    )
    return Plan(
        report.header.incident_id,
        report.header.case_id,
        1,
        version,
        sealed(steps, target, None, report),
    )


# --------------------------------------------------------------------------- later generations


def posted_units(report: m.IncidentReport, ctx: render.Context) -> dict[str, frozenset[str]]:
    """What a fresh generation 1 of this report would have posted, by part (the baseline of a
    case that was posted before this table kept the hashes)."""
    return {p.name: frozenset(unit_hash(u) for u in p.units) for p in render.parts_of(report, ctx)}


def update_plan(
    report: m.IncidentReport,
    version: int,
    alerts: Sequence[AlertRef],
    ctx: render.Context,
    posted: Posted,
    *,
    max_alerts: int,
    target: Target = Target(),  # noqa: B008
    per_call: int = PER_CALL,
) -> Plan:
    """The "Update" round: only what is new since ``posted``, by the user that owns each part."""
    steps: list[Step] = []
    title = retitle_step(report, posted)
    if title is not None:  # ARGUS's own retitle reaches the case (D-230, D-236)
        steps.append(title)
    fresh = [
        a for a in alerts if a.alert_id not in posted.attached and a.alert_id not in posted.gone
    ]
    fresh = fresh[: max(max_alerts - len(posted.attached), 0)]
    if fresh:
        steps += alert_steps(
            fresh, render.alert_tags_of(report), already=len(posted.attached), per_call=per_call
        )
    before_glance = posted.units.get(visual.PART, frozenset())
    for part in render.parts_of(report, ctx):
        before = posted.units.get(part.name, frozenset())
        now = {unit_hash(u) for u in part.units}
        new = [u for u in part.units if unit_hash(u) not in before]
        if not new:
            continue
        gone = len(before - now)
        intro = [
            f"New since report version {posted.version}: {len(new)} lines (version {version})."
        ]
        if gone:
            intro.append(f"{gone} earlier lines no longer apply; see the report.")
        steps += comment_steps(part, heading=f"Update: {part.title}", intro=intro, units=new)
    if visual.due(report, target.space, before_glance):  # AR10: the glance, if it changed
        steps += visual.steps(report, target.space, update=bool(before_glance))
    changed = [
        kind
        for kind in kinds_of(report)
        if upload_of(report, kind, version).sha256 != posted.files.get(kind)
    ]
    if changed:
        file_list, rows = file_steps(report, changed, version)
        steps += file_list
        steps.append(
            Step(
                "comment:files",
                "comment",
                Author.REPORTER,
                "files",
                text=render.files_comment(report, rows, update=True),
            )
        )
    now_verdict = (
        report.verdict.outcome,
        None if report.verdict.confidence is None else round(report.verdict.confidence, 2),
    )
    if posted.verdict is not None and now_verdict != posted.verdict:
        was = m.ReportVerdict(
            outcome=cast("m.Outcome | None", posted.verdict[0]),
            words="",
            kind="proposal",
            confidence=posted.verdict[1],
            source="",
        )
        steps.append(
            Step(
                "comment:verdict",
                "comment",
                Author.LEAD,
                "verdict",
                text=render.verdict_comment(report, ctx, update_of=was),
                payload=verdict_payload(report),
            )
        )
    return Plan(
        report.header.incident_id,
        report.header.case_id,
        posted.gen + 1,
        version,
        sealed(steps, target, posted.kibana_case_id, report),
        posted.kibana_case_id,
    )


def retitle_step(report: m.IncidentReport, posted: Posted) -> Step | None:
    """The lead's retitle when ARGUS's title moved since it wrote the case's (never over a title
    a person changed in Kibana: the poster reads it first, and a person's change is left)."""
    new = render.title_of(report)
    if posted.title is None or posted.title_by_person or posted.title == new:
        return None
    return Step(
        "edit:title",
        "retitle",
        Author.LEAD,
        "title",
        payload={"title": new, "was": posted.title},
    )


def moved_text(part: render.Part, comment: PostedComment) -> str:
    """What a spare comment says when its part now fits in fewer comments."""
    number = comment.key.rsplit(":", 1)[1]
    return f"## {part.title} ({number})\n\nThis part now fits in the comments above."


def edit_comment_step(had: PostedComment, body: str, units: tuple[str, ...]) -> Step:
    """The step that rewrites a comment ARGUS posted, under the key of the one it replaces."""
    return Step(
        f"edit:{had.key}",
        "edit_comment",
        Author(had.author),
        had.part,
        text=body,
        payload={"of": had.key, "comment_id": had.comment_id, "was_hash": text_hash(had.text)},
        units=units,
    )


def refresh_plan(
    report: m.IncidentReport,
    version: int,
    ctx: render.Context,
    posted: Posted,
    *,
    target: Target = Target(),  # noqa: B008
) -> Plan:
    """A person's ``argus case team refresh``: the title, the description and every comment of the
    case as the newest report renders them, each set in place where it differs from what ARGUS
    last wrote (the text of an earlier posting or its newest edit). A comment that now needs
    more comments than it had gets the extra ones as new comments; one that needs fewer leaves a
    short note in the spare ones (a comment is never deleted). The files, the verdict and the
    lead's notes are not the report's parts and are left alone. An empty plan: nothing differs."""
    steps: list[Step] = []
    title = retitle_step(report, posted)
    if title is not None:
        steps.append(title)
    description = render.description(report, ctx, attached=len(posted.attached))
    if posted.description is not None and posted.description != description:
        steps.append(
            Step(
                "edit:description",
                "redescribe",
                Author.LEAD,
                "description",
                text=description,
                payload={"was_hash": text_hash(posted.description)},
            )
        )
    for part in render.parts_of(report, ctx):
        texts, _ = render.comments_of(part)
        hashes = tuple(unit_hash(u) for u in part.units)
        old = {k: c for k, c in posted.comments.items() if c.part == part.name}
        for i, body in enumerate(texts, 1):
            key = f"comment:{part.name}:{i}"
            had = old.get(key)
            if had is None:  # a part that did not need this comment before
                steps.append(
                    Step(
                        key,
                        "comment",
                        part.author,
                        part.name,
                        text=body,
                        payload={REFRESH: True},  # not an update round: see sender._finish
                        units=hashes if i == 1 else (),
                    )
                )
            elif had.text != body:
                steps.append(edit_comment_step(had, body, hashes if i == 1 else ()))
        for key, spare in sorted(old.items()):
            if int(key.rsplit(":", 1)[1]) > len(texts) and spare.text != moved_text(part, spare):
                steps.append(edit_comment_step(spare, moved_text(part, spare), ()))
    return Plan(
        report.header.incident_id,
        report.header.case_id,
        posted.gen + 1,
        version,
        sealed(steps, target, posted.kibana_case_id, report),
        posted.kibana_case_id,
    )


def closing_key(ref: str) -> str:
    """The step key of the lead's note for a verdict comment (``ref``: its id and text hash)."""
    return f"comment:closing:{hashlib.sha256(ref.encode()).hexdigest()[:10]}"


def conflict_key(verdicts: Sequence[tuple[int, str]]) -> str:
    """The step key of the note that people disagree: one for each set of newest verdicts."""
    body = json.dumps(sorted(verdicts), separators=(",", ":")).encode()
    return f"comment:conflict:{hashlib.sha256(body).hexdigest()[:10]}"


def untagged_key(tag_step_id: int) -> str:
    return f"comment:untagged:{tag_step_id}"


def note_plan(
    report: m.IncidentReport,
    version: int,
    posted: Posted,
    *,
    key: str,
    text: str,
    target: Target = Target(),  # noqa: B008
) -> Plan:
    """One comment by the lead that is not part of the report: a note about a person's verdict,
    a disagreement, or alerts that could not be tagged. ``key`` makes the step unique, so a thing
    is said once."""
    step = Step(key, "comment", Author.LEAD, "note", text=text)
    return Plan(
        report.header.incident_id,
        report.header.case_id,
        posted.gen + 1,
        version,
        sealed([step], target, posted.kibana_case_id, report),
        posted.kibana_case_id,
    )


def describe(plan: Plan) -> list[dict[str, Any]]:
    """The plan for a person (preview, API): who does what, in order."""
    out: list[dict[str, Any]] = []
    for n, s in enumerate(plan.steps, 1):
        out.append(
            {
                "n": n,
                "key": s.key,
                "kind": s.kind,
                "author": s.author.value,
                "part": s.part,
                "what": s.describe(),
                "chars": len(s.text or ""),
                "size": size(int(s.payload.get("size", 0))) if s.kind == "file" else None,
            }
        )
    return out
