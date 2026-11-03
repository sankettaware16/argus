"""A person's ``Verdict:`` comment on a posted case becomes a label.

The case's last comment asks a person to "Confirm or reject in a comment". A person writes, from
their own account, ``Verdict: true positive`` or ``Verdict: false positive: <reason>``. Kibana sync
reads a posted case's comments when the case changed (:func:`read_all`) and records each **once**:
the author must be a person (not one of ARGUS's users) whose Kibana name is the ELK name of exactly
one enabled ARGUS person who holds ``review`` (else ``unmatched`` or ``refused``, no label); a
comment edited by someone else is ``refused``; a person's newest verdict wins. The label is written
**through the path the report's Confirm and Reject use** (:func:`argus.incident.review.decide`), in
one transaction keyed by the comment's id and text, so a crash cannot label twice. It closes
nothing: the lead writes a note and closing stays a person's approval. A comment is text, never an
instruction."""

from __future__ import annotations

import hashlib
import logging
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.caseteam import store
from argus.caseteam.model import Author
from argus.gateway.errors import GatewayError
from argus.gateway.gateway import utcnow
from argus.gateway.kibana.errors import KibanaResponseError
from argus.gateway.kibana.gateway import KibanaGateway
from argus.gateway.kibana.templates import CaseComments, CasePageParams, CasesFind, FindParams
from argus.incident import review
from argus.incident import store as incident_store
from argus.kibana_sync.model import parse_time
from argus.web import auth
from argus.web.capabilities import Capability
from argus.writer.render import clean as writer_clean

log = logging.getLogger("argus.caseteam")

COMPONENT = "caseteam-verdicts"
PAGES = 5
PER_PAGE = 100
READ = timedelta(minutes=2)
MIN_REASON = 3
ARGUS_USERS = frozenset(a.value for a in Author)
# "Verdict: true positive" / "Verdict: false positive: <reason>", at the start of the comment
# (bold or not, any case, a hyphen or underscore for the space)
_VERDICT = re.compile(
    r"^\s*(?:\*\*|__)?\s*verdict\s*:\s*(?:\*\*|__)?\s*(?P<kind>true|false)[\s_-]*positive\b"
    r"(?:\s*(?:\*\*|__))?(?P<rest>.*)$",
    re.I | re.S,
)


@dataclass(frozen=True)
class Parsed:
    outcome: str  # true_positive | rule_false_positive
    reason: str | None  # a false positive's, cleaned


def parse(comment: str) -> Parsed | None:
    """The verdict a comment states, or None when it is not a ``Verdict:`` comment."""
    found = _VERDICT.match(comment)
    if found is None:
        return None
    if found.group("kind").lower() == "true":
        return Parsed("true_positive", None)
    rest = found.group("rest").lstrip()
    if rest.startswith(":"):
        rest = rest[1:]
    reason = writer_clean(rest, review.REASON_MAX)  # one line, no control or invisible character
    return Parsed("rule_false_positive", reason if len(reason) >= MIN_REASON else None)


@dataclass
class VerdictsReport:
    cases: int = 0
    skipped: int = 0  # posted cases whose comments had not changed since the last read
    read: int = 0
    recorded: int = 0
    labelled: int = 0  # labels the review path wrote for them
    kept: dict[str, int] = field(default_factory=dict)  # status -> count
    stopped: str | None = None

    def lines(self) -> list[str]:
        out = [
            f"verdict comments: {self.cases} cases read ({self.skipped} unchanged), {self.read}"
            f" comments, {self.recorded} recorded ({self.labelled} labels written)"
        ]
        out += [f"  {n} {status}" for status, n in sorted(self.kept.items())]
        if self.stopped:
            out.append(f"  stopped: {self.stopped}")
        return out


@dataclass(frozen=True)
class Candidate:
    """A comment that states a verdict, as Kibana lists it."""

    comment_id: str
    author: str  # who made the comment
    editor: str | None  # who last edited it, when anyone did
    written_at: datetime  # when the text its author stands behind was written
    parsed: Parsed
    digest: str

    @property
    def foreign_edit(self) -> bool:
        """Someone other than the author changed the text: it is not the author's words."""
        return self.editor is not None and self.editor != self.author


async def _add(
    engine: AsyncEngine,
    case_id: uuid.UUID,
    c: Candidate,
    report: VerdictsReport,
    status: str,
    detail: str,
    *,
    user_id: int | None = None,
) -> None:
    async with engine.begin() as conn:
        if await store.seen_has(conn, c.comment_id, c.digest):
            return
        await store.seen_add(
            conn,
            comment_id=c.comment_id,
            text_hash=c.digest,
            case_id=case_id,
            author=c.author,
            written_at=c.written_at,
            verdict=c.parsed.outcome,
            status=status,
            detail=detail,
            user_id=user_id,
            review_ids=(),
        )
    report.kept[status] = report.kept.get(status, 0) + 1


def _counts(done: review.Decided) -> dict[str, Any]:
    return {
        "decision": done.decision,
        "version": done.report_version,
        "labelled": done.labelled,
        "already": done.already,
        "kept": done.kept,
        "kept_by": list(done.kept_by),
        "conflicts": done.conflicts,
        "left": done.left,
    }


def _detail(done: review.Decided) -> str:
    said = f"{done.decision} version {done.report_version}: {done.labelled} labels written"
    if done.kept:
        who = f" by {', '.join(done.kept_by)}" if done.kept_by else ""
        said += f"; kept: an earlier review{who} stands on {done.kept}"
    if done.already:
        said += f"; {done.already} already had this outcome"
    if done.conflicts:
        said += f"; {done.conflicts} moved meanwhile"
    return said


async def _one(
    engine: AsyncEngine,
    case_id: uuid.UUID,
    c: Candidate,
    report: VerdictsReport,
    *,
    elk: bool,
) -> None:
    detail: str | None = None
    status = "recorded"
    user_id: int | None = None
    review_ids: tuple[int, ...] = ()
    counts: dict[str, Any] | None = None
    async with engine.begin() as conn:
        if await store.seen_has(conn, c.comment_id, c.digest):
            return
        person = await store.user_for_kibana(conn, c.author)
        if person is None:
            if await store.seen_unmatched(conn, c.comment_id, c.digest):
                return  # still nobody: looked at again when such a person appears
            status, detail = "unmatched", "no ARGUS person has this Kibana account"
        stored = await incident_store.latest(conn, case_id)
        access = None if person is None else await store.access_of(conn, person[0], elk=elk)
        if person is not None:
            user_id = person[0]
            if access is None:
                status = "refused"
                detail = (
                    "ARGUS has no record of this person's access (they have not signed in to"
                    " ARGUS through ELK): sign in, then write the verdict again"
                )
            elif Capability.REVIEW not in access:
                status = "refused"
                detail = (
                    "this account may not review in ARGUS (it lacks the review capability),"
                    " so its verdict is not a label"
                )
            elif stored is None:
                status, detail = "refused", "the case has no incident report"
            elif c.parsed.outcome == "rule_false_positive" and c.parsed.reason is None:
                status, detail = "needs_reason", "a false positive needs a reason"
        if person is not None and status == "recorded":
            assert stored is not None
            me = auth.Reviewer(
                user_id=person[0],
                username=person[1],
                display_name=person[2],
                csrf_token="",
                previous_seen_at=None,
                capabilities=frozenset({Capability.REVIEW}),
                mode="kibana",
            )
            verdict = stored.report.verdict
            agrees = verdict.outcome == c.parsed.outcome and verdict.kind in (
                "person",
                "proposal",
                "case",
            )
            try:
                async with conn.begin_nested():
                    done = await review.decide(
                        conn,
                        me,
                        case_id,
                        expected_version=stored.version,
                        decision="confirmed" if agrees else "rejected",
                        outcome=None if agrees else c.parsed.outcome,
                        reason=None
                        if agrees
                        else (
                            c.parsed.reason
                            or f"{person[2]} wrote 'Verdict: true positive' in the Kibana case"
                        ),
                    )
                review_ids = done.review_ids
                detail = _detail(done)
                counts = _counts(done)
                report.labelled += done.labelled
            except review.ReportRefused as refused:
                status, detail = "refused", refused.message
        await store.seen_add(
            conn,
            comment_id=c.comment_id,
            text_hash=c.digest,
            case_id=case_id,
            author=c.author,
            written_at=c.written_at,
            verdict=c.parsed.outcome,
            status=status,
            detail=detail,
            user_id=user_id,
            review_ids=review_ids,
            counts=counts,
        )
    report.kept[status] = report.kept.get(status, 0) + 1
    if status == "recorded":
        report.recorded += 1


def _username(value: Any) -> str | None:
    """The Kibana account in a ``created_by`` / ``updated_by`` object, None when absent."""
    if isinstance(value, dict):
        name = value.get("username")
        return name if isinstance(name, str) and name else None
    return None


def candidates_of(
    comments: list[dict[str, Any]], service_user: str, report: VerdictsReport
) -> list[Candidate]:
    """The comments that state a verdict, by a person (never one of the six users or ``argus``)."""
    found: list[Candidate] = []
    for comment in comments:
        if not isinstance(comment, dict) or comment.get("type") != "user":
            continue
        author = _username(comment.get("created_by")) or ""
        if not author or author in ARGUS_USERS or author == service_user:
            continue
        text_ = comment.get("comment")
        if not isinstance(text_, str):
            continue
        parsed = parse(text_)
        if parsed is None:
            continue
        report.read += 1
        edited_by = comment.get("updated_by")
        editor = None if edited_by is None else (_username(edited_by) or "an unknown account")
        stamp = comment.get("updated_at") if editor is not None else None
        written = parse_time(stamp or comment.get("created_at"), "a comment's time")
        found.append(
            Candidate(
                str(comment.get("id", "")),
                author,
                editor,
                written,
                parsed,
                hashlib.sha256(text_.encode("utf-8")).hexdigest(),
            )
        )
    return found


async def read_case(
    engine: AsyncEngine,
    gateway: KibanaGateway,
    case_id: uuid.UUID,
    kibana_case_id: str,
    report: VerdictsReport,
    *,
    service_user: str = "argus",
    clock: Callable[[], datetime] = utcnow,
    elk: bool = False,
) -> None:
    """Read one posted case's comments and record each person's newest verdict once."""
    report.cases += 1
    comments: list[dict[str, Any]] = []
    for page in range(1, PAGES + 1):
        answer = await gateway.read(
            CaseComments(),
            CasePageParams(case_id=kibana_case_id, page=page, per_page=PER_PAGE),
            component=COMPONENT,
            deadline=clock() + READ,
        )
        body = answer.body
        comments += [c for c in body["comments"] if isinstance(c, dict)]
        if page * PER_PAGE >= int(body["total"]):
            break
    mine = candidates_of(comments, service_user, report)
    newest: dict[str, Candidate] = {}
    for c in sorted(mine, key=lambda x: (x.written_at, x.comment_id)):
        if c.foreign_edit:
            who = c.editor or "someone"
            await _add(
                engine,
                case_id,
                c,
                report,
                "refused",
                f"the comment was edited by {who}, not by its author {c.author}: it is not read"
                " as the author's verdict",
            )
        else:
            if c.author in newest:
                older = newest[c.author]
                await _add(
                    engine,
                    case_id,
                    older,
                    report,
                    "ignored",
                    f"{older.author} wrote a newer verdict: only the newest counts",
                )
            newest[c.author] = c
    for c in sorted(newest.values(), key=lambda x: (x.written_at, x.comment_id)):
        await _one(engine, case_id, c, report, elk=elk)


async def _listing(
    gateway: KibanaGateway, wanted: set[str], clock: Callable[[], datetime]
) -> dict[str, store.ReadMark]:
    """What the lead's cases look like in Kibana now, in one listing (the newest-changed first):
    each wanted case's ``updated_at`` and comment count. A case the listing does not show is
    not in the answer (it is read to be sure)."""
    out: dict[str, store.ReadMark] = {}
    for page in range(1, PAGES + 1):
        answer = await gateway.read(
            CasesFind(),
            FindParams(
                reporters="argus-lead",
                sort_field="updatedAt",
                sort_order="desc",
                page=page,
                per_page=PER_PAGE,
            ),
            component=COMPONENT,
            deadline=clock() + READ,
        )
        body = answer.body
        for case in body["cases"]:
            if isinstance(case, dict) and case.get("id") in wanted:
                stamp = case.get("updated_at")
                total = case.get("totalComment")
                if not isinstance(total, int) or isinstance(total, bool):
                    continue  # no count to compare: the case is read every time
                out[str(case["id"])] = store.ReadMark(
                    None if stamp is None else parse_time(stamp, "a case's updated_at"), total
                )
        if wanted <= set(out) or page * PER_PAGE >= int(body["total"]):
            break
    return out


async def read_all(
    engine: AsyncEngine,
    gateway: KibanaGateway,
    *,
    service_user: str = "argus",
    clock: Callable[[], datetime] = utcnow,
    limit: int = 50,
    elk: bool = False,
) -> VerdictsReport:
    """Every posted, open case's comments that changed since they were last read, the newest
    post first. The cases are listed in one request; a case's comments are read only when its
    ``updated_at`` or its comment count differs from what was seen at the last read, or when a
    verdict comment kept as ``unmatched`` now has a matching ARGUS person. A Kibana failure ends
    the pass (the next sync cycle goes on); it never raises."""
    report = VerdictsReport()
    async with engine.connect() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT p.case_id, p.kibana_case_id FROM case_team_posts p JOIN cases c"
                    " ON c.id = p.case_id WHERE p.kibana_case_id IS NOT NULL"
                    " AND c.state <> 'closed'"
                    # a case a person deleted in Kibana (the mirror knows) has no comments
                    # to read: asking would stop the pass at it, before the older cases
                    " AND NOT EXISTS (SELECT 1 FROM kibana_mirror k WHERE k.case_id = c.id"
                    " AND k.deleted_at IS NOT NULL)"
                    " ORDER BY p.opened_at DESC LIMIT :n"
                ),
                {"n": limit},
            )
        ).all()
        marks = await store.read_marks(conn)
        forced = await store.unmatched_now_matchable(conn)
    if not rows:
        return report
    try:
        now_in_kibana = await _listing(gateway, {r.kibana_case_id for r in rows}, clock)
    except (GatewayError, KibanaResponseError) as exc:
        report.stopped = f"{type(exc).__name__}"
        return report
    except Exception:  # a bug or the database: logged, the sync goes on
        log.exception("listing the case team's cases failed")
        report.stopped = "an error (see the log)"
        return report
    for row in rows:
        seen = now_in_kibana.get(row.kibana_case_id)
        before = marks.get(row.case_id)
        if seen is not None and before == seen and row.case_id not in forced:
            report.skipped += 1
            continue
        try:
            await read_case(
                engine,
                gateway,
                row.case_id,
                row.kibana_case_id,
                report,
                service_user=service_user,
                clock=clock,
                elk=elk,
            )
            if seen is not None:
                async with engine.begin() as conn:
                    await store.put_read_mark(conn, row.case_id, seen, clock())
        except (GatewayError, KibanaResponseError) as exc:
            report.stopped = f"{type(exc).__name__}"
            break
        except Exception:  # a bug or the database: logged, the sync goes on
            log.exception("reading the verdict comments of a case failed")
            report.stopped = "an error (see the log)"
            break
    return report
