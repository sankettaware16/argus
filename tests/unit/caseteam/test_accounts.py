"""The Kibana case carries the accounts that signed in from the affected devices (AR6, D-216): a
comment by `argus-evidence` with the table the escalation to the CISO needs, the accounts CSV in the
Files tab, both only when the report names an account, and an "Update" when a posted case gains one.
A report without accounts plans exactly what it always did."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from argus.caseteam import plan, render
from argus.caseteam.model import Author
from argus.incident import model as m
from tests.unit.caseteam import kit

pytestmark = pytest.mark.unit
CTX = kit.CTX
IDX = ".internal.alerts-security.alerts-acme-soc-000001"
NAME = "user-ar6-alpha"
WHEN = datetime(2026, 10, 26, 8, 40, tzinfo=UTC)


def with_accounts(report: m.IncidentReport, *names: str) -> m.IncidentReport:
    accounts = tuple(
        m.ReportAccount(
            name=n, device="10.0.0.7", first_seen=WHEN, last_seen=WHEN, signins=3, failed=0,
            days=1, browsers=("Chrome on Windows",),
        )
        for n in names
    )  # fmt: skip
    sentence = m.ReportSentence(text="10.0.0.7: Probable user.", cites=("F1",))
    device = m.ReportDeviceUsers(
        device="10.0.0.7",
        state="likely" if len(names) == 1 else "possible",
        sentence=sentence,
        accounts=accounts,
        account_count=len(names),
    )
    return report.model_copy(update={"users": m.ReportUsers(lead="A lead.", devices=(device,))})


def alerts(n: int) -> list[plan.AlertRef]:
    return [plan.AlertRef(f"{i:064x}", IDX) for i in range(n)]


def test_a_report_without_accounts_posts_no_accounts_comment_and_no_third_file() -> None:
    report = kit.amadey()
    assert render.accounts_part(report) is None
    assert "accounts" not in [p.name for p in render.parts_of(report, CTX)]
    first = plan.first_plan(report, 1, alerts(3), CTX)
    assert [s.payload["file_kind"] for s in first.steps if s.kind == "file"] == [
        "pdf", "dashboard", "indicators", "affected",
    ]  # fmt: skip
    assert plan.kinds_of(report) == plan.FILE_KINDS


def test_an_accounts_table_is_posted_by_the_evidence_user_after_the_devices() -> None:
    report = with_accounts(kit.amadey(), NAME, "user-ar6-beta")
    names = [p.name for p in render.parts_of(report, CTX)]
    without = [p.name for p in render.parts_of(kit.amadey(), CTX)]
    assert names == [*without[:2], "accounts", *without[2:]]  # right after the devices
    part = render.accounts_part(report)
    assert part is not None
    assert (part.author, part.title) == (Author.EVIDENCE, "Accounts affected")
    assert part.head[0].startswith("| Account | Device | State")
    assert len(part.units) == 2
    row = part.units[0]
    assert NAME in row.replace("`", "")
    assert "possible" in row
    assert "Chrome on Windows" in row
    assert "IST" in row
    assert "a lead" in " ".join(part.intro).lower() or "lead" in " ".join(part.intro).lower()
    first = plan.first_plan(report, 1, alerts(3), CTX)
    comments = [s for s in first.steps if s.kind == "comment" and s.part == "accounts"]
    assert comments
    assert all(s.author is Author.EVIDENCE for s in comments)
    order = [s.part for s in first.steps if s.kind == "comment"]
    assert order.index("devices") < order.index("accounts") < order.index("actions")


def test_a_hostile_account_name_is_fenced_and_cannot_break_the_table() -> None:
    report = with_accounts(kit.amadey(), "a|b `x` <script>alert(1)</script>")
    part = render.accounts_part(report)
    assert part is not None
    (row,) = part.units
    name_cell = row.split(" | ")[0]
    assert name_cell.startswith("| ``")
    assert "a\N{DIVIDES}b" in name_cell  # the look-alike: a raw pipe would split the cell
    assert row.count(" | ") == 6  # seven columns: the name did not add one


def test_the_accounts_csv_is_a_fourth_file_only_when_the_report_has_accounts() -> None:
    report = with_accounts(kit.amadey(), NAME)
    assert plan.kinds_of(report) == ("pdf", "dashboard", "indicators", "affected", "accounts")
    first = plan.first_plan(report, 1, alerts(3), CTX)
    kinds = [s.payload["file_kind"] for s in first.steps if s.kind == "file"]
    assert kinds == ["pdf", "dashboard", "indicators", "affected", "accounts"]
    listing = next(s for s in first.steps if s.key == "comment:files")
    assert listing.text is not None
    assert "affected-accounts CSV" in listing.text
    upload = plan.upload_of(report, "accounts", None)
    assert upload.filename.endswith("_affected_accounts")
    assert upload.mime == "text/csv"
    assert NAME.encode() in upload.data


def posted_after(first: plan.Plan) -> plan.Posted:
    units: dict[str, frozenset[str]] = {}
    files: dict[str, str] = {}
    attached: set[str] = set()
    verdict = None
    from argus.caseteam.model import unit_hash  # noqa: F401

    for s in first.steps:
        if s.kind == "comment":
            units[s.part] = units.get(s.part, frozenset()) | frozenset(s.units)
        elif s.kind == "file":
            files[s.payload["file_kind"]] = s.payload["sha256"]
        elif s.kind == "attach":
            attached |= {a for a, _ in s.payload["alerts"]}
        if s.part == "verdict":
            verdict = (s.payload["outcome"], s.payload["confidence"])
    return plan.Posted("kid-1", 1, 1, units, files, frozenset(attached), verdict)


def test_a_posted_case_that_gains_an_account_gets_an_update_and_the_new_file() -> None:
    report = kit.amadey()
    first = plan.first_plan(report, 1, alerts(4), CTX)
    posted = posted_after(first)
    later = with_accounts(report, NAME)
    update = plan.update_plan(later, 2, alerts(4), CTX, posted, max_alerts=25)
    comment = next(s for s in update.steps if s.kind == "comment" and s.part == "accounts")
    assert comment.author is Author.EVIDENCE
    assert comment.text is not None
    assert comment.text.startswith("## Update: Accounts affected")
    files = [s.payload["file_kind"] for s in update.steps if s.kind == "file"]
    assert "accounts" in files  # the CSV is new
    assert "indicators" not in files  # and the ones that did not change are not sent again
    nothing = plan.update_plan(report, 2, alerts(4), CTX, posted, max_alerts=25)
    assert [s for s in nothing.steps if s.part == "accounts"] == []
    assert "accounts" not in [s.payload.get("file_kind") for s in nothing.steps if s.kind == "file"]
