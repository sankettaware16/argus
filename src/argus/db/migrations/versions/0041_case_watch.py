"""The still-active watch and case membership (Q-C2, plan §5 and §7.1).

* ``case_watch_checks``: one answer of the daily watch for a case, a UTC day and a source
  (ARGUS's own alerts, or the proxy logs through ``proxy.contact`` / ``proxy.pair``): active,
  quiet, unverified, or not checked with the reason. A row is decided once: the trigger
  ``argus_watch_check_guard`` lets only a ``not_checked`` row be replaced (by the next run's
  answer) and holds the row's identity. ``requests`` and ``asked_on`` count SIEM requests a
  case's checks sent on a day (a row holds at most 20, the most a case may ask in a day; the
  sum for a case and day is the runner's: ``argus.cases.watch.cap_for``).
* ``case_suggestions``: investigations that may belong to a case but are not joined: their
  match is through a shared address or name, or ties between cases (a person decides).
  Removed with the investigation by the retention purge (``ON DELETE CASCADE``).
* ``cases.cause`` gains ``watch``: the suspected case ARGUS opens when activity follows a
  closure (plan §7.1: a linked suspected case, never a silent reopen).

``argus_runtime`` reads both tables and writes the columns the watch writes; the web's role gets
nothing (nothing in the web shows them yet: Q-B3).

Revision ID: 0041
Revises: 0040
Create Date: 2026-10-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0041"
down_revision: str | None = "0040"  # Q-F3's 0039 and 0040 come first
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

CHECK_INSERT = (
    "case_id, day, source, subject, part, outcome, reason, window_start, window_end, asked_at,"
    " asked_on, requests, attempts, detail"
)
CHECK_UPDATE = (
    "outcome, reason, window_start, window_end, asked_at, asked_on, requests, attempts,"
    " detail, checked_at"
)
SUGGESTION_INSERT = "investigation_id, case_id, link, link_value, kind, why"
SUGGESTION_UPDATE = "dismissed_at, dismissed_by"
CAUSES = ("verdict", "proposal", "person")
SOURCES = ("alerts", "proxy.contact", "proxy.pair")
OUTCOMES = ("active", "quiet", "unverified", "not_checked")
KINDS = ("shared", "tie", "also")

GUARD = """
CREATE FUNCTION argus_watch_check_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NEW.id <> OLD.id OR NEW.case_id <> OLD.case_id OR NEW.day <> OLD.day
       OR NEW.source <> OLD.source OR NEW.subject <> OLD.subject OR NEW.part <> OLD.part THEN
        RAISE EXCEPTION 'watch check %: its identity cannot change', OLD.id
            USING ERRCODE = 'QC422';
    END IF;
    IF OLD.outcome <> 'not_checked' THEN
        RAISE EXCEPTION 'watch check %: a decided answer is not replaced', OLD.id
            USING ERRCODE = 'QC422';
    END IF;
    IF NEW.attempts <> OLD.attempts + 1 THEN
        RAISE EXCEPTION 'watch check %: each new try is counted once', OLD.id
            USING ERRCODE = 'QC422';
    END IF;
    RETURN NEW;
END
$$;
"""


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


def upgrade() -> None:
    op.drop_constraint(op.f("ck_cases_cause_valid"), "cases", type_="check")
    op.create_check_constraint(
        op.f("ck_cases_cause_valid"), "cases", _in("cause", (*CAUSES, "watch"))
    )
    op.create_table(
        "case_watch_checks",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("subject", sa.Text(), server_default="", nullable=False),
        sa.Column("part", sa.SmallInteger(), server_default="0", nullable=False),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("asked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("asked_on", sa.Date(), nullable=True),
        sa.Column("requests", sa.SmallInteger(), server_default="0", nullable=False),
        sa.Column("attempts", sa.SmallInteger(), server_default="1", nullable=False),
        sa.Column(
            "detail",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "checked_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(_in("source", SOURCES), name=op.f("ck_case_watch_checks_source_valid")),
        sa.CheckConstraint(
            _in("outcome", OUTCOMES), name=op.f("ck_case_watch_checks_outcome_valid")
        ),
        sa.CheckConstraint(
            "window_start < window_end", name=op.f("ck_case_watch_checks_window_valid")
        ),
        sa.CheckConstraint(
            "reason IS NULL OR length(reason) <= 300",
            name=op.f("ck_case_watch_checks_reason_length"),
        ),
        sa.CheckConstraint(
            "outcome IN ('active', 'quiet') OR reason IS NOT NULL",
            name=op.f("ck_case_watch_checks_reason_given"),
        ),
        sa.CheckConstraint(
            "requests BETWEEN 0 AND 20", name=op.f("ck_case_watch_checks_requests_valid")
        ),
        sa.CheckConstraint(
            "(requests = 0) = (asked_on IS NULL)",
            name=op.f("ck_case_watch_checks_requests_have_a_day"),
        ),
        sa.CheckConstraint(
            "(source = 'alerts') = (subject = '')",
            name=op.f("ck_case_watch_checks_alerts_have_no_subject"),
        ),
        sa.CheckConstraint(
            "source <> 'alerts' OR requests = 0",
            name=op.f("ck_case_watch_checks_alerts_are_local"),
        ),
        sa.CheckConstraint(
            "attempts BETWEEN 1 AND 10000", name=op.f("ck_case_watch_checks_attempts_valid")
        ),
        sa.CheckConstraint(
            "jsonb_typeof(detail) = 'object'",
            name=op.f("ck_case_watch_checks_detail_is_object"),
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_case_watch_checks_case_id_cases")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_case_watch_checks")),
        sa.UniqueConstraint(
            "case_id",
            "day",
            "source",
            "subject",
            "part",
            name=op.f("uq_case_watch_checks_case_id_day_source_subject_part"),
        ),
    )
    op.create_index(
        op.f("ix_case_watch_checks_case_id_day"), "case_watch_checks", ["case_id", "day"]
    )
    op.create_index(
        op.f("ix_case_watch_checks_asked_on_case_id"),
        "case_watch_checks",
        ["asked_on", "case_id"],
    )
    op.execute(GUARD)
    op.execute(
        "CREATE TRIGGER case_watch_checks_decided_once BEFORE UPDATE ON case_watch_checks"
        " FOR EACH ROW EXECUTE FUNCTION argus_watch_check_guard()"
    )
    op.execute("ALTER TABLE case_watch_checks ENABLE ALWAYS TRIGGER case_watch_checks_decided_once")
    op.create_table(
        "case_suggestions",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("investigation_id", sa.UUID(), nullable=False),
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column("link", sa.Text(), nullable=False),
        sa.Column("link_value", sa.Text(), nullable=True),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("why", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("dismissed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("dismissed_by", sa.BigInteger(), nullable=True),
        sa.CheckConstraint(
            "link IN ('actor', 'c2', 'indicator')", name=op.f("ck_case_suggestions_link_valid")
        ),
        sa.CheckConstraint(_in("kind", KINDS), name=op.f("ck_case_suggestions_kind_valid")),
        sa.CheckConstraint(
            "link_value IS NULL OR length(link_value) <= 512",
            name=op.f("ck_case_suggestions_value_length"),
        ),
        sa.CheckConstraint(
            "length(why) BETWEEN 1 AND 300", name=op.f("ck_case_suggestions_why_length")
        ),
        sa.CheckConstraint(
            "(dismissed_at IS NULL) = (dismissed_by IS NULL)",
            name=op.f("ck_case_suggestions_dismissal_complete"),
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.id"],
            name=op.f("fk_case_suggestions_investigation_id_investigations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_case_suggestions_case_id_cases")
        ),
        sa.ForeignKeyConstraint(
            ["dismissed_by"], ["users.id"], name=op.f("fk_case_suggestions_dismissed_by_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_case_suggestions")),
        sa.UniqueConstraint(
            "investigation_id",
            "case_id",
            name=op.f("uq_case_suggestions_investigation_id_case_id"),
        ),
    )
    op.create_index(op.f("ix_case_suggestions_case_id"), "case_suggestions", ["case_id"])
    op.execute(
        f"GRANT SELECT, INSERT ({CHECK_INSERT}), UPDATE ({CHECK_UPDATE})"
        " ON case_watch_checks TO argus_runtime"
    )
    op.execute(
        f"GRANT SELECT, INSERT ({SUGGESTION_INSERT}), UPDATE ({SUGGESTION_UPDATE})"
        " ON case_suggestions TO argus_runtime"
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_case_suggestions_case_id"), table_name="case_suggestions")
    op.drop_table("case_suggestions")
    op.execute("DROP TRIGGER case_watch_checks_decided_once ON case_watch_checks")
    op.drop_index(op.f("ix_case_watch_checks_asked_on_case_id"), table_name="case_watch_checks")
    op.drop_index(op.f("ix_case_watch_checks_case_id_day"), table_name="case_watch_checks")
    op.drop_table("case_watch_checks")
    op.execute("DROP FUNCTION argus_watch_check_guard()")
    op.drop_constraint(op.f("ck_cases_cause_valid"), "cases", type_="check")
    op.create_check_constraint(op.f("ck_cases_cause_valid"), "cases", _in("cause", CAUSES))
