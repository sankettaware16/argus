"""Outside threat intel (AR3, D-165): the answers of VirusTotal, Shodan and Censys, and the
ledger of the requests that fetched them.

* ``outside_lookups``: one row per (source, kind, indicator): the parsed, size-capped answer
  (``status`` found, or not_found when the source has no record), and when it was fetched. An
  answer is valid for ``outside.cache_window`` (7 days); an indicator is never asked twice inside
  it. Only external indicators ever get a row (campus, private and special addresses and campus
  names are refused before any request). The raw reply is never kept.
* ``outside_requests``: the ledger. One row per request made (time, source, kind, the purpose that
  asked, the outcome, the HTTP status, the size of the answer, and until when a 429 stops the
  source). Never the key and never the indicator. The limits (per second, minute, day, month) are
  counted from it, so a restart or a second process cannot exceed them.

``argus_runtime`` reads both, inserts and updates the listed columns of both, and deletes expired
answers (the only table besides LangGraph's it may delete from: it is a cache); the web's role
reads the answers (the investigation page says what outside intel found) and never the ledger.

The role names are written out, not imported (see 0003).

Revision ID: 0048
Revises: 0047
Create Date: 2026-10-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0048"
down_revision: str | None = "0047"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SOURCES = ("virustotal", "shodan", "censys")
KINDS = ("ip", "domain", "url", "hash")
LOOKUP_INSERT = "source, kind, indicator, status, answer, answer_bytes, fetched_at"
LOOKUP_UPDATE = "status, answer, answer_bytes, fetched_at"
REQUEST_INSERT = "at, source, kind, purpose, outcome"
REQUEST_UPDATE = "outcome, http_status, answer_bytes, stopped_until"
WEB_GRANTS = ("GRANT SELECT ON outside_lookups TO argus_web",)


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


def upgrade() -> None:
    op.create_table(
        "outside_lookups",
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("indicator", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column(
            "answer",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
        sa.Column("answer_bytes", sa.Integer(), server_default="0", nullable=False),
        sa.Column(
            "fetched_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(_in("source", SOURCES), name=op.f("ck_outside_lookups_source_valid")),
        sa.CheckConstraint(_in("kind", KINDS), name=op.f("ck_outside_lookups_kind_valid")),
        sa.CheckConstraint(
            "status IN ('found', 'not_found')", name=op.f("ck_outside_lookups_status_valid")
        ),
        sa.CheckConstraint(
            "char_length(indicator) BETWEEN 1 AND 2048",
            name=op.f("ck_outside_lookups_indicator_length"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(answer) = 'object'", name=op.f("ck_outside_lookups_answer_is_object")
        ),
        sa.CheckConstraint("answer_bytes >= 0", name=op.f("ck_outside_lookups_bytes_valid")),
        sa.PrimaryKeyConstraint("source", "kind", "indicator", name=op.f("pk_outside_lookups")),
    )
    op.create_index(op.f("ix_outside_lookups_fetched_at"), "outside_lookups", ["fetched_at"])
    op.create_index(op.f("ix_outside_lookups_kind_indicator"), "outside_lookups",
                    ["kind", "indicator"])  # fmt: skip
    op.create_table(
        "outside_requests",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column(
            "at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("purpose", sa.Text(), nullable=False),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("answer_bytes", sa.Integer(), nullable=True),
        sa.Column("stopped_until", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(_in("source", SOURCES), name=op.f("ck_outside_requests_source_valid")),
        sa.CheckConstraint(_in("kind", KINDS), name=op.f("ck_outside_requests_kind_valid")),
        sa.CheckConstraint(
            "purpose IN ('agent', 'prefetch')", name=op.f("ck_outside_requests_purpose_valid")
        ),
        sa.CheckConstraint(
            "outcome IN ('reserved', 'ok', 'not_found', 'limited', 'error')",
            name=op.f("ck_outside_requests_outcome_valid"),
        ),
        sa.CheckConstraint(
            "answer_bytes IS NULL OR answer_bytes >= 0",
            name=op.f("ck_outside_requests_bytes_valid"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_outside_requests")),
    )
    op.create_index(op.f("ix_outside_requests_source_at"), "outside_requests", ["source", "at"])
    op.execute(
        f"GRANT SELECT, DELETE, INSERT ({LOOKUP_INSERT}), UPDATE ({LOOKUP_UPDATE})"
        " ON outside_lookups TO argus_runtime"
    )
    op.execute(
        f"GRANT SELECT, INSERT ({REQUEST_INSERT}), UPDATE ({REQUEST_UPDATE})"
        " ON outside_requests TO argus_runtime"
    )
    for grant in WEB_GRANTS:
        op.execute(grant)


def downgrade() -> None:
    op.drop_table("outside_requests")
    op.drop_table("outside_lookups")
