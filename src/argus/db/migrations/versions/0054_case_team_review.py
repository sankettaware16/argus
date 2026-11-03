"""The case team's rotation, comment reads and verdict statuses.

``case_team_looks`` (when the poster last looked at a case, so it rotates through candidates),
``case_team_reads`` (the Kibana case's ``updated_at`` and comment count at the last read) and
``case_team_seen`` (the primary key gains ``status``, and ``counts`` holds what the review path did;
still append-only). Downgrading is refused while a comment has two rows.

Revision ID: 0054
Revises: 0053
Create Date: 2026-10-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0054"
down_revision: str | None = "0053"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

READ_INSERT = "case_id, kibana_updated_at, comment_count, read_at"
READ_UPDATE = "kibana_updated_at, comment_count, read_at"


def upgrade() -> None:
    op.create_table(
        "case_team_looks",
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column(
            "examined_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_case_team_looks_case_id_cases")
        ),
        sa.PrimaryKeyConstraint("case_id", name=op.f("pk_case_team_looks")),
    )
    op.create_index(op.f("ix_case_team_looks_examined_at"), "case_team_looks", ["examined_at"])

    op.create_table(
        "case_team_reads",
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column("kibana_updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("comment_count", sa.Integer(), nullable=False),
        sa.Column(
            "read_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("comment_count >= 0", name=op.f("ck_case_team_reads_count_valid")),
        sa.ForeignKeyConstraint(
            ["case_id"],
            ["case_team_posts.case_id"],
            name=op.f("fk_case_team_reads_case_id_case_team_posts"),
        ),
        sa.PrimaryKeyConstraint("case_id", name=op.f("pk_case_team_reads")),
    )

    op.add_column("case_team_seen", sa.Column("counts", postgresql.JSONB(), nullable=True))
    op.drop_constraint(op.f("pk_case_team_seen"), "case_team_seen", type_="primary")
    op.create_primary_key(
        op.f("pk_case_team_seen"), "case_team_seen", ["kibana_comment_id", "text_hash", "status"]
    )

    op.execute(
        "GRANT SELECT, INSERT (case_id, examined_at), UPDATE (examined_at)"
        " ON case_team_looks TO argus_writer"
    )
    op.execute(
        f"GRANT SELECT, INSERT ({READ_INSERT}), UPDATE ({READ_UPDATE})"
        " ON case_team_reads TO argus_runtime"
    )
    op.execute("GRANT SELECT ON case_team_looks TO argus_runtime")
    op.execute("GRANT INSERT (counts) ON case_team_seen TO argus_runtime")


def downgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM case_team_seen GROUP BY kibana_comment_id, text_hash
                HAVING count(*) > 1
            ) THEN
                RAISE EXCEPTION 'a verdict comment has two rows (unmatched, then decided):'
                    ' the old key cannot hold them'
                    USING ERRCODE = 'QC422';
            END IF;
        END
        $$
        """
    )
    op.drop_constraint(op.f("pk_case_team_seen"), "case_team_seen", type_="primary")
    op.create_primary_key(
        op.f("pk_case_team_seen"), "case_team_seen", ["kibana_comment_id", "text_hash"]
    )
    op.drop_column("case_team_seen", "counts")
    op.drop_table("case_team_reads")
    op.drop_index(op.f("ix_case_team_looks_examined_at"), table_name="case_team_looks")
    op.drop_table("case_team_looks")
