"""Jobs started in the app that argus-admin runs (D-327)

``admin_jobs``: ``inspect_tls`` (the certificates an address presents) and ``setup`` (``argus
init`` with the first-time setup's answers), with what each found. ``admin_job_secrets``: a key a
job needs, sealed with argus-admin's public key; the web inserts it and never reads it, and
argus-admin deletes it once the job has run.

Revision ID: 0110
Revises: 0109
Create Date: 2026-11-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0110"
down_revision: str | None = "0109"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

WEB_GRANTS = (
    "GRANT SELECT, INSERT (kind, params, created_by, created_at, stepped_up_at) ON admin_jobs"
    " TO argus_web",
    "GRANT INSERT (job_id, name, sealed) ON admin_job_secrets TO argus_web",
)


def upgrade() -> None:
    op.create_table(
        "admin_jobs",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column(
            "params", postgresql.JSONB(astext_type=sa.Text()), server_default="{}", nullable=False
        ),
        sa.Column("created_by", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("stepped_up_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("state", sa.Text(), server_default="pending", nullable=False),
        sa.Column("result", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "kind IN ('inspect_tls', 'setup')", name=op.f("ck_admin_jobs_kind_valid")
        ),
        sa.CheckConstraint(
            "state IN ('pending', 'running', 'done', 'failed')",
            name=op.f("ck_admin_jobs_state_valid"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(params) = 'object'", name=op.f("ck_admin_jobs_params_is_object")
        ),
        sa.CheckConstraint(
            "result IS NULL OR jsonb_typeof(result) = 'object'",
            name=op.f("ck_admin_jobs_result_is_object"),
        ),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["users.id"],
            ondelete="RESTRICT",
            name=op.f("fk_admin_jobs_created_by_users"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_admin_jobs")),
    )
    op.create_index(op.f("ix_admin_jobs_state_id"), "admin_jobs", ["state", "id"])
    op.create_table(
        "admin_job_secrets",
        sa.Column("job_id", sa.BigInteger(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("sealed", sa.LargeBinary(), nullable=False),
        sa.CheckConstraint(
            "name ~ '^[a-z_]+(\\.[a-z0-9_]+)+$'", name=op.f("ck_admin_job_secrets_name_valid")
        ),
        sa.CheckConstraint(
            "octet_length(sealed) <= 20000", name=op.f("ck_admin_job_secrets_sealed_length")
        ),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["admin_jobs.id"],
            ondelete="CASCADE",
            name=op.f("fk_admin_job_secrets_job_id_admin_jobs"),
        ),
        sa.PrimaryKeyConstraint("job_id", "name", name=op.f("pk_admin_job_secrets")),
    )
    op.execute("GRANT SELECT, UPDATE (state, result, finished_at) ON admin_jobs TO argus_runtime")
    op.execute("GRANT SELECT, DELETE ON admin_job_secrets TO argus_runtime")
    for grant in WEB_GRANTS:
        op.execute(grant)


def downgrade() -> None:
    op.drop_table("admin_job_secrets")
    op.drop_index(op.f("ix_admin_jobs_state_id"), table_name="admin_jobs")
    op.drop_table("admin_jobs")
