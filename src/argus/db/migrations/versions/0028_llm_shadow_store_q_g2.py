"""The local model's shadow store: answers to live items, kept for the evaluation ladder

The runtime role may read and add rows (``argus llm shadow``), not change or delete them. The web's
role gets nothing on the table, so no page or API can read it (shadow output is never shown);
``argus doctor`` checks the web's grants table by table. That holds once the web logs in as its own
login (``web.database_role: api``).

Revision ID: 0028
Revises: 0027
Create Date: 2026-10-23 11:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0028"
down_revision: str | None = "0027"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Written out, not imported (see 0003).
COLUMNS = (
    "investigation_id, version, pack, dossier_hash, task, prompt, provider, model, usable, ok,"
    " outcome, floor, reference, detail, answer, latency_ms, lease_ms, input_tokens,"
    " output_tokens"
)


def upgrade() -> None:
    op.create_table(
        "llm_shadow",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column(
            "at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column("investigation_id", sa.UUID(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("pack", sa.Text(), nullable=False),
        sa.Column("dossier_hash", sa.Text(), nullable=False),
        sa.Column("task", sa.Text(), nullable=False),
        sa.Column("prompt", sa.Text(), nullable=False),
        sa.Column("provider", sa.Text(), nullable=False),
        sa.Column("model", sa.Text(), nullable=False),
        sa.Column("usable", sa.Boolean(), nullable=False),
        sa.Column("ok", sa.Boolean(), nullable=True),
        sa.Column("outcome", sa.Text(), nullable=True),
        sa.Column("floor", sa.Boolean(), nullable=False),
        sa.Column("reference", sa.Text(), nullable=True),
        sa.Column(
            "detail", postgresql.JSONB(astext_type=sa.Text()), server_default="{}", nullable=False
        ),
        sa.Column("answer", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("latency_ms", sa.Integer(), nullable=False),
        sa.Column("lease_ms", sa.Integer(), nullable=False),
        sa.Column("input_tokens", sa.Integer(), nullable=False),
        sa.Column("output_tokens", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "task IN ('extract', 'triage', 'summary', 'notes', 'fallback')",
            name=op.f("ck_llm_shadow_task_valid"),
        ),
        sa.CheckConstraint(
            "dossier_hash ~ '^[0-9a-f]{64}$'", name=op.f("ck_llm_shadow_hash_valid")
        ),
        sa.CheckConstraint(
            "latency_ms >= 0 AND lease_ms >= 0 AND input_tokens >= 0 AND output_tokens >= 0",
            name=op.f("ck_llm_shadow_non_negative"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(detail) = 'object'", name=op.f("ck_llm_shadow_detail_is_object")
        ),
        sa.CheckConstraint(
            "answer IS NULL OR (jsonb_typeof(answer) = 'object' AND length(answer::text) <= 20000)",
            name=op.f("ck_llm_shadow_answer_valid"),
        ),
        sa.CheckConstraint(
            "usable OR (ok IS NULL AND answer IS NULL)",
            name=op.f("ck_llm_shadow_unusable_is_empty"),
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.id"],
            name=op.f("fk_llm_shadow_investigation_id_investigations"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_llm_shadow")),
    )
    op.create_index(
        op.f("ix_llm_shadow_investigation_id_dossier_hash_task_prompt_provider_model"),
        "llm_shadow",
        ["investigation_id", "dossier_hash", "task", "prompt", "provider", "model"],
        unique=True,
    )
    op.create_index(
        op.f("ix_llm_shadow_provider_model_task_at"),
        "llm_shadow",
        ["provider", "model", "task", "at"],
        unique=False,
    )
    op.execute(f"GRANT SELECT, INSERT ({COLUMNS}) ON llm_shadow TO argus_runtime")


def downgrade() -> None:
    op.drop_index(op.f("ix_llm_shadow_provider_model_task_at"), table_name="llm_shadow")
    op.drop_index(
        op.f("ix_llm_shadow_investigation_id_dossier_hash_task_prompt_provider_model"),
        table_name="llm_shadow",
    )
    op.drop_table("llm_shadow")
