"""Evidence requests: an opaque id (E1, E2 ...) per request, and the task key on the ledger

The web's group role (``argus_web``, 0021) may read what report@2 shows: the evidence rows, their
ids and the ledger rows that answered them (``WEB_GRANTS``, in ``argus.db.roles.API_GRANTS``).

Revision ID: 0023
Revises: 0022
Create Date: 2026-10-22 21:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from argus.db.siem_names import RENAME

revision: str = "0023"
down_revision: str | None = "0022"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# What the web reads for report@2 (written out, not imported: see 0003); 0021 made the role.
WEB_GRANTS = ("GRANT SELECT ON evidence, evidence_requests, siem_requests TO argus_web",)

BACKFILL = """
INSERT INTO evidence_requests (investigation_id, eid, task_key, template, template_version,
                               origin, reason, first_version, created_at)
SELECT k.investigation_id,
       row_number() OVER (PARTITION BY k.investigation_id
                          ORDER BY k.first_version, k.first_at, k.task_key),
       k.task_key, k.template, k.template_version,
       CASE WHEN p.task_key IS NULL THEN 'agent' ELSE 'pack' END,
       NULL, k.first_version, k.first_at
FROM (SELECT investigation_id, task_key, min(template) AS template,
             min(template_version) AS template_version, min(version) AS first_version,
             min(collected_at) AS first_at
      FROM evidence GROUP BY investigation_id, task_key) k
LEFT JOIN (SELECT DISTINCT d.investigation_id, e.value ->> 'task_key' AS task_key
           FROM dossiers d CROSS JOIN LATERAL jsonb_array_elements(
             CASE WHEN jsonb_typeof(d.body -> 'evidence') = 'array'
                  THEN d.body -> 'evidence' ELSE '[]'::jsonb END) e) p
  ON p.investigation_id = k.investigation_id AND p.task_key = k.task_key
"""


def upgrade() -> None:
    op.execute(RENAME)  # an old database's tables first (argus.db.siem_names)
    op.create_table(
        "evidence_requests",
        sa.Column("investigation_id", sa.UUID(), nullable=False),
        sa.Column("eid", sa.Integer(), nullable=False),
        sa.Column("task_key", sa.Text(), nullable=False),
        sa.Column("template", sa.Text(), nullable=False),
        sa.Column("template_version", sa.Integer(), nullable=False),
        sa.Column("origin", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("first_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("eid >= 1", name=op.f("ck_evidence_requests_eid_valid")),
        sa.CheckConstraint(
            "first_version >= 0", name=op.f("ck_evidence_requests_first_version_valid")
        ),
        sa.CheckConstraint(
            "origin IN ('pack', 'agent', 'wave', 'person', 'watch')",
            name=op.f("ck_evidence_requests_origin_valid"),
        ),
        sa.CheckConstraint(
            "reason IS NULL OR length(reason) <= 200",
            name=op.f("ck_evidence_requests_reason_length"),
        ),
        sa.CheckConstraint(
            "task_key ~ '^[0-9a-f]{64}$'", name=op.f("ck_evidence_requests_task_key_valid")
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.id"],
            name=op.f("fk_evidence_requests_investigation_id_investigations"),
        ),
        sa.PrimaryKeyConstraint("investigation_id", "eid", name=op.f("pk_evidence_requests")),
    )
    op.create_index(
        op.f("ix_evidence_requests_investigation_id_task_key"),
        "evidence_requests",
        ["investigation_id", "task_key"],
        unique=True,
    )
    # Every evidence row stored so far gets its id, numbered per investigation in the order
    # the requests were first made. Who asked is not stored with evidence: a task key some
    # dossier lists was the dossier's own check, any other the investigator's.
    op.execute(BACKFILL)
    op.create_foreign_key(
        op.f("fk_evidence_investigation_id_task_key_evidence_requests"),
        "evidence",
        "evidence_requests",
        ["investigation_id", "task_key"],
        ["investigation_id", "task_key"],
    )
    op.add_column("siem_requests", sa.Column("task_key", sa.Text(), nullable=True))
    op.create_check_constraint(
        op.f("ck_siem_requests_task_key_valid"),
        "siem_requests",
        "task_key IS NULL OR task_key ~ '^[0-9a-f]{64}$'",
    )
    op.create_index(op.f("ix_siem_requests_task_key"), "siem_requests", ["task_key"], unique=False)
    # The role name is written out, not imported (see 0003). An E-id is never changed or
    # removed by ARGUS at run time: no UPDATE, no DELETE.
    op.execute(
        "GRANT SELECT, INSERT (investigation_id, eid, task_key, template, template_version,"
        " origin, reason, first_version, created_at) ON evidence_requests TO argus_runtime"
    )
    op.execute("GRANT INSERT (task_key) ON siem_requests TO argus_runtime")
    for grant in WEB_GRANTS:
        op.execute(grant)


def downgrade() -> None:
    op.execute("REVOKE SELECT ON evidence, siem_requests FROM argus_web")
    op.drop_index(op.f("ix_siem_requests_task_key"), table_name="siem_requests")
    op.drop_constraint(op.f("ck_siem_requests_task_key_valid"), "siem_requests", type_="check")
    op.drop_column("siem_requests", "task_key")
    op.drop_constraint(
        op.f("fk_evidence_investigation_id_task_key_evidence_requests"),
        "evidence",
        type_="foreignkey",
    )
    op.drop_index(
        op.f("ix_evidence_requests_investigation_id_task_key"), table_name="evidence_requests"
    )
    op.drop_table("evidence_requests")
