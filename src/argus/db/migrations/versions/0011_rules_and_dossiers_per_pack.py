"""The time of a rule's definition (R9 review, D-059); dossiers per pack version (R10, D-058)

A dossier is keyed by (investigation, version, pack): a new pack version adds a dossier
instead of conflicting with the old one, and reviews (keyed by version) are not disturbed.

Revision ID: 0011
Revises: 0010
Create Date: 2026-10-13
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("rules", sa.Column("definition_at", sa.DateTime(timezone=True), nullable=True))
    op.execute("UPDATE rules SET definition_at = last_alert_at")
    op.add_column("signals", sa.Column("pack", sa.Text(), nullable=True))
    op.execute(
        "UPDATE signals s SET pack = d.pack FROM dossiers d"
        " WHERE d.investigation_id = s.investigation_id AND d.version = s.version"
    )
    op.alter_column("signals", "pack", nullable=False)
    op.drop_constraint(
        op.f("fk_signals_investigation_id_version_dossiers"), "signals", type_="foreignkey"
    )
    op.drop_constraint(op.f("pk_signals"), "signals", type_="primary")
    op.drop_constraint(op.f("pk_dossiers"), "dossiers", type_="primary")
    op.create_primary_key(op.f("pk_dossiers"), "dossiers", ["investigation_id", "version", "pack"])
    op.create_primary_key(
        op.f("pk_signals"), "signals", ["investigation_id", "version", "pack", "name"]
    )
    op.create_foreign_key(
        op.f("fk_signals_investigation_id_version_pack_dossiers"),
        "signals",
        "dossiers",
        ["investigation_id", "version", "pack"],
        ["investigation_id", "version", "pack"],
    )
    # The role name is written out, not imported (see 0003).
    op.execute("GRANT INSERT (definition_at), UPDATE (definition_at) ON rules TO argus_runtime")
    op.execute("GRANT INSERT (pack) ON signals TO argus_runtime")


def downgrade() -> None:
    # keep the newest dossier of each investigation version: the old key allows one
    op.execute(
        "DELETE FROM signals s USING dossiers d WHERE d.investigation_id = s.investigation_id"
        " AND d.version = s.version AND d.pack = s.pack AND EXISTS (SELECT 1 FROM dossiers n"
        " WHERE n.investigation_id = d.investigation_id AND n.version = d.version"
        " AND n.created_at > d.created_at)"
    )
    op.execute(
        "DELETE FROM dossiers d WHERE EXISTS (SELECT 1 FROM dossiers n"
        " WHERE n.investigation_id = d.investigation_id AND n.version = d.version"
        " AND n.created_at > d.created_at)"
    )
    op.drop_constraint(
        op.f("fk_signals_investigation_id_version_pack_dossiers"), "signals", type_="foreignkey"
    )
    op.drop_constraint(op.f("pk_signals"), "signals", type_="primary")
    op.drop_constraint(op.f("pk_dossiers"), "dossiers", type_="primary")
    op.create_primary_key(op.f("pk_dossiers"), "dossiers", ["investigation_id", "version"])
    op.create_primary_key(op.f("pk_signals"), "signals", ["investigation_id", "version", "name"])
    op.create_foreign_key(
        op.f("fk_signals_investigation_id_version_dossiers"),
        "signals",
        "dossiers",
        ["investigation_id", "version"],
        ["investigation_id", "version"],
    )
    op.drop_column("signals", "pack")
    op.drop_column("rules", "definition_at")
