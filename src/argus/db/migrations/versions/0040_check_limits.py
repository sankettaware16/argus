"""The limits of "Check more" are the table's own.

The web's login no longer inserts ``kind`` or ``source`` (they default to what a person's check is),
``created_at`` is the server's clock, and a trigger on the insert, under one advisory lock so
requests cannot pass one count together, refuses the 6th open check of a person, the 101st open
check and the 31st check of one person in a UTC day (SQLSTATE ``AR001``;
``argus.investigation.checks`` turns it into a refusal). The numbers are written here and in
``checks.py``; a test keeps them equal.

Revision ID: 0040
Revises: 0039
Create Date: 2026-10-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0040"
down_revision: str | None = "0039"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# What was taken from the web's role (the tests subtract it from what 0039 granted).
WEB_TAKEN_BACK = ("REVOKE INSERT (kind, source) ON investigation_checks FROM argus_web",)

LIMITS = """
CREATE FUNCTION argus_check_limits() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
    mine integer;
    everyones integer;
    today integer;
BEGIN
    -- one check is counted at a time: two requests at once cannot both pass the same count
    PERFORM pg_advisory_xact_lock(hashtext('argus.investigation_checks.limits'));
    SELECT count(*) FILTER (WHERE requested_by = NEW.requested_by), count(*)
      INTO mine, everyones FROM public.investigation_checks
     WHERE kind = 'check' AND status IN ('queued', 'running');
    IF mine >= 5 THEN
        RAISE EXCEPTION 'you have % checks waiting already: wait for them to finish', mine
            USING ERRCODE = 'AR001';
    END IF;
    IF everyones >= 100 THEN
        RAISE EXCEPTION 'too many checks are waiting; try again later' USING ERRCODE = 'AR001';
    END IF;
    SELECT count(*) INTO today FROM public.investigation_checks
     WHERE kind = 'check' AND requested_by = NEW.requested_by
       AND created_at >= date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
    IF today >= 30 THEN
        RAISE EXCEPTION 'you have asked for % checks today: that is the limit for a day', today
            USING ERRCODE = 'AR001';
    END IF;
    RETURN NEW;
END
$$
"""


def upgrade() -> None:
    op.add_column(
        "investigation_checks",
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_investigation_checks_by_day",
        "investigation_checks",
        ["requested_by", "created_at"],
        postgresql_where=sa.text("kind = 'check'"),
    )
    op.alter_column("investigation_checks", "kind", server_default="check")
    op.alter_column("investigation_checks", "source", server_default="person")
    for revoke in WEB_TAKEN_BACK:
        op.execute(revoke)
    op.execute(LIMITS)
    op.execute("REVOKE ALL ON FUNCTION argus_check_limits() FROM PUBLIC")
    op.execute(
        "CREATE TRIGGER investigation_checks_limits BEFORE INSERT ON investigation_checks"
        " FOR EACH ROW WHEN (NEW.kind = 'check') EXECUTE FUNCTION argus_check_limits()"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS investigation_checks_limits ON investigation_checks")
    op.execute("DROP FUNCTION IF EXISTS argus_check_limits()")
    op.execute("GRANT INSERT (kind, source) ON investigation_checks TO argus_web")
    op.alter_column("investigation_checks", "source", server_default=None)
    op.alter_column("investigation_checks", "kind", server_default=None)
    op.drop_index("ix_investigation_checks_by_day", table_name="investigation_checks")
    op.drop_column("investigation_checks", "created_at")
