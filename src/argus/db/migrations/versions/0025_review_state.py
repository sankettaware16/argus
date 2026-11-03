"""The newest review of each investigation, kept by a trigger (Q-A1, plan §8 criterion 14)

The lists derived each investigation's state from its newest review by ranking every review
on every request: at twice the exit's size (350,000 investigations, 70,000 reviewed) that
alone took most of 300 ms. ``review_state`` holds the result instead, one row per reviewed
investigation, written only by an AFTER INSERT trigger on the append-only ``review_events``
(a SECURITY DEFINER function: ARGUS's runtime role may read the table and never write it, so
a state still comes only from a review event). The upgrade fills it from the reviews so far.

Every list also sorted all investigations for each page: each list order has an index now
(Q-A1 review F2), so a page is read in order instead.

Revision ID: 0025
Revises: 0024
Create Date: 2026-10-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0025"
down_revision: str | None = "0024"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# The web's own group role (0021, Q-A2) reads it too (argus.db.roles.API_GRANTS).
WEB_GRANTS = ("GRANT SELECT ON review_state TO argus_web",)

# A note never changes the state: the decision columns change only for a newer decision (ids
# rise with every insert, so an older one committed late never overwrites a newer one).
TRACK = """
CREATE FUNCTION argus_track_review_state() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    IF NEW.action = 'note' THEN
        INSERT INTO public.review_state AS s (investigation_id, latest_id)
        VALUES (NEW.investigation_id, NEW.id)
        ON CONFLICT (investigation_id)
        DO UPDATE SET latest_id = greatest(s.latest_id, EXCLUDED.latest_id);
    ELSE
        INSERT INTO public.review_state AS s (investigation_id, latest_id, decision_id, action,
            version, alert_count, outcome, decided_at, user_id)
        VALUES (NEW.investigation_id, NEW.id, NEW.id, NEW.action, NEW.version, NEW.alert_count,
            NEW.outcome, NEW.created_at, NEW.user_id)
        ON CONFLICT (investigation_id) DO UPDATE SET
            latest_id = greatest(s.latest_id, EXCLUDED.latest_id),
            decision_id = EXCLUDED.decision_id, action = EXCLUDED.action,
            version = EXCLUDED.version, alert_count = EXCLUDED.alert_count,
            outcome = EXCLUDED.outcome, decided_at = EXCLUDED.decided_at,
            user_id = EXCLUDED.user_id
        WHERE s.decision_id IS NULL OR s.decision_id < EXCLUDED.decision_id;
    END IF;
    RETURN NULL;
END
$$
"""
FILL = """
INSERT INTO review_state (investigation_id, latest_id, decision_id, action, version,
    alert_count, outcome, decided_at, user_id)
SELECT s.investigation_id, s.latest_id, r.id, r.action, r.version, r.alert_count, r.outcome,
    r.created_at, r.user_id
FROM (SELECT investigation_id, max(id) AS latest_id,
             max(id) FILTER (WHERE action <> 'note') AS decision_id
      FROM review_events GROUP BY investigation_id) s
LEFT JOIN review_events r ON r.id = s.decision_id
"""

# The lists' orders (argus.web.queries._ORDER), each an index; the urgent one with the
# severity's rank exactly as the query writes it.
RANK = (
    "(CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2"
    " WHEN 'low' THEN 1 ELSE 0 END) DESC"
)
ORDERS = {
    "ix_investigations_newest": ("last_event_at DESC NULLS LAST", "id"),
    "ix_investigations_oldest": ("last_event_at ASC NULLS LAST", "id"),
    "ix_investigations_urgent": (RANK, "last_event_at DESC NULLS LAST", "id"),
}


def upgrade() -> None:
    # No review may slip in between the fill and the trigger (both in this transaction).
    op.execute("LOCK TABLE review_events IN SHARE ROW EXCLUSIVE MODE")
    op.create_table(
        "review_state",
        sa.Column("investigation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("latest_id", sa.BigInteger(), nullable=False),
        sa.Column("decision_id", sa.BigInteger(), nullable=True),
        sa.Column("action", sa.Text(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=True),
        sa.Column("alert_count", sa.Integer(), nullable=True),
        sa.Column("outcome", sa.Text(), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("user_id", sa.BigInteger(), nullable=True),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.id"],
            name=op.f("fk_review_state_investigation_id_investigations"),
        ),
        sa.PrimaryKeyConstraint("investigation_id", name=op.f("pk_review_state")),
    )
    op.create_index(op.f("ix_review_state_decided_at"), "review_state", ["decided_at"])
    op.execute(FILL)
    # Each list order walks an index (review F2): no list sorts every investigation.
    for name, columns in ORDERS.items():
        op.create_index(name, "investigations", [sa.text(c) for c in columns])
    op.create_index("ix_review_state_decided", "review_state",
                    [sa.text("decided_at DESC"), "investigation_id"])  # fmt: skip
    op.create_index("ix_review_state_follow_ups", "review_state", ["investigation_id"],
                    postgresql_where=sa.text("action = 'follow_up'"))  # fmt: skip
    op.execute(TRACK)
    op.execute("REVOKE ALL ON FUNCTION argus_track_review_state() FROM PUBLIC")
    op.execute(
        "CREATE TRIGGER review_events_track_state AFTER INSERT ON review_events"
        " FOR EACH ROW EXECUTE FUNCTION argus_track_review_state()"
    )
    # The role name is written out, not imported (see 0003). Read only: the trigger writes.
    op.execute("GRANT SELECT ON review_state TO argus_runtime")
    for grant in WEB_GRANTS:
        op.execute(grant)


def downgrade() -> None:
    for name in ORDERS:
        op.drop_index(name, table_name="investigations")
    op.execute("DROP TRIGGER IF EXISTS review_events_track_state ON review_events")
    op.execute("DROP FUNCTION IF EXISTS argus_track_review_state()")
    op.drop_index(op.f("ix_review_state_decided_at"), table_name="review_state")
    op.drop_table("review_state")
