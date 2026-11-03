"""Who was behind an address: SSO sign-ins per internal address and UTC day

``signin_sightings``: one account's sign-ins from one address on one day (first and last event,
counts, hours, commonest browsers); the usernames are personal data, shown only to people with
``see_logs`` and never given to a model. ``signin_lookups``: that ARGUS asked about an address on a
day, and whether the answer was whole, so "looked, none seen", "not looked yet" and "incomplete"
differ. Neither is derived from grouping; the runtime prunes by ``signins.keep_days``.

Revision ID: 0056
Revises: 0055
Create Date: 2026-10-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0056"
down_revision: str | None = "0055"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

REASONS = ("partial", "bad_answer", "logs_gone", "failed")
SIGHTING_INSERT = (
    "address, day, user_name, first_at, last_at, events, successes, failures, hours, user_agents"
)
LOOKUP_INSERT = "address, day, looked_at, complete, accounts, more_accounts, reason"
LOOKUP_UPDATE = "looked_at, complete, accounts, more_accounts, reason"
# what the doctor and the tests compare with ``roles.API_GRANTS``
WEB_GRANTS = ("GRANT SELECT ON signin_sightings, signin_lookups TO argus_web",)


def upgrade() -> None:
    op.create_table(
        "signin_sightings",
        sa.Column("address", postgresql.INET(), nullable=False),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("user_name", sa.Text(), nullable=False),
        sa.Column("first_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("events", sa.Integer(), nullable=False),
        sa.Column("successes", sa.Integer(), nullable=False),
        sa.Column("failures", sa.Integer(), nullable=False),
        sa.Column("hours", postgresql.ARRAY(sa.SmallInteger()), nullable=False),
        sa.Column(
            "user_agents",
            postgresql.JSONB(),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "written_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "char_length(user_name) BETWEEN 1 AND 256",
            name=op.f("ck_signin_sightings_user_name_length"),
        ),
        sa.CheckConstraint("first_at <= last_at", name=op.f("ck_signin_sightings_span_valid")),
        sa.CheckConstraint(
            "events >= 1 AND successes >= 0 AND failures >= 0 AND successes + failures <= events",
            name=op.f("ck_signin_sightings_counts_valid"),
        ),
        sa.CheckConstraint(
            "cardinality(hours) BETWEEN 1 AND 24"
            " AND hours <@ ARRAY[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23]"
            "::smallint[]",
            name=op.f("ck_signin_sightings_hours_valid"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(user_agents) = 'array' AND jsonb_array_length(user_agents) <= 3",
            name=op.f("ck_signin_sightings_agents_valid"),
        ),
        sa.PrimaryKeyConstraint("address", "day", "user_name", name=op.f("pk_signin_sightings")),
    )
    op.create_index(op.f("ix_signin_sightings_day"), "signin_sightings", ["day"])
    op.create_table(
        "signin_lookups",
        sa.Column("address", postgresql.INET(), nullable=False),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("looked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("complete", sa.Boolean(), nullable=False),
        sa.Column("accounts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("more_accounts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "accounts >= 0 AND more_accounts >= 0 AND more_accounts <= accounts",
            name=op.f("ck_signin_lookups_counts_valid"),
        ),
        sa.CheckConstraint(
            "(complete AND reason IS NULL)"
            " OR (NOT complete AND reason IS NOT NULL AND reason IN ("
            + ", ".join(f"'{r}'" for r in REASONS)
            + ")"
            " AND accounts = 0 AND more_accounts = 0)",
            name=op.f("ck_signin_lookups_reason_valid"),
        ),
        sa.PrimaryKeyConstraint("address", "day", name=op.f("pk_signin_lookups")),
    )
    op.create_index(op.f("ix_signin_lookups_day"), "signin_lookups", ["day"])
    op.execute(
        f"GRANT SELECT, DELETE, INSERT ({SIGHTING_INSERT}) ON signin_sightings TO argus_runtime"
    )
    op.execute(
        f"GRANT SELECT, DELETE, INSERT ({LOOKUP_INSERT}), UPDATE ({LOOKUP_UPDATE})"
        " ON signin_lookups TO argus_runtime"
    )
    for grant in WEB_GRANTS:
        op.execute(grant)


def downgrade() -> None:
    op.drop_index(op.f("ix_signin_lookups_day"), table_name="signin_lookups")
    op.drop_table("signin_lookups")
    op.drop_index(op.f("ix_signin_sightings_day"), table_name="signin_sightings")
    op.drop_table("signin_sightings")
