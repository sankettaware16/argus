"""The owner-notified review fixes: durable changes, withdrawn notices, new destinations

``case_known_matches.changed_version`` makes a change durable: the row stays ``changed`` until a
person reviews a version at or after it. ``case_events.kind`` gains ``notice_withdrawn`` and
``case_known_keys.kind`` gains ``new_destination`` (counted on the case, not raised). Downgrading is
refused while a case event is a withdrawn notice.

Revision ID: 0051
Revises: 0050
Create Date: 2026-10-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0051"
down_revision: str | None = "0050"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OLD_EVENT_KINDS = (
    "suspected", "opened", "confirmed", "dismissed", "taken", "assigned", "released",
    "contained", "new_activity", "activity_after_closure", "linked", "published",
    "closure_requested", "merge_requested", "closed", "merged_into", "merged_in", "reopened",
    "notified", "blocked", "address_moved",
)  # fmt: skip
NEW_EVENT_KIND = "notice_withdrawn"
OLD_KEY_KINDS = ("seed", "flag", "destination", "family", "service", "bytes")
NEW_KEY_KIND = "new_destination"
MATCH_INSERT = "investigation_id, case_id, version, outcome, why, changed_version"
MATCH_UPDATE = "case_id, version, outcome, why, changed_version, decided_at"


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


def upgrade() -> None:
    op.add_column("case_known_matches", sa.Column("changed_version", sa.Integer(), nullable=True))
    op.execute("UPDATE case_known_matches SET changed_version = version WHERE outcome = 'changed'")
    op.create_check_constraint(
        op.f("ck_case_known_matches_changed_version_valid"),
        "case_known_matches",
        "(outcome = 'changed') = (changed_version IS NOT NULL)"
        " AND (changed_version IS NULL OR changed_version >= 0)",
    )
    op.drop_constraint(op.f("ck_case_events_kind_valid"), "case_events", type_="check")
    op.create_check_constraint(
        op.f("ck_case_events_kind_valid"),
        "case_events",
        _in("kind", (*OLD_EVENT_KINDS, NEW_EVENT_KIND)),
    )
    op.drop_constraint(op.f("ck_case_known_keys_kind_valid"), "case_known_keys", type_="check")
    op.create_check_constraint(
        op.f("ck_case_known_keys_kind_valid"),
        "case_known_keys",
        _in("kind", (*OLD_KEY_KINDS, NEW_KEY_KIND)),
    )
    op.execute(
        f"GRANT SELECT, INSERT ({MATCH_INSERT}), UPDATE ({MATCH_UPDATE})"
        " ON case_known_matches TO argus_runtime"
    )


def downgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM case_events WHERE kind = 'notice_withdrawn') THEN
                RAISE EXCEPTION 'a notice was withdrawn: the case events are append-only'
                    USING ERRCODE = 'QC422';
            END IF;
        END
        $$
        """
    )
    op.execute("DELETE FROM case_known_keys WHERE kind = 'new_destination'")
    op.drop_constraint(op.f("ck_case_known_keys_kind_valid"), "case_known_keys", type_="check")
    op.create_check_constraint(
        op.f("ck_case_known_keys_kind_valid"), "case_known_keys", _in("kind", OLD_KEY_KINDS)
    )
    op.drop_constraint(op.f("ck_case_events_kind_valid"), "case_events", type_="check")
    op.create_check_constraint(
        op.f("ck_case_events_kind_valid"), "case_events", _in("kind", OLD_EVENT_KINDS)
    )
    op.drop_constraint(
        op.f("ck_case_known_matches_changed_version_valid"), "case_known_matches", type_="check"
    )
    op.drop_column("case_known_matches", "changed_version")
