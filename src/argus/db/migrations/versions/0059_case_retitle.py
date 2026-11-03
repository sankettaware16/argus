"""A case can be retitled (D-230): the case event of a new title.

Case titles were fixed words ("Contact with a threat-listed address from a campus host"); they now
name the incident (:mod:`argus.cases.naming`), and ARGUS refreshes the titles it wrote when a
case's facts change, while a person's title is theirs. Each change is a case event.

* ``case_events.kind`` gains ``retitled``: the event of a new title, with the old and the new title
  and who in its details. It keeps the state (the case guard checks versions and edges, and the
  kind's own CHECK allows a same-state event that is neither a creation, a closure nor a
  reopening). No table is added, and the grants stay: ``argus_runtime`` could update
  ``cases.title`` since 0026.

Downgrading is refused while a case event is a ``retitled``: the case events are append-only.

Revision ID: 0059
Revises: 0058
Create Date: 2026-10-30
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0059"
down_revision: str | None = "0058"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OLD_EVENT_KINDS = (
    "suspected", "opened", "confirmed", "dismissed", "taken", "assigned", "released",
    "contained", "new_activity", "activity_after_closure", "linked", "published",
    "closure_requested", "merge_requested", "closed", "merged_into", "merged_in", "reopened",
    "notified", "blocked", "address_moved", "notice_withdrawn", "unlinked",
)  # fmt: skip
NEW_EVENT_KIND = "retitled"


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


def upgrade() -> None:
    op.drop_constraint(op.f("ck_case_events_kind_valid"), "case_events", type_="check")
    op.create_check_constraint(
        op.f("ck_case_events_kind_valid"),
        "case_events",
        _in("kind", (*OLD_EVENT_KINDS, NEW_EVENT_KIND)),
    )


def downgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM case_events WHERE kind = 'retitled') THEN
                RAISE EXCEPTION 'a case was retitled: the case events are append-only'
                    USING ERRCODE = 'QC422';
            END IF;
        END
        $$
        """
    )
    op.drop_constraint(op.f("ck_case_events_kind_valid"), "case_events", type_="check")
    op.create_check_constraint(
        op.f("ck_case_events_kind_valid"), "case_events", _in("kind", OLD_EVENT_KINDS)
    )
