"""A person splits a case (D-211): investigations move out of it, and can come back.

A suggested case can group two devices that are separate incidents, and recording the owner's
notice (AR4b) on such a case would make its fingerprint absorb the second device's alerts. Nothing
could remove a member (only a merge did, and it closes the case), and indicators could only grow.
``argus case split`` moves chosen investigations, with the actor indicators only they carried, into
a new case or an existing one, in one transaction.

* ``case_events.kind`` gains ``unlinked``: the source case's event for a split. It keeps the state
  (the case guard needs no change: it checks versions and edges, and the kind's own CHECK allows a
  same-state event that is neither a creation, a closure nor a reopening).
* **A removed row can come back.** ``case_members`` is keyed by (case, investigation) and
  ``case_indicators`` by (case, kind, value), so an investigation or an indicator removed from a
  case and added to it again (a split undone; a device that returns) would have hit the key. The
  service now revives the row (the new link or role, version and person, ``removed_*`` cleared);
  the history of the first stay is in the case's events, which are append-only. Both
  ``argus_runtime`` and the web's role (a person's Link from a page can revive a row) get UPDATE on
  the columns it sets (the removal columns of ``case_members`` they had already).
* The web's trigger ``argus_web_case_writes`` also fires on UPDATE of ``case_members`` and
  ``case_indicators``: it refuses a row the web sets to an ``added_by`` that is not a ``user:``
  actor, whether the row is inserted or revived (an update that leaves ``added_by`` alone, such as
  a removal, passes as before).

Downgrading is refused while a case event is an ``unlinked``: the case events are append-only. The
revived rows stay as they are (the older code never reads their history); the grants and the
trigger go back to 0042's.

The role names are written out, not imported (see 0003). ``WEB_GRANTS`` is what the doctor and the
tests compare with ``roles.API_GRANTS``.

Revision ID: 0055
Revises: 0054
Create Date: 2026-10-30
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0055"
down_revision: str | None = "0054"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OLD_EVENT_KINDS = (
    "suspected", "opened", "confirmed", "dismissed", "taken", "assigned", "released",
    "contained", "new_activity", "activity_after_closure", "linked", "published",
    "closure_requested", "merge_requested", "closed", "merged_into", "merged_in", "reopened",
    "notified", "blocked", "address_moved", "notice_withdrawn",
)  # fmt: skip
NEW_EVENT_KIND = "unlinked"
MEMBER_REVIVE = "link, link_value, added_version, added_by, added_at"
INDICATOR_REVIVE = "role, source, added_version, added_by, added_at, removed_version, removed_at"
# what the doctor and the tests compare with ``roles.API_GRANTS``
WEB_GRANTS = (
    f"GRANT UPDATE ({MEMBER_REVIVE}) ON case_members TO argus_web",
    f"GRANT UPDATE ({INDICATOR_REVIVE}) ON case_indicators TO argus_web",
)

# 0042's function with the member/indicator check also made when a row's added_by changes
WEB_WRITES_FN = """
CREATE OR REPLACE FUNCTION argus_web_case_writes() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NOT (pg_has_role(current_user, 'argus_web', 'MEMBER')
            AND NOT pg_has_role(
                current_user, (SELECT relowner FROM pg_class WHERE oid = TG_RELID), 'MEMBER'
            )) THEN
        RETURN NEW;
    END IF;
    IF TG_TABLE_NAME = 'case_events' THEN
        IF NEW.actor_user_id IS NULL OR NEW.actor <> 'user:' || NEW.actor_user_id THEN
            RAISE EXCEPTION 'the web records a case event only as the person who acted (%)',
                NEW.actor USING ERRCODE = 'insufficient_privilege',
                HINT = 'Q-B3 review: the web is a person''s hands, not ARGUS''s own voice';
        END IF;
    ELSIF TG_TABLE_NAME IN ('case_members', 'case_indicators') THEN
        IF (TG_OP = 'INSERT' OR NEW.added_by IS DISTINCT FROM OLD.added_by)
           AND NEW.added_by !~ '^user:[1-9][0-9]{0,17}$' THEN
            RAISE EXCEPTION 'the web adds a member or indicator only as a person (%)',
                NEW.added_by USING ERRCODE = 'insufficient_privilege',
                HINT = 'Q-B3 review: the web is a person''s hands, not ARGUS''s own voice';
        END IF;
    ELSIF TG_TABLE_NAME = 'kibana_outbox' THEN
        IF NEW.write_class = 'W1' THEN
            RAISE EXCEPTION 'the web plans no write that opens or comments a Kibana case'
                USING ERRCODE = 'insufficient_privilege',
                HINT = 'a person''s command from a page changes or closes a Kibana case (W2, W3)';
        END IF;
    END IF;
    RETURN NEW;
END
$$;
"""
# the same function as 0042 made it
OLD_WEB_WRITES_FN = WEB_WRITES_FN.replace(
    """        IF (TG_OP = 'INSERT' OR NEW.added_by IS DISTINCT FROM OLD.added_by)
           AND NEW.added_by !~ '^user:[1-9][0-9]{0,17}$' THEN""",
    """        IF NEW.added_by !~ '^user:[1-9][0-9]{0,17}$' THEN""",
)
REVIVED_TABLES = ("case_members", "case_indicators")
RUNTIME_REVOKE = """
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'argus_runtime') THEN
        REVOKE UPDATE ({members}) ON case_members FROM argus_runtime;
        REVOKE UPDATE ({indicators}) ON case_indicators FROM argus_runtime;
    END IF;
END
$$
"""


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


def _web_trigger(table: str, when: str) -> None:
    op.execute(f"DROP TRIGGER {table}_web_writes ON {table}")
    op.execute(
        f"CREATE TRIGGER {table}_web_writes BEFORE {when} ON {table}"
        " FOR EACH ROW EXECUTE FUNCTION argus_web_case_writes()"
    )
    op.execute(f"ALTER TABLE {table} ENABLE ALWAYS TRIGGER {table}_web_writes")


def upgrade() -> None:
    op.drop_constraint(op.f("ck_case_events_kind_valid"), "case_events", type_="check")
    op.create_check_constraint(
        op.f("ck_case_events_kind_valid"),
        "case_events",
        _in("kind", (*OLD_EVENT_KINDS, NEW_EVENT_KIND)),
    )
    op.execute(f"GRANT UPDATE ({MEMBER_REVIVE}) ON case_members TO argus_runtime")
    op.execute(f"GRANT UPDATE ({INDICATOR_REVIVE}) ON case_indicators TO argus_runtime")
    for grant in WEB_GRANTS:
        op.execute(grant)
    op.execute(WEB_WRITES_FN)
    for table in REVIVED_TABLES:
        _web_trigger(table, "INSERT OR UPDATE")


def downgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM case_events WHERE kind = 'unlinked') THEN
                RAISE EXCEPTION 'a case was split: the case events are append-only'
                    USING ERRCODE = 'QC422';
            END IF;
        END
        $$
        """
    )
    for table in REVIVED_TABLES:
        _web_trigger(table, "INSERT")
    op.execute(OLD_WEB_WRITES_FN)
    op.execute(f"REVOKE UPDATE ({MEMBER_REVIVE}) ON case_members FROM argus_web")
    op.execute(f"REVOKE UPDATE ({INDICATOR_REVIVE}) ON case_indicators FROM argus_web")
    op.execute(  # the runtime role may be missing (0003's downgrade is a no-op without it)
        RUNTIME_REVOKE.format(members=MEMBER_REVIVE, indicators=INDICATOR_REVIVE)
    )
    op.drop_constraint(op.f("ck_case_events_kind_valid"), "case_events", type_="check")
    op.create_check_constraint(
        op.f("ck_case_events_kind_valid"), "case_events", _in("kind", OLD_EVENT_KINDS)
    )
