"""What was advised, asked and done about a case (Q-H2, plan §5 and §7.7).

``case_actions`` holds one row for each (case, catalogue action): the advice ARGUS records
(``recommended``), a person's ``requested`` (the owner was asked) and ``reported_done`` (an
attestation: ARGUS cannot see the action), and ARGUS's own answer after it (``verified``, or
``not_verified`` with the reason and the last sign of activity). Nothing is executed: Phase 6 is
the first that may act. The catalogue is ``config/actions.yaml``; its action ids are checked by
the loader, not here, so the table never needs a migration when an action is added.

What the database refuses whoever asks (``argus_case_action_guard``, the owner's function, ENABLE
ALWAYS like the other guards):

* the edges: recommended -> requested | reported_done; requested -> reported_done; reported_done
  -> verified | not_verified; verified -> not_verified (activity came back); not_verified ->
  reported_done (a person tried again) or not_verified again (a newer reason). Nothing else, and
  the identity of a row (case, action, family, owner) never changes;
* a person's new attestation clears the earlier verdict, so an old "not verified" never sits
  beside a newer "done"; ``updated_at`` is the database's own time;
* from the web's login (checked by ``current_user``, as 0042 does): only a person's
  ``requested`` or ``reported_done``, never ARGUS's recommendation or verdict, and a new row
  carries only its own state's columns (a ``requested`` row holds no report or attestation, a
  ``reported_done`` row no request). ``requested_by`` and ``reported_by`` are ``user:<id>`` for
  everybody (a CHECK), so the web cannot sign in ARGUS's name;
* from the web's login, a report dated within 10 minutes of the database's clock (``reported_at``
  starts the three whole days a verdict waits for, and orders ARGUS's verdicts: a date a century
  ahead would block every verdict, a date days back would let quiet days count at once).

``argus_runtime`` reads the table and writes the named columns, with no DELETE. The web's role
reads it and writes only the person's columns: it may INSERT a row already ``requested`` or
``reported_done`` (a page can show a catalogue action ARGUS has not yet recorded) and UPDATE
those columns; the verdict columns are ARGUS's.

The role name is written out, not imported (see 0003).

Revision ID: 0044
Revises: 0043
Create Date: 2026-10-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0044"
down_revision: str | None = "0043"  # Q-H4's 0043_notices publishes first
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

STATES = ("recommended", "requested", "reported_done", "verified", "not_verified")
RUNTIME_INSERT = (
    "case_id, action, family, owner, catalogue_version, state, recommended_at, recommended_by,"
    " requested_at, requested_by, reported_at, reported_by, attestation, verdict_at, verdict,"
    " last_beat"
)
RUNTIME_UPDATE = (
    "state, requested_at, requested_by, reported_at, reported_by, attestation, verdict_at,"
    " verdict, last_beat"
)
WEB_INSERT = (
    "case_id, action, family, owner, catalogue_version, state, requested_at, requested_by,"
    " reported_at, reported_by, attestation"
)
WEB_UPDATE = "state, requested_at, requested_by, reported_at, reported_by, attestation"
# what the doctor and the tests compare with ``roles.API_GRANTS``
WEB_GRANTS = (
    f"GRANT SELECT, INSERT ({WEB_INSERT}), UPDATE ({WEB_UPDATE}) ON case_actions TO argus_web",
)
USER = r"^user:[1-9][0-9]{0,17}$"

GUARD = """
CREATE FUNCTION argus_case_action_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    from_web boolean := pg_has_role(current_user, 'argus_web', 'MEMBER')
        AND NOT pg_has_role(
            current_user, (SELECT relowner FROM pg_class WHERE oid = TG_RELID), 'MEMBER'
        );
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state NOT IN ('recommended', 'requested', 'reported_done') THEN
            RAISE EXCEPTION 'case action %: a row starts as recommended, requested or done',
                NEW.action USING ERRCODE = 'QC422';
        END IF;
        IF from_web AND (NEW.state = 'recommended' OR NEW.recommended_at IS NOT NULL
                         OR NEW.recommended_by IS NOT NULL OR NEW.verdict_at IS NOT NULL) THEN
            RAISE EXCEPTION 'case action %: the web records only a person''s request or report',
                NEW.action USING ERRCODE = 'insufficient_privilege',
                HINT = 'ARGUS recommends and verifies; the web is a person''s hands';
        END IF;
        IF from_web AND ((NEW.state = 'requested' AND (NEW.reported_at IS NOT NULL
                              OR NEW.reported_by IS NOT NULL OR NEW.attestation IS NOT NULL))
                         OR (NEW.state = 'reported_done' AND (NEW.requested_at IS NOT NULL
                              OR NEW.requested_by IS NOT NULL))) THEN
            RAISE EXCEPTION 'case action %: a new row holds only its own state''s columns',
                NEW.action USING ERRCODE = 'QC422';
        END IF;
        IF from_web AND NEW.reported_at IS NOT NULL
           AND abs(extract(epoch FROM NEW.reported_at - now())) > 600 THEN
            RAISE EXCEPTION 'case action %: a report is dated now, not another time', NEW.action
                USING ERRCODE = 'QC422';
        END IF;
        NEW.updated_at := now();
        RETURN NEW;
    END IF;
    IF NEW.id <> OLD.id OR NEW.case_id <> OLD.case_id OR NEW.action <> OLD.action
       OR NEW.family <> OLD.family OR NEW.owner <> OLD.owner
       OR NEW.catalogue_version <> OLD.catalogue_version
       OR NEW.recommended_at IS DISTINCT FROM OLD.recommended_at
       OR NEW.recommended_by IS DISTINCT FROM OLD.recommended_by THEN
        RAISE EXCEPTION 'case action %: its identity cannot change', OLD.id
            USING ERRCODE = 'QC422';
    END IF;
    IF NOT ((OLD.state = 'recommended' AND NEW.state IN ('requested', 'reported_done'))
            OR (OLD.state = 'requested' AND NEW.state = 'reported_done')
            OR (OLD.state = 'reported_done' AND NEW.state IN ('verified', 'not_verified'))
            OR (OLD.state = 'verified' AND NEW.state = 'not_verified')
            OR (OLD.state = 'not_verified' AND NEW.state IN ('reported_done', 'not_verified'))
    ) THEN
        RAISE EXCEPTION 'case action %: % cannot become %', OLD.id, OLD.state, NEW.state
            USING ERRCODE = 'QC422';
    END IF;
    IF from_web AND NEW.state NOT IN ('requested', 'reported_done') THEN
        RAISE EXCEPTION 'case action %: the web records only a person''s request or report',
            OLD.id USING ERRCODE = 'insufficient_privilege',
            HINT = 'ARGUS recommends and verifies; the web is a person''s hands';
    END IF;
    IF NEW.state <> 'requested' AND (NEW.requested_at IS DISTINCT FROM OLD.requested_at
                                     OR NEW.requested_by IS DISTINCT FROM OLD.requested_by) THEN
        RAISE EXCEPTION 'case action %: the request is a person''s and does not change', OLD.id
            USING ERRCODE = 'QC422';
    END IF;
    IF NEW.state = 'reported_done' THEN
        IF NEW.reported_at IS NOT DISTINCT FROM OLD.reported_at
           OR (OLD.reported_at IS NOT NULL AND NEW.reported_at <= OLD.reported_at) THEN
            RAISE EXCEPTION 'case action %: a new report is newer than the last', OLD.id
                USING ERRCODE = 'QC422';
        END IF;
        IF from_web AND abs(extract(epoch FROM NEW.reported_at - now())) > 600 THEN
            RAISE EXCEPTION 'case action %: a report is dated now, not another time', OLD.id
                USING ERRCODE = 'QC422';
        END IF;
        NEW.verdict_at := NULL;
        NEW.verdict := NULL;
        NEW.last_beat := NULL;
    ELSE
        IF NEW.reported_at IS DISTINCT FROM OLD.reported_at
           OR NEW.reported_by IS DISTINCT FROM OLD.reported_by
           OR NEW.attestation IS DISTINCT FROM OLD.attestation THEN
            RAISE EXCEPTION 'case action %: only a new report changes who reported it', OLD.id
                USING ERRCODE = 'QC422';
        END IF;
        IF NEW.verdict_at <= NEW.reported_at THEN
            RAISE EXCEPTION 'case action %: a verdict comes after the report it judges', OLD.id
                USING ERRCODE = 'QC422';
        END IF;
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END
$$;
"""


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


def upgrade() -> None:
    op.create_table(
        "case_actions",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("family", sa.Text(), nullable=False),
        sa.Column("owner", sa.Text(), nullable=False),
        sa.Column("catalogue_version", sa.Integer(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("recommended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("recommended_by", sa.Text(), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("requested_by", sa.Text(), nullable=True),
        sa.Column("reported_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reported_by", sa.Text(), nullable=True),
        sa.Column("attestation", sa.Text(), nullable=True),
        sa.Column("verdict_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verdict", sa.Text(), nullable=True),
        sa.Column("last_beat", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(_in("state", STATES), name=op.f("ck_case_actions_state_valid")),
        sa.CheckConstraint(
            "action ~ '^[a-z][a-z0-9_]*[.][a-z][a-z0-9_]*$' AND length(action) <= 80",
            name=op.f("ck_case_actions_action_valid"),
        ),
        sa.CheckConstraint(
            "family ~ '^[a-z][a-z0-9_]*$' AND owner ~ '^[a-z][a-z0-9_]*$'"
            " AND length(family) <= 60 AND length(owner) <= 60",
            name=op.f("ck_case_actions_names_valid"),
        ),
        sa.CheckConstraint(
            "catalogue_version >= 1", name=op.f("ck_case_actions_catalogue_version_valid")
        ),
        sa.CheckConstraint(
            "recommended_by IS NULL OR recommended_by = 'argus:responder'",
            name=op.f("ck_case_actions_recommended_by_argus"),
        ),
        sa.CheckConstraint(
            f"(requested_by IS NULL OR requested_by ~ '{USER}')"
            f" AND (reported_by IS NULL OR reported_by ~ '{USER}')",
            name=op.f("ck_case_actions_people_are_users"),
        ),
        sa.CheckConstraint(
            "(recommended_at IS NULL) = (recommended_by IS NULL)"
            " AND (requested_at IS NULL) = (requested_by IS NULL)"
            " AND (reported_at IS NULL) = (reported_by IS NULL)"
            " AND (reported_at IS NULL) = (attestation IS NULL)"
            " AND (verdict_at IS NULL) = (verdict IS NULL)",
            name=op.f("ck_case_actions_pairs_complete"),
        ),
        sa.CheckConstraint(
            "state <> 'recommended' OR recommended_at IS NOT NULL",
            name=op.f("ck_case_actions_recommended_is_recorded"),
        ),
        sa.CheckConstraint(
            "state <> 'requested' OR requested_at IS NOT NULL",
            name=op.f("ck_case_actions_requested_is_recorded"),
        ),
        sa.CheckConstraint(
            "state NOT IN ('reported_done', 'verified', 'not_verified') OR reported_at IS NOT NULL",
            name=op.f("ck_case_actions_done_is_recorded"),
        ),
        sa.CheckConstraint(
            "(state IN ('verified', 'not_verified')) = (verdict_at IS NOT NULL)",
            name=op.f("ck_case_actions_verdict_is_recorded"),
        ),
        sa.CheckConstraint(
            "last_beat IS NULL OR state = 'not_verified'",
            name=op.f("ck_case_actions_last_beat_means_not_verified"),
        ),
        sa.CheckConstraint(
            "attestation IS NULL OR length(attestation) BETWEEN 1 AND 500",
            name=op.f("ck_case_actions_attestation_length"),
        ),
        sa.CheckConstraint(
            "verdict IS NULL OR length(verdict) BETWEEN 1 AND 300",
            name=op.f("ck_case_actions_verdict_length"),
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_case_actions_case_id_cases")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_case_actions")),
        sa.UniqueConstraint("case_id", "action", name=op.f("uq_case_actions_case_id_action")),
    )
    op.create_index(op.f("ix_case_actions_state"), "case_actions", ["state"])
    op.execute(GUARD)
    op.execute("REVOKE EXECUTE ON FUNCTION argus_case_action_guard() FROM PUBLIC")
    op.execute(
        "CREATE TRIGGER case_actions_guard BEFORE INSERT OR UPDATE ON case_actions"
        " FOR EACH ROW EXECUTE FUNCTION argus_case_action_guard()"
    )
    op.execute("ALTER TABLE case_actions ENABLE ALWAYS TRIGGER case_actions_guard")
    op.execute(
        f"GRANT SELECT, INSERT ({RUNTIME_INSERT}), UPDATE ({RUNTIME_UPDATE})"
        " ON case_actions TO argus_runtime"
    )
    for grant in WEB_GRANTS:
        op.execute(grant)


def downgrade() -> None:
    op.execute("DROP TRIGGER case_actions_guard ON case_actions")
    op.drop_index(op.f("ix_case_actions_state"), table_name="case_actions")
    op.drop_table("case_actions")
    op.execute("DROP FUNCTION argus_case_action_guard()")
