"""The web's login may read the case record and run the case commands (Q-B3).

Q-C1 gave the case tables to ARGUS's runtime role and Q-C3 gave the web's login the approval
functions, but the web's role (``argus_web``, Q-A2) had no grant on any case table, so no page or
route could show a case or let a person take one. Q-C3 left the decision to this component
(Q-B3): "the web records, ARGUS applies" or the web runs the commands itself.

This migration lets the web run them: ``CaseService`` writes a command's case row, members,
indicators, event and Kibana outbox rows in one transaction, so the web gets exactly the
columns that service writes for the commands a person gives from a page (take, assign, release,
contain, reopen, request a closure or a merge, merge a suspected case, apply an approval the
person has just completed) and the notes' inserts, and may read what the pages show. It gets
no INSERT on ``cases`` (the web opens no case), no DELETE anywhere, no UPDATE on events, notes,
approvals or the outbox, and nothing on ``chain_heads``.

What the database already refuses whoever asks stays refused: the case guard's lifecycle edges
and versions, closing a confirmed case without a complete approval, the outbox guard's moves, the
append-only tables and the hash chains (their triggers are the owner's). Reading the mirror and
the reconciliation's findings lets a page show Kibana's state and people's comments there; the
web never writes either. Q-C2's tables (``case_suggestions``, ``case_watch_checks``) are read, and
a person dismisses a suggestion (``dismissed_at``, ``dismissed_by``), the one column pair the
terminal's ``argus case suggestions --dismiss`` also writes; the finder that says whether a case
was quiet (the case pages and the approval desk build the case service with it) also reads the
opener's ``case_openings``.

The web's login is runtime-equivalent for the case record (Q-B3 review, decision 22): so that a
buggy or hijacked web process cannot sign its writes with ARGUS's name or an invented one, the
owner's trigger ``argus_web_case_writes`` (ENABLE ALWAYS, like the other guards; it looks at
``current_user`` as ``argus_web_state_rows`` does, so the owner and ARGUS's own logins pass) refuses
from the web's login a case event whose actor is not ``user:<id>`` with that id in
``actor_user_id``, a member or indicator whose ``added_by`` is not a ``user:`` actor, and a ``W1``
Kibana write (a case is opened in Kibana by ARGUS; no command a person gives from a page plans
one). A ``W3`` write without its approval is refused already by the table's CHECK and by
``argus_outbox_guard``. Whose person it is stays the session's: the database cannot know it.

The role name is written out, not imported (see 0003). ``WEB_GRANTS`` is what the doctor and the
tests compare with ``roles.API_GRANTS``.

Revision ID: 0042
Revises: 0041
Create Date: 2026-10-26
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0042"
down_revision: str | None = "0041"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

WEB_GRANTS = (
    "GRANT SELECT ON case_notes, entity_notes, kibana_mirror, kibana_findings, kibana_outbox"
    " TO argus_web",
    "GRANT SELECT, UPDATE (title, state, severity, owner_user_id, version, opened_at, closed_at,"
    " closure_reason, closure_request_id, merged_into_id, attention, kibana_wait, updated_at)"
    " ON cases TO argus_web",
    "GRANT SELECT, INSERT (case_id, investigation_id, link, link_value, added_version,"
    " added_by), UPDATE (removed_version, removed_at) ON case_members TO argus_web",
    "GRANT SELECT, INSERT (case_id, kind, value, role, source, added_version, added_by)"
    " ON case_indicators TO argus_web",
    "GRANT SELECT, INSERT (case_id, case_version, kind, actor, actor_user_id, from_state,"
    " to_state, details, kibana_rows) ON case_events TO argus_web",
    "GRANT INSERT (case_id, author_user_id, body) ON case_notes TO argus_web",
    "GRANT INSERT (kind, value, author_user_id, body) ON entity_notes TO argus_web",
    "GRANT INSERT (case_id, case_event_id, position, idempotency_key, write_class, op,"
    " payload, payload_hash, before_image, approval_request_id) ON kibana_outbox TO argus_web",
    # Q-C2's tables (0041): the suggested members and the watch's answers are read on the page;
    # dismissing a suggestion is a person's act (audited as theirs)
    "GRANT SELECT, UPDATE (dismissed_at, dismissed_by) ON case_suggestions TO argus_web",
    "GRANT SELECT ON case_watch_checks TO argus_web",
    # the finder (Q-C2) reads the opener's record of what it decided about a ``tie``
    "GRANT SELECT ON case_openings TO argus_web",
)

# The owner's function, run from the web's login only (the table's owner and ARGUS's other
# logins are not argus_web members): the web is a person's hands, never ARGUS's own voice.
WEB_WRITES_FN = """
CREATE FUNCTION argus_web_case_writes() RETURNS trigger
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
        IF NEW.added_by !~ '^user:[1-9][0-9]{0,17}$' THEN
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
WEB_WRITES_TABLES = ("case_events", "case_members", "case_indicators", "kibana_outbox")


def upgrade() -> None:
    for grant in WEB_GRANTS:
        op.execute(grant)
    op.execute(WEB_WRITES_FN)
    op.execute("REVOKE EXECUTE ON FUNCTION argus_web_case_writes() FROM PUBLIC")
    for table in WEB_WRITES_TABLES:
        op.execute(
            f"CREATE TRIGGER {table}_web_writes BEFORE INSERT ON {table}"
            " FOR EACH ROW EXECUTE FUNCTION argus_web_case_writes()"
        )
        op.execute(f"ALTER TABLE {table} ENABLE ALWAYS TRIGGER {table}_web_writes")


def downgrade() -> None:
    for table in WEB_WRITES_TABLES:
        op.execute(f"DROP TRIGGER {table}_web_writes ON {table}")
    op.execute("DROP FUNCTION argus_web_case_writes()")
    op.execute(
        "REVOKE ALL ON case_notes, entity_notes, kibana_mirror, kibana_findings, kibana_outbox,"
        " cases, case_members, case_indicators, case_events, case_suggestions,"
        " case_watch_checks FROM argus_web"
    )
