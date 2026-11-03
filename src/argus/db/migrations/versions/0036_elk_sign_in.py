"""ELK sign-in: who an account is, ELK sessions, devices, break-glass

``users`` says what an account is (``kind``), where it signs in (``realm``), its exact ELK username
and ``argus_uid``; its password hash is optional, and is never dropped before the person's ELK
sign-in has worked. A new ``argus_uid`` behind a known name is a new person: the old row is frozen.
``user_sessions`` gains the ELK session's state (capability snapshot, encrypted credential, why it
could not be verified); ``user_devices`` holds device-cookie hashes; ``break_glass`` the one
emergency window. ``review_events.kibana_ok`` records whether a review was made under a live ELK
check that showed the alert-status privileges. The web's login may update only the identity lane's
and the gateway's ``siem_state`` rows (``argus_web_state_rows``). Downgrading ends ELK sessions.

Revision ID: 0036
Revises: 0035
Create Date: 2026-10-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from argus.db.siem_names import RENAME

revision: str = "0036"
down_revision: str | None = "0035"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

CAPABILITIES = (
    "view", "see_logs", "review", "answer_gold", "manage_cases", "reopen", "approve", "admin"
)  # fmt: skip
UID = "'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'"

# 0026's body with the three added conditions (kind, mode, verified).
SESSION_USER_NEW = """
CREATE OR REPLACE FUNCTION argus_approval_session_user(p_session_token text) RETURNS bigint
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    uid bigint;
BEGIN
    SELECT s.user_id INTO uid FROM public.user_sessions s JOIN public.users u ON u.id = s.user_id
        WHERE s.token_hash = encode(sha256(convert_to(p_session_token, 'UTF8')), 'hex')
          AND s.ended_at IS NULL AND s.expires_at > clock_timestamp()
          AND s.last_seen_at >= clock_timestamp() - interval '12 hours'
          AND NOT u.disabled AND u.username <> 'argus-assistant'
          AND u.kind = 'person' AND s.mode <> 'break_glass' AND s.unverified_since IS NULL;
    IF uid IS NULL THEN
        RAISE EXCEPTION 'no live session of a person' USING ERRCODE = 'QC401';
    END IF;
    RETURN uid;
END
$$;
"""
SESSION_USER_OLD = """
CREATE OR REPLACE FUNCTION argus_approval_session_user(p_session_token text) RETURNS bigint
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    uid bigint;
BEGIN
    SELECT s.user_id INTO uid FROM public.user_sessions s JOIN public.users u ON u.id = s.user_id
        WHERE s.token_hash = encode(sha256(convert_to(p_session_token, 'UTF8')), 'hex')
          AND s.ended_at IS NULL AND s.expires_at > clock_timestamp()
          AND s.last_seen_at >= clock_timestamp() - interval '12 hours'
          AND NOT u.disabled AND u.username <> 'argus-assistant';
    IF uid IS NULL THEN
        RAISE EXCEPTION 'no live session of a person' USING ERRCODE = 'QC401';
    END IF;
    RETURN uid;
END
$$;
"""

# The web's login (a member of argus_web, not of the table's owner) changes the identity lane's
# row and the gateway rows its security-index check keeps (a request through the Elasticsearch
# gateway admits against the budget and the lanes and reports to the breaker and the health
# memory), and no other: the Kibana lane's rows are none of its business. Like 0027's guards it
# looks at current_user, and the owner (a superuser locally) passes.
WEB_STATE_FN = """
CREATE FUNCTION argus_web_state_rows() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF OLD.name NOT IN ('identity', 'health', 'budget', 'breaker', 'lanes')
       AND pg_has_role(current_user, 'argus_web', 'MEMBER')
       AND NOT pg_has_role(
           current_user, (SELECT relowner FROM pg_class WHERE oid = TG_RELID), 'MEMBER'
       ) THEN
        RAISE EXCEPTION 'only the identity lane''s state and the gateway state of its index check'
                        ' may be changed by the web (row %)', OLD.name
            USING ERRCODE = 'insufficient_privilege',
                  HINT = 'the web has no business with the other lanes (Q-E2 review)';
    END IF;
    RETURN NEW;
END
$$;
"""

# The role names are written out, not imported (see 0003). Mirrors argus.db.roles.
RUNTIME_GRANTS = (
    "GRANT INSERT (kind, realm), UPDATE (elk_username, realm) ON users TO argus_runtime",
    "GRANT UPDATE (credential, ended_why) ON user_sessions TO argus_runtime",
    "GRANT SELECT, INSERT (user_id, token_hash), UPDATE (last_used_at) ON user_devices"
    " TO argus_runtime",
    "GRANT SELECT, INSERT (user_id, reason, enabled_by, expires_at, override),"
    " UPDATE (consumed_at, ended_at) ON break_glass TO argus_runtime",
    "GRANT INSERT (kibana_ok) ON review_events TO argus_runtime",
)
WEB_GRANTS = (
    "GRANT INSERT (username, display_name, kind, realm, elk_username, argus_uid, email,"
    " capabilities, elk_first_signin_at, last_good_check_at),"
    " UPDATE (display_name, email, argus_uid, elk_first_signin_at, last_good_check_at,"
    " disabled, frozen_at) ON users TO argus_web",
    "GRANT INSERT (mode, capabilities, checked_at, map_version, credential, no_custody),"
    " UPDATE (capabilities, checked_at, map_version, credential, unverified_since,"
    " unverified_why, ended_why) ON user_sessions TO argus_web",
    "GRANT SELECT, INSERT (user_id, token_hash), UPDATE (last_used_at) ON user_devices"
    " TO argus_web",
    "GRANT SELECT, UPDATE (consumed_at) ON break_glass TO argus_web",
    "GRANT INSERT (kibana_ok) ON review_events TO argus_web",
    # the identity lane runs in the web: its gate state, its ledger rows, the switches it obeys
    "GRANT UPDATE (state, updated_at) ON siem_state TO argus_web",
    "GRANT SELECT ON siem_switches TO argus_web",
    "GRANT INSERT (at, component, purpose, template, version, indices, outcome, http_status,"
    " took_ms, elapsed_ms, response_bytes, attempts, live_session, task_key, lane, target,"
    " outbox_id, payload_hash, write_class, approval_id, health, switches)"
    " ON siem_requests TO argus_web",
)
WEB_REVOKES = (
    "REVOKE UPDATE (state, updated_at) ON siem_state FROM argus_web",
    "REVOKE SELECT ON siem_switches FROM argus_web",
    "REVOKE INSERT (at, component, purpose, template, version, indices, outcome, http_status,"
    " took_ms, elapsed_ms, response_bytes, attempts, live_session, task_key, lane, target,"
    " outbox_id, payload_hash, write_class, approval_id, health, switches)"
    " ON siem_requests FROM argus_web",
)


def upgrade() -> None:
    op.execute(RENAME)  # an old database's tables first (argus.db.siem_names)
    op.add_column("users", sa.Column("kind", sa.Text(), server_default="person", nullable=False))
    op.add_column("users", sa.Column("realm", sa.Text(), server_default="local", nullable=False))
    op.add_column("users", sa.Column("elk_username", sa.Text(), nullable=True))
    op.add_column("users", sa.Column("argus_uid", sa.Text(), nullable=True))
    op.add_column("users", sa.Column("email", sa.Text(), nullable=True))
    op.add_column(
        "users", sa.Column("elk_first_signin_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "users", sa.Column("last_good_check_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("users", sa.Column("frozen_at", sa.DateTime(timezone=True), nullable=True))
    op.alter_column("users", "password_hash", nullable=True)
    op.execute("UPDATE users SET kind = 'service' WHERE username = 'argus-assistant'")
    op.create_check_constraint(
        op.f("ck_users_kind_valid"), "users", "kind IN ('person', 'service', 'break_glass')"
    )
    op.create_check_constraint(
        op.f("ck_users_realm_valid"), "users", "realm IN ('local', 'native')"
    )
    op.create_check_constraint(
        op.f("ck_users_realm_matches_elk_name"),
        "users",
        "(realm = 'native') = (elk_username IS NOT NULL)",
    )
    op.create_check_constraint(
        op.f("ck_users_elk_username_valid"),
        "users",
        "elk_username IS NULL OR char_length(elk_username) BETWEEN 1 AND 507",
    )
    op.create_check_constraint(
        op.f("ck_users_argus_uid_valid"), "users", f"argus_uid IS NULL OR argus_uid ~ {UID}"
    )
    op.create_check_constraint(
        op.f("ck_users_password_or_elk"),
        "users",
        "password_hash IS NOT NULL OR elk_first_signin_at IS NOT NULL",
    )
    op.create_check_constraint(
        op.f("ck_users_break_glass_is_local"), "users", "kind <> 'break_glass' OR realm = 'local'"
    )
    op.create_index(
        op.f("ix_users_elk_username"),
        "users",
        ["elk_username"],
        unique=True,
        postgresql_where=sa.text("elk_username IS NOT NULL AND frozen_at IS NULL"),
    )
    op.create_index(
        op.f("ix_users_argus_uid"),
        "users",
        ["argus_uid"],
        unique=True,
        postgresql_where=sa.text("argus_uid IS NOT NULL"),
    )

    op.add_column(
        "user_sessions", sa.Column("mode", sa.Text(), server_default="local", nullable=False)
    )
    op.add_column(
        "user_sessions", sa.Column("capabilities", postgresql.ARRAY(sa.Text()), nullable=True)
    )
    op.add_column(
        "user_sessions", sa.Column("checked_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("user_sessions", sa.Column("map_version", sa.SmallInteger(), nullable=True))
    op.add_column("user_sessions", sa.Column("credential", sa.LargeBinary(), nullable=True))
    op.add_column(
        "user_sessions",
        sa.Column("no_custody", sa.Boolean(), server_default="false", nullable=False),
    )
    op.add_column(
        "user_sessions", sa.Column("unverified_since", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("user_sessions", sa.Column("unverified_why", sa.Text(), nullable=True))
    op.add_column("user_sessions", sa.Column("ended_why", sa.Text(), nullable=True))
    known = ", ".join(f"'{c}'" for c in CAPABILITIES)
    op.create_check_constraint(
        op.f("ck_user_sessions_mode_valid"),
        "user_sessions",
        "mode IN ('local', 'elk', 'break_glass')",
    )
    op.create_check_constraint(
        op.f("ck_user_sessions_snapshot_valid"),
        "user_sessions",
        f"capabilities IS NULL OR (capabilities <@ ARRAY[{known}]::text[]"
        " AND array_position(capabilities, NULL) IS NULL)",
    )
    op.create_check_constraint(
        op.f("ck_user_sessions_elk_has_snapshot"),
        "user_sessions",
        "mode <> 'elk' OR (capabilities IS NOT NULL AND checked_at IS NOT NULL)",
    )
    op.create_check_constraint(
        op.f("ck_user_sessions_unverified_why_valid"),
        "user_sessions",
        "unverified_why IS NULL OR unverified_why IN ('outage', 'refused')",
    )
    op.create_check_constraint(
        op.f("ck_user_sessions_credential_only_elk"),
        "user_sessions",
        "credential IS NULL OR (mode = 'elk' AND NOT no_custody)",
    )
    op.create_index(
        "ix_user_sessions_with_credential",
        "user_sessions",
        ["token_hash"],
        postgresql_where=sa.text("credential IS NOT NULL"),
    )

    op.add_column(
        "review_events",
        sa.Column("kibana_ok", sa.Boolean(), server_default="false", nullable=False),
    )

    op.create_table(
        "user_devices",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "last_used_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_user_devices_user_id_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_user_devices")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_user_devices_token_hash")),
    )
    op.create_index(op.f("ix_user_devices_user_id"), "user_devices", ["user_id"], unique=False)

    op.create_table(
        "break_glass",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("slot", sa.SmallInteger(), server_default="1", nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("enabled_by", sa.Text(), nullable=False),
        sa.Column(
            "enabled_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("override", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "char_length(reason) BETWEEN 10 AND 500", name=op.f("ck_break_glass_reason_valid")
        ),
        sa.CheckConstraint(
            "expires_at > enabled_at AND expires_at <= enabled_at + interval '4 hours'",
            name=op.f("ck_break_glass_window_valid"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_break_glass_user_id_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_break_glass")),
    )
    op.create_index(
        op.f("ix_break_glass_slot"),
        "break_glass",
        ["slot"],
        unique=True,
        postgresql_where=sa.text("ended_at IS NULL"),
    )

    op.execute(SESSION_USER_NEW)
    for grant in (*RUNTIME_GRANTS, *WEB_GRANTS):
        op.execute(grant)
    op.execute(WEB_STATE_FN)
    op.execute("REVOKE EXECUTE ON FUNCTION argus_web_state_rows() FROM PUBLIC")
    op.execute(
        "CREATE TRIGGER siem_state_web_rows BEFORE UPDATE ON siem_state"
        " FOR EACH ROW EXECUTE FUNCTION argus_web_state_rows()"
    )
    op.execute("ALTER TABLE siem_state ENABLE ALWAYS TRIGGER siem_state_web_rows")


def downgrade() -> None:
    bind = op.get_bind()
    only_elk = bind.execute(sa.text("SELECT count(*) FROM users WHERE password_hash IS NULL"))
    kept = only_elk.scalar_one()
    if kept:
        raise RuntimeError(
            f"{kept} account(s) signed in through ELK only and have no local password: a"
            " downgrade would lose them. Give each a password first, or stay on this revision"
        )
    op.execute(SESSION_USER_OLD)
    # the old code reads every session as a local one: an ELK or break-glass session left open
    # would be a session of the account's old rights (and the credential column goes below)
    op.execute(
        "UPDATE user_sessions SET ended_at = now(), credential = NULL, ended_why = 'downgrade'"
        " WHERE mode <> 'local' AND ended_at IS NULL"
    )
    op.execute("UPDATE users SET disabled = true WHERE kind = 'break_glass'")
    op.execute("DROP TRIGGER siem_state_web_rows ON siem_state")
    op.execute("DROP FUNCTION argus_web_state_rows()")
    for revoke in WEB_REVOKES:
        op.execute(revoke)
    op.drop_table("break_glass")
    op.drop_index(op.f("ix_user_devices_user_id"), table_name="user_devices")
    op.drop_table("user_devices")
    op.drop_column("review_events", "kibana_ok")
    op.drop_index("ix_user_sessions_with_credential", table_name="user_sessions")
    for name in (
        "ck_user_sessions_credential_only_elk",
        "ck_user_sessions_unverified_why_valid",
        "ck_user_sessions_elk_has_snapshot",
        "ck_user_sessions_snapshot_valid",
        "ck_user_sessions_mode_valid",
    ):
        op.drop_constraint(op.f(name), "user_sessions", type_="check")
    for column in (
        "ended_why",
        "unverified_why",
        "unverified_since",
        "no_custody",
        "credential",
        "map_version",
        "checked_at",
        "capabilities",
        "mode",
    ):
        op.drop_column("user_sessions", column)
    op.drop_index(op.f("ix_users_argus_uid"), table_name="users")
    op.drop_index(op.f("ix_users_elk_username"), table_name="users")
    for name in (
        "ck_users_break_glass_is_local",
        "ck_users_password_or_elk",
        "ck_users_argus_uid_valid",
        "ck_users_elk_username_valid",
        "ck_users_realm_matches_elk_name",
        "ck_users_realm_valid",
        "ck_users_kind_valid",
    ):
        op.drop_constraint(op.f(name), "users", type_="check")
    op.alter_column("users", "password_hash", nullable=False)
    for column in (
        "frozen_at",
        "last_good_check_at",
        "elk_first_signin_at",
        "email",
        "argus_uid",
        "elk_username",
        "realm",
        "kind",
    ):
        op.drop_column("users", column)
