"""Users and roles in the app (D-327)

``user_links``: one-time links that let a person set their own password (a new account's welcome,
a reset), only their hashes kept. The web's login still holds no UPDATE of a password or of a
local account's capabilities: four functions do it, each checking inside the database what the
web says. An administrator's live session (the raw token, hashed here), confirmed by password in
the last five minutes, makes an account, changes one's capabilities or makes a link; the raw link
token sets a password. So the web's database login alone, without a person's session or link,
makes no usable account and takes over none.

Revision ID: 0109
Revises: 0108
Create Date: 2026-11-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0109"
down_revision: str | None = "0108"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

WEB_GRANTS = ("GRANT SELECT ON user_links TO argus_web",)
UNUSABLE = "!"  # an invited account's password until its person sets one: it never verifies

ADMIN_USER = """
CREATE FUNCTION argus_admin_session_user(p_session_token text) RETURNS bigint
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    uid bigint;
BEGIN
    uid := public.argus_approval_session_user(p_session_token);
    PERFORM 1 FROM public.user_sessions s JOIN public.users u ON u.id = s.user_id
        WHERE s.token_hash = encode(sha256(convert_to(p_session_token, 'UTF8')), 'hex')
          AND ('admin' = ANY(u.capabilities) OR 'admin' = ANY(coalesce(s.capabilities, '{}')));
    IF NOT FOUND THEN
        RAISE EXCEPTION 'only an administrator manages accounts' USING ERRCODE = 'QC403';
    END IF;
    PERFORM 1 FROM public.user_sessions s
        WHERE s.token_hash = encode(sha256(convert_to(p_session_token, 'UTF8')), 'hex')
          AND s.stepped_up_at >= clock_timestamp() - interval '5 minutes';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'confirm your password again first' USING ERRCODE = 'QC412';
    END IF;
    RETURN uid;
END
$$;
"""
CHECK_TARGET = """
    SELECT realm, kind INTO t_realm, t_kind FROM public.users WHERE id = p_user;
    IF t_realm IS NULL THEN
        RAISE EXCEPTION 'no such account' USING ERRCODE = 'QC404';
    END IF;
    IF t_realm <> 'local' OR t_kind <> 'person' THEN
        RAISE EXCEPTION 'only a local person''s account is managed here' USING ERRCODE = 'QC409';
    END IF;
"""
CREATE = """
CREATE FUNCTION argus_user_create(p_session_token text, p_username text, p_display_name text,
    p_capabilities text[], p_link_hash text, p_expires_at timestamptz) RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    by_id bigint;
    made bigint;
BEGIN
    by_id := public.argus_admin_session_user(p_session_token);
    INSERT INTO public.users (username, display_name, password_hash, capabilities, kind, realm)
        VALUES (p_username, p_display_name, '@UNUSABLE@', p_capabilities, 'person', 'local')
        RETURNING id INTO made;
    INSERT INTO public.user_links (token_hash, user_id, purpose, created_by, created_at,
        expires_at) VALUES (p_link_hash, made, 'welcome', by_id, clock_timestamp(), p_expires_at);
    RETURN made;
END
$$;
"""
CAPABILITIES = """
CREATE FUNCTION argus_user_capabilities(p_session_token text, p_user bigint,
    p_capabilities text[]) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    by_id bigint;
    t_realm text;
    t_kind text;
BEGIN
    by_id := public.argus_admin_session_user(p_session_token);
@CHECK_TARGET@
    IF by_id = p_user AND NOT ('admin' = ANY(p_capabilities)) THEN
        RAISE EXCEPTION 'you cannot take your own admin away' USING ERRCODE = 'QC409';
    END IF;
    UPDATE public.users SET capabilities = p_capabilities WHERE id = p_user;
END
$$;
"""
LINK = """
CREATE FUNCTION argus_user_link(p_session_token text, p_user bigint, p_link_hash text,
    p_expires_at timestamptz) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    by_id bigint;
    t_realm text;
    t_kind text;
BEGIN
    by_id := public.argus_admin_session_user(p_session_token);
@CHECK_TARGET@
    UPDATE public.user_links SET used_at = clock_timestamp()
        WHERE user_id = p_user AND used_at IS NULL;  -- a newer link ends the older ones
    INSERT INTO public.user_links (token_hash, user_id, purpose, created_by, created_at,
        expires_at) VALUES (p_link_hash, p_user, 'reset', by_id, clock_timestamp(), p_expires_at);
END
$$;
"""
USE = """
CREATE FUNCTION argus_link_use(p_token text, p_password_hash text) RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    uid bigint;
BEGIN
    IF p_password_hash !~ '^[$]argon2id[$]' THEN
        RAISE EXCEPTION 'not a password hash' USING ERRCODE = 'QC422';
    END IF;
    UPDATE public.user_links SET used_at = clock_timestamp()
        WHERE token_hash = encode(sha256(convert_to(p_token, 'UTF8')), 'hex')
          AND used_at IS NULL AND expires_at > clock_timestamp()
        RETURNING user_id INTO uid;
    IF uid IS NULL THEN
        RAISE EXCEPTION 'this link was used, ended or never made' USING ERRCODE = 'QC410';
    END IF;
    UPDATE public.users SET password_hash = p_password_hash
        WHERE id = uid AND realm = 'local' AND kind = 'person' AND NOT disabled;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'this account cannot sign in here' USING ERRCODE = 'QC409';
    END IF;
    UPDATE public.user_links SET used_at = clock_timestamp()
        WHERE user_id = uid AND used_at IS NULL;
    UPDATE public.user_sessions SET ended_at = clock_timestamp()
        WHERE user_id = uid AND ended_at IS NULL;
    RETURN uid;
END
$$;
"""
WEB_FUNCTIONS = (
    "argus_user_create(text, text, text, text[], text, timestamptz)",
    "argus_user_capabilities(text, bigint, text[])",
    "argus_user_link(text, bigint, text, timestamptz)",
    "argus_link_use(text, text)",
)
HELPER = "argus_admin_session_user(text)"


def upgrade() -> None:
    op.create_table(
        "user_links",
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("purpose", sa.Text(), nullable=False),
        sa.Column("created_by", sa.BigInteger(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "purpose IN ('welcome', 'reset')", name=op.f("ck_user_links_purpose_valid")
        ),
        sa.CheckConstraint(
            "token_hash ~ '^[0-9a-f]{64}$'", name=op.f("ck_user_links_token_hash_valid")
        ),
        sa.CheckConstraint(
            "expires_at > created_at", name=op.f("ck_user_links_expires_after_created")
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], ondelete="CASCADE", name=op.f("fk_user_links_user_id_users")
        ),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["users.id"],
            ondelete="SET NULL",
            name=op.f("fk_user_links_created_by_users"),
        ),
        sa.PrimaryKeyConstraint("token_hash", name=op.f("pk_user_links")),
    )
    op.create_index(op.f("ix_user_links_user_id"), "user_links", ["user_id"])
    op.execute("GRANT SELECT ON user_links TO argus_runtime")
    for grant in WEB_GRANTS:
        op.execute(grant)
    for body in (ADMIN_USER, CREATE, CAPABILITIES, LINK, USE):
        op.execute(body.replace("@UNUSABLE@", UNUSABLE).replace("@CHECK_TARGET@", CHECK_TARGET))
    op.execute(f"REVOKE EXECUTE ON FUNCTION {HELPER} FROM PUBLIC")
    for function in WEB_FUNCTIONS:
        op.execute(f"REVOKE EXECUTE ON FUNCTION {function} FROM PUBLIC")
        op.execute(f"GRANT EXECUTE ON FUNCTION {function} TO argus_approvals")


def downgrade() -> None:
    for function in (*WEB_FUNCTIONS, HELPER):
        op.execute(f"DROP FUNCTION {function}")
    op.drop_index(op.f("ix_user_links_user_id"), table_name="user_links")
    op.drop_table("user_links")
