"""More jobs argus-admin runs for the app (D-328, D-329)

``check`` (a connection check: the SIEM's key, a Kibana key, an AI provider, a threat-intel
source), ``assets`` (an uploaded asset map, sealed like a key: it is sensitive), ``llm_switch``
(the AI's kill switch) and ``service`` (a service or timer switched on or off, or restarted). A
sealed asset map may hold up to 5 MB. A setting's key may now name an AI provider's key
(``llm.keys.GROQ_API_KEY``) or a provider with a hyphen. A threat-intel key's test is counted
in ``outside_requests`` with its own purpose, ``check``; argus-admin publishes the sources' use
(``admin_state`` ``usage``) and the services' state (``services``).

Revision ID: 0111
Revises: 0110
Create Date: 2026-11-17
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0111"
down_revision: str | None = "0110"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

KINDS = "('inspect_tls', 'setup', 'check', 'assets', 'llm_switch', 'service')"
OLD_KINDS = "('inspect_tls', 'setup')"
PURPOSES = "('agent', 'prefetch', 'families', 'check')"
OLD_PURPOSES = "('agent', 'prefetch', 'families')"
STATES = "('seal', 'snapshot', 'heartbeat', 'usage', 'services')"
OLD_STATES = "('seal', 'snapshot', 'heartbeat')"
KEY = "key ~ '^[a-z_]+(\\.[A-Za-z0-9_-]+)+$'"
OLD_KEY = "key ~ '^[a-z_]+(\\.[a-z0-9_]+)+$'"


def upgrade() -> None:
    op.drop_constraint(op.f("ck_admin_jobs_kind_valid"), "admin_jobs", type_="check")
    op.create_check_constraint(op.f("ck_admin_jobs_kind_valid"), "admin_jobs", f"kind IN {KINDS}")
    op.drop_constraint(
        op.f("ck_admin_job_secrets_sealed_length"), "admin_job_secrets", type_="check"
    )
    op.create_check_constraint(
        op.f("ck_admin_job_secrets_sealed_length"),
        "admin_job_secrets",
        "octet_length(sealed) <= 5300000",
    )
    op.drop_constraint(op.f("ck_admin_changes_key_valid"), "admin_changes", type_="check")
    op.create_check_constraint(op.f("ck_admin_changes_key_valid"), "admin_changes", KEY)
    op.drop_constraint(op.f("ck_outside_requests_purpose_valid"), "outside_requests", type_="check")
    op.create_check_constraint(
        op.f("ck_outside_requests_purpose_valid"), "outside_requests", f"purpose IN {PURPOSES}"
    )
    op.drop_constraint(op.f("ck_admin_state_name_valid"), "admin_state", type_="check")
    op.create_check_constraint(
        op.f("ck_admin_state_name_valid"), "admin_state", f"name IN {STATES}"
    )


def downgrade() -> None:
    op.execute("DELETE FROM admin_state WHERE name IN ('usage', 'services')")
    op.drop_constraint(op.f("ck_admin_state_name_valid"), "admin_state", type_="check")
    op.create_check_constraint(
        op.f("ck_admin_state_name_valid"), "admin_state", f"name IN {OLD_STATES}"
    )
    op.execute("DELETE FROM outside_requests WHERE purpose = 'check'")
    op.drop_constraint(op.f("ck_outside_requests_purpose_valid"), "outside_requests", type_="check")
    op.create_check_constraint(
        op.f("ck_outside_requests_purpose_valid"), "outside_requests", f"purpose IN {OLD_PURPOSES}"
    )
    op.execute(f"DELETE FROM admin_jobs WHERE kind NOT IN {OLD_KINDS}")  # noqa: S608 - constants
    op.execute("DELETE FROM admin_changes WHERE key !~ '^[a-z_]+(\\.[a-z0-9_]+)+$'")
    op.drop_constraint(op.f("ck_admin_changes_key_valid"), "admin_changes", type_="check")
    op.create_check_constraint(op.f("ck_admin_changes_key_valid"), "admin_changes", OLD_KEY)
    op.drop_constraint(
        op.f("ck_admin_job_secrets_sealed_length"), "admin_job_secrets", type_="check"
    )
    op.create_check_constraint(
        op.f("ck_admin_job_secrets_sealed_length"),
        "admin_job_secrets",
        "octet_length(sealed) <= 20000",
    )
    op.drop_constraint(op.f("ck_admin_jobs_kind_valid"), "admin_jobs", type_="check")
    op.create_check_constraint(
        op.f("ck_admin_jobs_kind_valid"), "admin_jobs", f"kind IN {OLD_KINDS}"
    )
