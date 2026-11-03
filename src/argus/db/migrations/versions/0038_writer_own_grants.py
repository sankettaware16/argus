"""The case writer's own grants: the writer's login stops being a member of ``argus_runtime``.

Membership gave the writer's login everything the runtime can do (re-enable a disabled user,
change capabilities, lift a mirror pause), which the approvals' send-time checks rely on nobody
doing. The group role ``argus_writer`` now holds exactly what the writer needs
(``argus.db.roles.WRITER_GRANTS``, checked by ``argus doctor`` against every table), and ``argus
db bootstrap`` takes the login out of ``argus_runtime``.

Revision ID: 0038
Revises: 0037
Create Date: 2026-10-26
"""

from collections.abc import Sequence

from alembic import op

from argus.db.siem_names import RENAME

revision: str = "0038"
down_revision: str | None = "0037"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

READS = (
    "alert_records",
    "approval_decisions",
    "approval_requests",
    "case_events",
    "case_members",
    "cases",
    "siem_live_sessions",
    "siem_probes",
    "siem_switches",
    "identity_checks",
    "investigation_alerts",
    "kibana_mirror",
    "users",
    # its own tables (0037 granted the writing; the runtime's SELECT came with the membership)
    "kibana_outbox",
    "kibana_steps",
    "kibana_lookups",
    "kibana_writer_runs",
    "kibana_writer_ramp",
)
AUDIT_INSERT = (
    "actor",
    "action",
    "outcome",
    "target_type",
    "target_id",
    "correlation_id",
    "details",
)
FINDINGS_INSERT = (
    "found_at",
    "kind",
    "severity",
    "kibana_case_id",
    "case_id",
    "dedupe_key",
    "lag_s",
    "details",
)
LEDGER_INSERT = (
    "at",
    "component",
    "purpose",
    "template",
    "version",
    "indices",
    "outcome",
    "http_status",
    "took_ms",
    "elapsed_ms",
    "response_bytes",
    "attempts",
    "live_session",
    "task_key",
    "lane",
    "target",
    "outbox_id",
    "payload_hash",
    "write_class",
    "approval_id",
    "health",
    "switches",
)
FUNCTIONS = (
    "argus_approval_propose(text, uuid, integer, text, text, bigint, jsonb, text, text,"
    " timestamptz, text)",
    "argus_closure_write_move(bigint, text, text)",
    "argus_closure_write_lock(bigint)",
)
INSERTS = (
    ("audit_events", AUDIT_INSERT),
    ("kibana_findings", FINDINGS_INSERT),
    ("siem_requests", LEDGER_INSERT),
)


def upgrade() -> None:
    op.execute(RENAME)  # an old database's tables first (argus.db.siem_names)
    for table in READS:
        op.execute(f"GRANT SELECT ON {table} TO argus_writer")
    for table, columns in INSERTS:
        op.execute(f"GRANT SELECT, INSERT ({', '.join(columns)}) ON {table} TO argus_writer")
    op.execute("GRANT SELECT, UPDATE (state, updated_at) ON siem_state TO argus_writer")
    for function in FUNCTIONS:
        op.execute(f"GRANT EXECUTE ON FUNCTION {function} TO argus_writer")


def downgrade() -> None:
    for function in FUNCTIONS:
        op.execute(f"REVOKE EXECUTE ON FUNCTION {function} FROM argus_writer")
    op.execute("REVOKE SELECT, UPDATE (state, updated_at) ON siem_state FROM argus_writer")
    for table, columns in INSERTS:
        op.execute(f"REVOKE SELECT, INSERT ({', '.join(columns)}) ON {table} FROM argus_writer")
    for table in READS:
        op.execute(f"REVOKE SELECT ON {table} FROM argus_writer")  # noqa: S608 - fixed names
