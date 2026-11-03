"""The device that saw or shipped an alert is no host entity: stored data follows

The normalizer no longer makes ``host.name`` an entity when it names the event's observer or agent.
This removes such entities already stored (from each alert's normalized form and the
investigations' entities) and recounts the entity table. Grouping keys are not affected.

Revision ID: 0015
Revises: 0014
Create Date: 2026-10-14 12:00:00.000000
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# The reporting device's names in one raw alert, nested or flat (normalize.REPORTER_FIELDS).
REPORTERS = """
SELECT lower(btrim(r.v)) FROM (VALUES
  (raw #>> '{observer,hostname}'), (raw ->> 'observer.hostname'),
  (raw #>> '{observer,name}'), (raw ->> 'observer.name'),
  (raw #>> '{agent,hostname}'), (raw ->> 'agent.hostname'),
  (raw #>> '{agent,name}'), (raw ->> 'agent.name')
) AS r(v) WHERE r.v IS NOT NULL AND btrim(r.v) <> ''
"""


def upgrade() -> None:
    # One pass over every stored alert, in ARGUS's own database (never the SIEM): the session's
    # statement timeout is for the service, not for this one-time step.
    op.execute("SET LOCAL statement_timeout = '10min'")
    lateral = REPORTERS.replace("raw", "a.raw")  # a constant: no value is interpolated
    op.execute(
        "CREATE TEMP TABLE argus_reporters ON COMMIT DROP AS"  # noqa: S608
        f" SELECT a.alert_id, r.v FROM alert_records a, LATERAL ({lateral})"
        " AS r(v) WHERE a.status = 'normalized'"
    )
    op.execute("CREATE INDEX ON argus_reporters (alert_id)")
    op.execute(
        """
        CREATE TEMP TABLE argus_changed ON COMMIT DROP AS
        SELECT DISTINCT a.alert_id FROM alert_records a
        JOIN argus_reporters r ON r.alert_id = a.alert_id
        CROSS JOIN LATERAL jsonb_array_elements(a.normalized -> 'entities') AS t(x)
        WHERE x ->> 'kind' = 'host' AND lower(x ->> 'value') = r.v
        """
    )
    op.execute(
        """
        UPDATE alert_records a SET normalized = jsonb_set(
          jsonb_set(a.normalized, '{entities}', coalesce((
            SELECT jsonb_agg(x ORDER BY o) FROM jsonb_array_elements(a.normalized -> 'entities')
              WITH ORDINALITY AS t(x, o)
            WHERE NOT (x ->> 'kind' = 'host' AND lower(x ->> 'value') IN (
              SELECT r.v FROM argus_reporters r WHERE r.alert_id = a.alert_id))
          ), '[]'::jsonb)),
          '{normalizer_version}', '"1.1.0"')
        FROM argus_changed c WHERE c.alert_id = a.alert_id
        """
    )
    op.execute(
        """
        CREATE TEMP TABLE argus_hosts ON COMMIT DROP AS
        SELECT DISTINCT l.investigation_id, x ->> 'value' AS value
        FROM investigation_alerts l JOIN alert_records a ON a.alert_id = l.alert_id
        CROSS JOIN LATERAL jsonb_array_elements(a.normalized -> 'entities') AS t(x)
        WHERE x ->> 'kind' = 'host' AND l.investigation_id IN (
          SELECT l2.investigation_id FROM investigation_alerts l2
          JOIN argus_changed c ON c.alert_id = l2.alert_id)
        """
    )
    op.execute(
        """
        DELETE FROM investigation_entities e
        WHERE e.kind = 'host' AND e.investigation_id IN (
          SELECT l.investigation_id FROM investigation_alerts l
          JOIN argus_changed c ON c.alert_id = l.alert_id)
        AND NOT EXISTS (SELECT 1 FROM argus_hosts h
                        WHERE h.investigation_id = e.investigation_id AND h.value = e.value)
        """
    )
    op.execute(
        """
        UPDATE entities n SET investigations = c.count FROM (
          SELECT kind, value, count(*) AS count FROM investigation_entities
          WHERE kind = 'host' GROUP BY kind, value) c
        WHERE n.kind = c.kind AND n.value = c.value AND n.investigations <> c.count
        """
    )
    op.execute(
        "DELETE FROM entities n WHERE n.kind = 'host' AND NOT EXISTS (SELECT 1 FROM"
        " investigation_entities e WHERE e.kind = n.kind AND e.value = n.value)"
    )


def downgrade() -> None:
    """Back to the 1.0 entities: the reporting device's host.name is an entity again."""
    op.execute("SET LOCAL statement_timeout = '10min'")
    op.execute(
        "CREATE FUNCTION pg_temp.argus_reporters(raw jsonb) RETURNS SETOF text"
        f" LANGUAGE sql IMMUTABLE AS $$ {REPORTERS} $$"
    )
    op.execute(
        """
        UPDATE alert_records a SET normalized = jsonb_set(jsonb_set(a.normalized, '{entities}',
            (a.normalized -> 'entities') || jsonb_build_array(jsonb_build_object(
              'kind', 'host', 'field', 'host.name', 'value', h.v))),
          '{normalizer_version}', '"1.0.0"')
        FROM (SELECT alert_id, btrim(coalesce(raw #>> '{host,name}', raw ->> 'host.name')) AS v
              FROM alert_records) h
        WHERE h.alert_id = a.alert_id AND a.status = 'normalized' AND h.v <> ''
          AND lower(h.v) IN (SELECT pg_temp.argus_reporters(a.raw))
          AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(a.normalized -> 'entities') t(x)
                          WHERE x ->> 'kind' = 'host' AND x ->> 'value' = h.v)
        """
    )
    op.execute(
        """
        INSERT INTO investigation_entities (investigation_id, kind, value)
        SELECT DISTINCT l.investigation_id, 'host', x ->> 'value'
        FROM investigation_alerts l JOIN alert_records a ON a.alert_id = l.alert_id
        CROSS JOIN LATERAL jsonb_array_elements(a.normalized -> 'entities') AS t(x)
        WHERE x ->> 'kind' = 'host'
        ON CONFLICT DO NOTHING
        """
    )
    op.execute(
        """
        INSERT INTO entities (kind, value, investigations)
        SELECT kind, value, count(*) FROM investigation_entities WHERE kind = 'host'
        GROUP BY kind, value
        ON CONFLICT (kind, value) DO UPDATE SET investigations = EXCLUDED.investigations
        """
    )
    op.execute("DROP FUNCTION pg_temp.argus_reporters(jsonb)")
