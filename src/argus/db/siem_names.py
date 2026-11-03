"""The rename of the SIEM's tables to ``siem_*``, shared by the migrations.

A database made before the rename holds the gateway's tables under an older prefix; this renames
them in place with every constraint, index, sequence and trigger, so data and grants stay. With no
such prefix, or ``siem_switches`` there already, it does nothing. Migrations that name a ``siem_``
table run it first, so an old database upgrades from any revision.
"""

RENAME = """
DO $$
DECLARE
    r record;
    old text;
BEGIN
    SELECT left(c.relname, length(c.relname) - length('_switches')) INTO old
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = current_schema() AND c.relkind = 'r'
      AND c.relname LIKE '%\\_switches' AND c.relname <> 'siem_switches'
      AND to_regclass(left(c.relname, length(c.relname) - length('_switches')) || '_requests')
          IS NOT NULL
      AND to_regclass(left(c.relname, length(c.relname) - length('_switches')) || '_live_sessions')
          IS NOT NULL;
    IF old IS NULL OR to_regclass('siem_switches') IS NOT NULL THEN
        RETURN;
    END IF;
    -- constraints first (a primary key's index follows its constraint's name)
    FOR r IN
        SELECT c.conname, t.relname
        FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = current_schema() AND c.conname LIKE '%' || old || '\\_%'
    LOOP
        EXECUTE format('ALTER TABLE %I RENAME CONSTRAINT %I TO %I',
                       r.relname, r.conname, replace(r.conname, old || '_', 'siem_'));
    END LOOP;
    FOR r IN
        SELECT g.tgname, t.relname
        FROM pg_trigger g JOIN pg_class t ON t.oid = g.tgrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = current_schema() AND NOT g.tgisinternal
          AND g.tgname LIKE '%' || old || '\\_%'
    LOOP
        EXECUTE format('ALTER TRIGGER %I ON %I RENAME TO %I',
                       r.tgname, r.relname, replace(r.tgname, old || '_', 'siem_'));
    END LOOP;
    FOR r IN
        SELECT c.relname
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = current_schema() AND c.relkind = 'i'
          AND c.relname LIKE '%' || old || '\\_%'
    LOOP
        EXECUTE format('ALTER INDEX %I RENAME TO %I',
                       r.relname, replace(r.relname, old || '_', 'siem_'));
    END LOOP;
    FOR r IN
        SELECT c.relname
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = current_schema() AND c.relkind = 'S'
          AND c.relname LIKE '%' || old || '\\_%'
    LOOP
        EXECUTE format('ALTER SEQUENCE %I RENAME TO %I',
                       r.relname, replace(r.relname, old || '_', 'siem_'));
    END LOOP;
    FOR r IN
        SELECT c.relname
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = current_schema() AND c.relkind = 'r' AND c.relname LIKE old || '\\_%'
    LOOP
        EXECUTE format('ALTER TABLE %I RENAME TO %I',
                       r.relname, replace(r.relname, old || '_', 'siem_'));
    END LOOP;
END
$$;
"""
