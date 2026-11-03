"""The rename of the SIEM's tables to ``siem_*`` (D-291), shared by the migrations.

The migrations create ``siem_*`` since D-291. A database made before it holds the gateway's tables
under the site's old prefix (the one other prefix under which ``_switches``, ``_requests`` and
``_live_sessions`` all exist, made by 0004); this renames them in place with every constraint,
index, sequence and trigger whose name carries the old word, so data, grants and defaults stay as
they were. With no such prefix, or ``siem_switches`` there already, it does nothing. Every
migration after 0004 that names a ``siem_`` table runs it first, so an old database (a restored
dump, a replay copy) upgrades from any revision; 0064 runs it for one already past them all.
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
