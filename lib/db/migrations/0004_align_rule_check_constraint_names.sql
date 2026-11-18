-- Guardian Nexus migration 0004: align SQL-migration CHECK names with Drizzle.
-- Definitions and validated state are checked before any rename; no rows change.
BEGIN;

DO $migration$
DECLARE
  item record;
  target_table oid;
  expected_column smallint;
  old_count integer;
  new_count integer;
  existing_kind "char";
  existing_validated boolean;
  existing_no_inherit boolean;
  existing_columns smallint[];
  existing_expression text;
  normalized_expression text;
  source_name text;
BEGIN
  FOR item IN
    SELECT *
      FROM (VALUES
        (
          'workspace_action_rule_versions',
          'workspace_action_rule_versions_rule_document_check',
          'workspace_action_rule_versions_document_check',
          'rule_document',
          'jsonb_typeofrule_document=''object''::text'
        ),
        (
          'workspace_agents',
          'workspace_agents_credential_sha256_check',
          'workspace_agents_credential_hash_check',
          'credential_sha256',
          'credential_sha256~''^[a-f0-9]{64}$''::text'
        )
      ) AS checks(table_name, old_name, new_name, column_name, expected_expression)
  LOOP
    target_table := to_regclass(format('public.%I', item.table_name));
    IF target_table IS NULL THEN
      RAISE EXCEPTION 'workspace_check_constraint_table_missing:%',
        item.table_name USING ERRCODE = '42P01';
    END IF;

    SELECT attribute.attnum
      INTO expected_column
      FROM pg_attribute AS attribute
     WHERE attribute.attrelid = target_table
       AND attribute.attname = item.column_name
       AND attribute.attnum > 0
       AND NOT attribute.attisdropped;
    IF expected_column IS NULL THEN
      RAISE EXCEPTION 'workspace_check_constraint_column_missing:%',
        item.column_name USING ERRCODE = '42703';
    END IF;

    SELECT
      count(*) FILTER (WHERE constraint_row.conname = item.old_name)::integer,
      count(*) FILTER (WHERE constraint_row.conname = item.new_name)::integer
      INTO old_count, new_count
      FROM pg_constraint AS constraint_row
     WHERE constraint_row.conrelid = target_table
       AND constraint_row.conname IN (item.old_name, item.new_name);

    IF old_count = 1 AND new_count = 0 THEN
      source_name := item.old_name;
    ELSIF old_count = 0 AND new_count = 1 THEN
      source_name := item.new_name;
    ELSE
      RAISE EXCEPTION 'workspace_check_constraint_name_state_invalid:%',
        item.table_name USING ERRCODE = '42704';
    END IF;

    SELECT
      constraint_row.contype,
      constraint_row.convalidated,
      constraint_row.connoinherit,
      constraint_row.conkey,
      pg_get_expr(constraint_row.conbin, constraint_row.conrelid)
      INTO existing_kind, existing_validated, existing_no_inherit,
        existing_columns, existing_expression
      FROM pg_constraint AS constraint_row
     WHERE constraint_row.conrelid = target_table
       AND constraint_row.conname = source_name;

    normalized_expression := lower(
      regexp_replace(existing_expression, '[[:space:]()"]', '', 'g')
    );
    IF existing_kind <> 'c'
      OR NOT existing_validated
      OR existing_no_inherit
      OR existing_columns <> ARRAY[expected_column]::smallint[]
      OR normalized_expression <> item.expected_expression
    THEN
      RAISE EXCEPTION 'workspace_check_constraint_definition_mismatch:%',
        item.table_name USING ERRCODE = '23514';
    END IF;

    IF source_name = item.old_name THEN
      EXECUTE format(
        'ALTER TABLE public.%I RENAME CONSTRAINT %I TO %I',
        item.table_name,
        item.old_name,
        item.new_name
      );
    END IF;
  END LOOP;
END;
$migration$;

COMMIT;
