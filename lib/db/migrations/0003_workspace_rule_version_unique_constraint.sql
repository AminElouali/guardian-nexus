-- Guardian Nexus migration 0003: expose the rule-version uniqueness as a
-- PostgreSQL constraint, matching the Drizzle schema and catalog contract.
-- The unique index already exists after migration 0001; attach it rather than
-- creating another index or touching any rows.
BEGIN;

DO $migration$
DECLARE
  target_table oid := to_regclass('public.workspace_action_rule_versions');
  existing_constraint_valid boolean;
  expected_index oid;
BEGIN
  IF target_table IS NULL THEN
    RAISE EXCEPTION 'workspace_rule_versions_table_missing'
      USING ERRCODE = '42P01';
  END IF;

  SELECT
    constraint_row.contype = 'u'
    AND constraint_row.conkey = ARRAY[
      (SELECT attribute.attnum
         FROM pg_attribute AS attribute
        WHERE attribute.attrelid = target_table
          AND attribute.attname = 'workspace_id'),
      (SELECT attribute.attnum
         FROM pg_attribute AS attribute
        WHERE attribute.attrelid = target_table
          AND attribute.attname = 'action_type'),
      (SELECT attribute.attnum
         FROM pg_attribute AS attribute
        WHERE attribute.attrelid = target_table
          AND attribute.attname = 'version')
    ]::smallint[]
    INTO existing_constraint_valid
    FROM pg_constraint AS constraint_row
   WHERE constraint_row.conrelid = target_table
     AND constraint_row.conname =
       'workspace_action_rule_versions_workspace_action_version_uidx';

  IF FOUND THEN
    IF existing_constraint_valid THEN
      RETURN;
    END IF;
    RAISE EXCEPTION 'workspace_rule_version_unique_constraint_mismatch'
      USING ERRCODE = '42830';
  END IF;

  SELECT index_row.indexrelid
    INTO expected_index
    FROM pg_index AS index_row
    JOIN pg_class AS index_class
      ON index_class.oid = index_row.indexrelid
   WHERE index_row.indrelid = target_table
     AND index_class.relname =
       'workspace_action_rule_versions_workspace_action_version_uidx'
     AND index_row.indisunique
     AND index_row.indisvalid
     AND index_row.indpred IS NULL
     AND index_row.indexprs IS NULL
     AND index_row.indnatts = 3
     AND index_row.indnkeyatts = 3
     AND ARRAY(
       SELECT attribute.attname::text
         FROM unnest(index_row.indkey) WITH ORDINALITY AS key_column(attnum, ord)
         JOIN pg_attribute AS attribute
           ON attribute.attrelid = target_table
          AND attribute.attnum = key_column.attnum
        WHERE key_column.ord <= index_row.indnkeyatts
        ORDER BY key_column.ord
     ) = ARRAY['workspace_id', 'action_type', 'version']::text[];

  IF expected_index IS NULL THEN
    RAISE EXCEPTION 'workspace_rule_version_unique_index_missing_or_mismatched'
      USING ERRCODE = '42704';
  END IF;

  ALTER TABLE public.workspace_action_rule_versions
    ADD CONSTRAINT workspace_action_rule_versions_workspace_action_version_uidx
    UNIQUE USING INDEX workspace_action_rule_versions_workspace_action_version_uidx;
END;
$migration$;

COMMIT;
