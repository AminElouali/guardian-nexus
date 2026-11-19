-- Guardian Nexus migration 0006: align the approval action reference check.
-- The lab migration runner fills both arrays from APPROVAL_ACTION_REFS.
-- The legacy array is the two synthetic action references that existed before
-- generic support and external-email actions were added.
BEGIN;

DO $migration$
DECLARE
  legacy_action_refs text[] := ARRAY[{{LEGACY_APPROVAL_ACTION_REFS_SQL}}]::text[];
  current_action_refs text[] := ARRAY[{{APPROVAL_ACTION_REFS_SQL}}]::text[];
  sorted_legacy_action_refs text[];
  sorted_current_action_refs text[];
  actual_action_refs text[];
  action_ref_attnum smallint;
  action_sha256_attnum smallint;
  constraint_row record;
  normalized_expression text;
  expected_expression_shape constant text :=
    '(((synthetic_action_ref IS NULL) AND (action_sha256 IS NULL)) OR ' ||
    '((synthetic_action_ref = ANY (ARRAY[<action_refs>])) AND ' ||
    '(action_sha256 IS NOT NULL)))';
  rendered_action_refs text;
BEGIN
  IF cardinality(legacy_action_refs) <> 2
    OR cardinality(current_action_refs) <> 4
    OR legacy_action_refs <@ current_action_refs IS NOT TRUE
    OR (
      SELECT count(DISTINCT action_ref)
        FROM unnest(current_action_refs) AS action_ref
    ) <> cardinality(current_action_refs)
  THEN
    RAISE EXCEPTION 'approval_action_ref_catalog_invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT array_agg(action_ref ORDER BY action_ref)
    INTO sorted_legacy_action_refs
    FROM unnest(legacy_action_refs) AS action_ref;
  SELECT array_agg(action_ref ORDER BY action_ref)
    INTO sorted_current_action_refs
    FROM unnest(current_action_refs) AS action_ref;

  SELECT attribute.attnum
    INTO action_ref_attnum
    FROM pg_attribute AS attribute
   WHERE attribute.attrelid =
         'public.ai_assessment_approval_requests'::regclass
     AND attribute.attname = 'synthetic_action_ref'
     AND attribute.attnum > 0
     AND NOT attribute.attisdropped;
  SELECT attribute.attnum
    INTO action_sha256_attnum
    FROM pg_attribute AS attribute
   WHERE attribute.attrelid =
         'public.ai_assessment_approval_requests'::regclass
     AND attribute.attname = 'action_sha256'
     AND attribute.attnum > 0
     AND NOT attribute.attisdropped;
  IF action_ref_attnum IS NULL OR action_sha256_attnum IS NULL THEN
    RAISE EXCEPTION 'approval_action_ref_constraint_column_missing'
      USING ERRCODE = '42703';
  END IF;

  SELECT
    constraint_row.oid,
    constraint_row.contype,
    constraint_row.convalidated,
    constraint_row.connoinherit,
    constraint_row.condeferrable,
    constraint_row.condeferred,
    constraint_row.conkey,
    pg_get_expr(constraint_row.conbin, constraint_row.conrelid) AS expression
    INTO constraint_row
    FROM pg_constraint AS constraint_row
   WHERE constraint_row.conrelid =
         'public.ai_assessment_approval_requests'::regclass
     AND constraint_row.conname =
         'ai_assessment_approval_action_ref_check';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'approval_action_ref_constraint_missing'
      USING ERRCODE = '42704';
  END IF;

  IF constraint_row.contype <> 'c'
    OR NOT constraint_row.convalidated
    OR constraint_row.connoinherit
    OR constraint_row.condeferrable
    OR constraint_row.condeferred
    OR NOT (
      constraint_row.conkey @>
        ARRAY[action_ref_attnum, action_sha256_attnum]::smallint[]
      AND constraint_row.conkey <@
        ARRAY[action_ref_attnum, action_sha256_attnum]::smallint[]
    )
  THEN
    RAISE EXCEPTION 'approval_action_ref_constraint_shape_invalid'
      USING ERRCODE = '23514';
  END IF;

  SELECT array_agg(captured[1] ORDER BY captured[1])
    INTO actual_action_refs
    FROM regexp_matches(
      constraint_row.expression,
      $pattern$'([^']+)'::text$pattern$,
      'g'
    ) AS captured;
  normalized_expression := lower(
    regexp_replace(constraint_row.expression, '[[:space:]]', '', 'g')
  );
  normalized_expression := regexp_replace(
    normalized_expression,
    '::text',
    '',
    'g'
  );
  normalized_expression := regexp_replace(
    normalized_expression,
    $pattern$array\[.*\]$pattern$,
    'array[<action_refs>]',
    'g'
  );
  IF normalized_expression <> lower(
      regexp_replace(expected_expression_shape, '[[:space:]]', '', 'g')
    )
  THEN
    RAISE EXCEPTION 'approval_action_ref_constraint_definition_unexpected'
      USING ERRCODE = '23514';
  END IF;

  IF actual_action_refs = sorted_current_action_refs THEN
    -- Already aligned: deliberately perform no DDL.
    NULL;
  ELSIF actual_action_refs = sorted_legacy_action_refs THEN
    SELECT string_agg(quote_literal(action_ref), ', ' ORDER BY action_ref)
      INTO rendered_action_refs
      FROM unnest(current_action_refs) AS action_ref;
    EXECUTE format(
      'ALTER TABLE public.ai_assessment_approval_requests ' ||
      'DROP CONSTRAINT ai_assessment_approval_action_ref_check, ' ||
      'ADD CONSTRAINT ai_assessment_approval_action_ref_check CHECK (' ||
      '(synthetic_action_ref IS NULL AND action_sha256 IS NULL) OR ' ||
      '(synthetic_action_ref IN (%s) AND action_sha256 IS NOT NULL))',
      rendered_action_refs
    );
  ELSE
    RAISE EXCEPTION 'approval_action_ref_constraint_references_unexpected'
      USING ERRCODE = '23514';
  END IF;
END;
$migration$;

COMMIT;
