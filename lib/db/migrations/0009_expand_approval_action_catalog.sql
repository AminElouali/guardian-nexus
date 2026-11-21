-- Guardian Nexus migration 0009: expand action-reference checks from the
-- four-action catalog to the versioned eight-service synthetic catalog.
-- The literal arrays are checked against APPROVAL_ACTION_REFS by an API test.
BEGIN;

DO $migration$
DECLARE
  legacy_action_refs text[] := ARRAY[
    'guardian.synthetic.support.refund.v1',
    'guardian.synthetic.finance.bank-change.v1',
    'guardian.support.reply.send.v1',
    'guardian.email.send.external.v1'
  ]::text[];
  current_action_refs text[] := ARRAY[
    'guardian.synthetic.support.refund.v1',
    'guardian.synthetic.finance.bank-change.v1',
    'guardian.support.reply.send.v1',
    'guardian.email.send.external.v1',
    'guardian.email.reply.internal.v1',
    'guardian.email.send.external_sensitive.v1',
    'guardian.email.forwarding_rule.create.v1',
    'guardian.support.customer_account.close.v1',
    'guardian.finance.balance_invoice.read.v1',
    'guardian.finance.vendor_payment.known.v1',
    'guardian.finance.vendor_payment.new.v1',
    'guardian.data.query.read.v1',
    'guardian.data.customer.export.v1',
    'guardian.data.bulk.modify.v1',
    'guardian.data.bulk.delete.v1',
    'guardian.code.pull_request.open.v1',
    'guardian.code.pull_request.merge_main.v1',
    'guardian.code.deploy.production.v1',
    'guardian.code.secret.access.v1',
    'guardian.web.navigate.read.v1',
    'guardian.web.personal_data.submit.v1',
    'guardian.web.purchase.v1',
    'guardian.web.unapproved_credentials.submit.v1',
    'guardian.cloud.resource.read.v1',
    'guardian.cloud.resource.create.v1',
    'guardian.cloud.iam.permission.change.v1',
    'guardian.cloud.production_destructive.v1',
    'guardian.multiagent.delegate_equal_or_lower.v1',
    'guardian.multiagent.delegate_higher_scope.v1',
    'guardian.multiagent.privilege_escalation.v1'
  ]::text[];
  target record;
  found_constraint record;
  expected_attnums smallint[];
  actual_action_refs text[];
  normalized_expression text;
  expected_expression_shape text;
  rendered_action_refs text;
  relation_oid oid;
  attribute_attnum smallint;
BEGIN
  IF cardinality(legacy_action_refs) <> 4
    OR cardinality(current_action_refs) <> 30
    OR legacy_action_refs <@ current_action_refs IS NOT TRUE
    OR (
      SELECT count(DISTINCT action_ref)
        FROM unnest(current_action_refs) AS action_ref
    ) <> cardinality(current_action_refs)
  THEN
    RAISE EXCEPTION 'approval_action_ref_catalog_invalid'
      USING ERRCODE = '22023';
  END IF;

  FOR target IN
    SELECT *
    FROM (VALUES
      ('ai_assessment_approval_requests',
       'ai_assessment_approval_action_ref_check',
       'synthetic_action_ref,action_sha256',
       'approval'),
      ('workspace_action_rule_heads',
       'workspace_action_rule_heads_action_type_check',
       'action_type',
       'action_type'),
      ('workspace_action_rule_versions',
       'workspace_action_rule_versions_action_type_check',
       'action_type',
       'action_type'),
      ('workspace_connector_executions',
       'workspace_connector_executions_action_type_check',
       'action_type',
       'action_type')
    ) AS constraint_targets(table_name, constraint_name, column_names, kind)
  LOOP
    relation_oid := format('public.%I', target.table_name)::regclass;

    IF target.kind = 'approval' THEN
      SELECT array_agg(attribute.attnum::smallint ORDER BY expected.ordinality)
        INTO expected_attnums
        FROM unnest(string_to_array(target.column_names, ',')) WITH ORDINALITY
          AS expected(column_name, ordinality)
        JOIN pg_attribute AS attribute
          ON attribute.attrelid = relation_oid
         AND attribute.attname = expected.column_name
         AND attribute.attnum > 0
         AND NOT attribute.attisdropped;
    ELSE
      SELECT attribute.attnum::smallint
        INTO attribute_attnum
        FROM pg_attribute AS attribute
       WHERE attribute.attrelid = relation_oid
         AND attribute.attname = target.column_names
         AND attribute.attnum > 0
         AND NOT attribute.attisdropped;
      expected_attnums := ARRAY[attribute_attnum]::smallint[];
    END IF;

    IF expected_attnums IS NULL OR array_position(expected_attnums, NULL) IS NOT NULL THEN
      RAISE EXCEPTION 'approval_action_ref_constraint_column_missing:%', target.table_name
        USING ERRCODE = '42703';
    END IF;

    SELECT
      catalog_constraint.oid,
      catalog_constraint.contype,
      catalog_constraint.convalidated,
      catalog_constraint.connoinherit,
      catalog_constraint.condeferrable,
      catalog_constraint.condeferred,
      catalog_constraint.conkey,
      pg_get_expr(catalog_constraint.conbin, catalog_constraint.conrelid) AS expression
      INTO found_constraint
      FROM pg_constraint AS catalog_constraint
     WHERE catalog_constraint.conrelid = relation_oid
       AND catalog_constraint.conname = target.constraint_name;

    IF NOT FOUND THEN
      RAISE EXCEPTION 'approval_action_ref_constraint_missing:%', target.constraint_name
        USING ERRCODE = '42704';
    END IF;

    IF found_constraint.contype <> 'c'
      OR NOT found_constraint.convalidated
      OR found_constraint.connoinherit
      OR found_constraint.condeferrable
      OR found_constraint.condeferred
      OR NOT (
        found_constraint.conkey @> expected_attnums
        AND found_constraint.conkey <@ expected_attnums
      )
    THEN
      RAISE EXCEPTION 'approval_action_ref_constraint_shape_invalid:%', target.constraint_name
        USING ERRCODE = '23514';
    END IF;

    SELECT array_agg(matches.captures[1] ORDER BY matches.ordinality)
      INTO actual_action_refs
      FROM regexp_matches(
        found_constraint.expression,
        $pattern$'([^']+)'::text$pattern$,
        'g'
      ) WITH ORDINALITY AS matches(captures, ordinality);

    normalized_expression := lower(
      regexp_replace(found_constraint.expression, '[[:space:]]', '', 'g')
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
    expected_expression_shape := CASE target.kind
      WHEN 'approval' THEN
        '(((synthetic_action_ref IS NULL) AND (action_sha256 IS NULL)) OR ' ||
        '((synthetic_action_ref = ANY (ARRAY[<action_refs>])) AND ' ||
        '(action_sha256 IS NOT NULL)))'
      ELSE
        '(' || target.column_names || ' = ANY (ARRAY[<action_refs>]))'
    END;
    IF normalized_expression <> lower(
        regexp_replace(expected_expression_shape, '[[:space:]]', '', 'g')
      )
    THEN
      RAISE EXCEPTION 'approval_action_ref_constraint_definition_unexpected:%', target.constraint_name
        USING ERRCODE = '23514';
    END IF;

    SELECT string_agg(
        quote_literal(current_ref.action_ref),
        ', ' ORDER BY current_ref.ordinality
      )
      INTO rendered_action_refs
      FROM unnest(current_action_refs)
        WITH ORDINALITY AS current_ref(action_ref, ordinality);

    IF actual_action_refs = current_action_refs THEN
      -- Already aligned: deliberately perform no DDL.
      NULL;
    ELSIF actual_action_refs = legacy_action_refs THEN
      IF target.kind = 'approval' THEN
        EXECUTE format(
          'ALTER TABLE public.%I DROP CONSTRAINT %I, ' ||
          'ADD CONSTRAINT %I CHECK (' ||
          '(synthetic_action_ref IS NULL AND action_sha256 IS NULL) OR ' ||
          '(synthetic_action_ref IN (%s) AND action_sha256 IS NOT NULL))',
          target.table_name,
          target.constraint_name,
          target.constraint_name,
          rendered_action_refs
        );
      ELSE
        EXECUTE format(
          'ALTER TABLE public.%I DROP CONSTRAINT %I, ' ||
          'ADD CONSTRAINT %I CHECK (%I IN (%s))',
          target.table_name,
          target.constraint_name,
          target.constraint_name,
          target.column_names,
          rendered_action_refs
        );
      END IF;
    ELSE
      RAISE EXCEPTION 'approval_action_ref_constraint_references_unexpected:%', target.constraint_name
        USING ERRCODE = '23514';
    END IF;
  END LOOP;
END;
$migration$;

COMMIT;
