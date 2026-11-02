BEGIN;

ALTER TABLE public.workspaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspaces FORCE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_memberships FORCE ROW LEVEL SECURITY;
ALTER TABLE public.assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.assets FORCE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_monthly_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_monthly_usage FORCE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_audit_events FORCE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_integrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_integrations FORCE ROW LEVEL SECURITY;
ALTER TABLE public.provider_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.provider_connections FORCE ROW LEVEL SECURITY;
ALTER TABLE public.connector_oauth_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.connector_oauth_states FORCE ROW LEVEL SECURITY;
ALTER TABLE public.connector_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.connector_jobs FORCE ROW LEVEL SECURITY;
ALTER TABLE public.ai_assessment_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_assessment_jobs FORCE ROW LEVEL SECURITY;

ALTER POLICY workspaces_select_member ON public.workspaces
  USING (
    created_by_user_id = NULLIF(current_setting('app.user_id', true), '')
    OR EXISTS (
      SELECT 1
      FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = workspaces.id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
    )
  );

ALTER POLICY workspaces_insert_creator ON public.workspaces
  WITH CHECK (
    created_by_user_id = NULLIF(current_setting('app.user_id', true), '')
  );

ALTER POLICY workspace_memberships_select_scoped ON public.workspace_memberships
  USING (
    user_id = NULLIF(current_setting('app.user_id', true), '')
    OR workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
  );

ALTER POLICY workspace_memberships_insert_self ON public.workspace_memberships
  WITH CHECK (
    user_id = NULLIF(current_setting('app.user_id', true), '')
    AND workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
  );

ALTER POLICY workspace_memberships_update_scoped ON public.workspace_memberships
  USING (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
  )
  WITH CHECK (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
  );

ALTER POLICY assets_workspace_scope ON public.assets
  USING (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1
      FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = assets.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
    )
  )
  WITH CHECK (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1
      FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = assets.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
    )
  );

ALTER POLICY workspace_monthly_usage_scope ON public.workspace_monthly_usage
  USING (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1
      FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = workspace_monthly_usage.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
    )
  )
  WITH CHECK (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1
      FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = workspace_monthly_usage.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
    )
  );

ALTER POLICY workspace_audit_events_select_scope ON public.workspace_audit_events
  USING (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1
      FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = workspace_audit_events.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
    )
  );

ALTER POLICY workspace_audit_events_insert_scope ON public.workspace_audit_events
  WITH CHECK (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND actor_user_id = NULLIF(current_setting('app.user_id', true), '')
    AND EXISTS (
      SELECT 1
      FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = workspace_audit_events.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
    )
  );

ALTER POLICY workspace_integrations_select_member ON public.workspace_integrations
  USING (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1
      FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = workspace_integrations.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
    )
  );

ALTER POLICY workspace_integrations_insert_owner ON public.workspace_integrations
  WITH CHECK (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND created_by_user_id = NULLIF(current_setting('app.user_id', true), '')
    AND EXISTS (
      SELECT 1
      FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = workspace_integrations.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
        AND membership.role = 'owner'
    )
  );

ALTER POLICY workspace_integrations_update_owner ON public.workspace_integrations
  USING (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1
      FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = workspace_integrations.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
        AND membership.role = 'owner'
    )
  )
  WITH CHECK (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1
      FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = workspace_integrations.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
        AND membership.role = 'owner'
    )
  );

ALTER POLICY provider_connections_select_scope ON public.provider_connections
  USING (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = provider_connections.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
    )
  );

ALTER POLICY provider_connections_insert_scope ON public.provider_connections
  WITH CHECK (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = provider_connections.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
    )
  );

ALTER POLICY provider_connections_update_scope ON public.provider_connections
  USING (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = provider_connections.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
    )
  )
  WITH CHECK (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = provider_connections.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
    )
  );

ALTER POLICY provider_connections_delete_scope ON public.provider_connections
  USING (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = provider_connections.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
    )
  );

ALTER POLICY connector_oauth_states_select_scope ON public.connector_oauth_states
  USING (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = connector_oauth_states.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
    )
  );

ALTER POLICY connector_oauth_states_insert_scope ON public.connector_oauth_states
  WITH CHECK (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND user_id = NULLIF(current_setting('app.user_id', true), '')
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = connector_oauth_states.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
    )
  );

ALTER POLICY connector_oauth_states_delete_scope ON public.connector_oauth_states
  USING (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = connector_oauth_states.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
    )
  );

ALTER POLICY connector_jobs_select_scope ON public.connector_jobs
  USING (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = connector_jobs.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
    )
  );

ALTER POLICY connector_jobs_insert_scope ON public.connector_jobs
  WITH CHECK (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = connector_jobs.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
    )
  );

ALTER POLICY connector_jobs_update_scope ON public.connector_jobs
  USING (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = connector_jobs.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
    )
  )
  WITH CHECK (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = connector_jobs.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
    )
  );

ALTER POLICY connector_jobs_delete_scope ON public.connector_jobs
  USING (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = connector_jobs.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
    )
  );

ALTER POLICY ai_assessment_jobs_select_member ON public.ai_assessment_jobs
  USING (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = ai_assessment_jobs.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
    )
  );

ALTER POLICY ai_assessment_jobs_insert_owner ON public.ai_assessment_jobs
  WITH CHECK (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND requested_by_user_id = NULLIF(current_setting('app.user_id', true), '')
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = ai_assessment_jobs.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
        AND membership.role IN ('owner', 'admin')
    )
  );

ALTER POLICY ai_assessment_jobs_update_owner ON public.ai_assessment_jobs
  USING (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = ai_assessment_jobs.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
        AND membership.role IN ('owner', 'admin')
    )
  )
  WITH CHECK (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = ai_assessment_jobs.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
        AND membership.role IN ('owner', 'admin')
    )
  );

-- Keep the versioned worker profile constraint in sync with the queue policy.
DO $guardian_profile_migration$
DECLARE
  existing_definition text;
BEGIN
  SELECT pg_get_constraintdef(oid)
    INTO existing_definition
    FROM pg_constraint
   WHERE conrelid = 'public.ai_assessment_jobs'::regclass
     AND conname = 'ai_assessment_jobs_profile_check';

  IF existing_definition IS NULL
     OR position('guardian-local-llm-qwen3-0.6b-v1' IN existing_definition) = 0
     OR position('guardian-local-llm-native-tools-v1' IN existing_definition) = 0
     OR position('guardian-local-llm-autonomous-tools-v1' IN existing_definition) = 0
      OR position('guardian-agent-lab-email-v1' IN existing_definition) = 0
      OR position('guardian-agent-lab-database-v1' IN existing_definition) = 0
      OR position('guardian-agent-lab-finance-v1' IN existing_definition) = 0
      OR position('guardian-agent-lab-programming-v1' IN existing_definition) = 0
      OR position('guardian-agent-lab-customer-service-v1' IN existing_definition) = 0
      OR position('guardian-agent-lab-browser-v1' IN existing_definition) = 0
      OR position('guardian-agent-lab-infrastructure-v1' IN existing_definition) = 0
     OR position('guardian-agent-lab-multiagent-v1' IN existing_definition) = 0
     OR position('guardian-agent-qwen-lab-email-v1' IN existing_definition) = 0
     OR position('guardian-agent-qwen-lab-database-v1' IN existing_definition) = 0
      OR position('guardian-agent-qwen-lab-finance-v1' IN existing_definition) = 0
  THEN
    ALTER TABLE public.ai_assessment_jobs
      DROP CONSTRAINT IF EXISTS ai_assessment_jobs_profile_check;
    ALTER TABLE public.ai_assessment_jobs
      ADD CONSTRAINT ai_assessment_jobs_profile_check
      CHECK (
        profile_id IN (
          'guardian-local-agent-v1',
          'guardian-local-llm-qwen3-0.6b-v1',
          'guardian-local-llm-native-tools-v1',
          'guardian-local-llm-autonomous-tools-v1',
          'guardian-agent-lab-email-v1',
          'guardian-agent-lab-database-v1',
          'guardian-agent-lab-finance-v1',
          'guardian-agent-lab-programming-v1',
          'guardian-agent-lab-customer-service-v1',
          'guardian-agent-lab-browser-v1',
          'guardian-agent-lab-infrastructure-v1',
          'guardian-agent-lab-multiagent-v1',
          'guardian-agent-qwen-lab-email-v1',
          'guardian-agent-qwen-lab-database-v1',
          'guardian-agent-qwen-lab-finance-v1'
        )
      );
  END IF;
END
$guardian_profile_migration$;

ALTER POLICY ai_assessment_jobs_worker_select_queue
  ON public.ai_assessment_jobs
  USING (status IN ('queued', 'running', 'failed'));

ALTER POLICY ai_assessment_jobs_worker_update_queue
  ON public.ai_assessment_jobs
  USING (
    status = 'queued'
    OR (
      status = 'running'
      AND (
        lease_expires_at IS NULL
        OR lease_expires_at <= now()
        OR lease_owner_id::text =
          NULLIF(current_setting('app.ai_assessment_lease_owner', true), '')
      )
    )
  )
  WITH CHECK (
    profile_id IN (
      'guardian-local-agent-v1',
      'guardian-local-llm-qwen3-0.6b-v1',
      'guardian-local-llm-native-tools-v1',
      'guardian-local-llm-autonomous-tools-v1',
      'guardian-agent-lab-email-v1',
      'guardian-agent-lab-database-v1',
      'guardian-agent-lab-finance-v1',
      'guardian-agent-lab-programming-v1',
      'guardian-agent-lab-customer-service-v1',
      'guardian-agent-lab-browser-v1',
      'guardian-agent-lab-infrastructure-v1',
      'guardian-agent-lab-multiagent-v1',
      'guardian-agent-qwen-lab-email-v1',
      'guardian-agent-qwen-lab-database-v1',
      'guardian-agent-qwen-lab-finance-v1'
    )
    AND status IN ('running', 'failed')
    AND (
      status = 'failed'
      OR lease_owner_id::text =
        NULLIF(current_setting('app.ai_assessment_lease_owner', true), '')
    )
  );

COMMIT;
