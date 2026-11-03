BEGIN;

CREATE TABLE IF NOT EXISTS public.ai_assessment_approval_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
  job_id uuid NOT NULL REFERENCES public.ai_assessment_jobs(id) ON DELETE CASCADE,
  case_id text NOT NULL,
  proposal_sha256 text NOT NULL,
  action_sha256 text,
  proposal_binding_sha256 text NOT NULL,
  requested_by_user_id text NOT NULL,
  requested_by_role text,
  binding_version integer NOT NULL DEFAULT 1,
  synthetic_action_ref text,
  status text NOT NULL DEFAULT 'pending'
    CONSTRAINT ai_assessment_approval_status_check
    CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
  expires_at timestamptz NOT NULL,
  decided_by_user_id text,
  decided_by_role text,
  decided_at timestamptz,
  simulated_at timestamptz,
  simulation_result_code text,
  simulation_result_sha256 text,
  replay_binding_sha256 text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ai_assessment_approval_hashes_check CHECK (
    proposal_sha256 ~ '^[a-f0-9]{64}$'
    AND (action_sha256 IS NULL OR action_sha256 ~ '^[a-f0-9]{64}$')
    AND proposal_binding_sha256 ~ '^[a-f0-9]{64}$'
    AND (simulation_result_sha256 IS NULL OR simulation_result_sha256 ~ '^[a-f0-9]{64}$')
    AND (replay_binding_sha256 IS NULL OR replay_binding_sha256 ~ '^[a-f0-9]{64}$')
  ),
  CONSTRAINT ai_assessment_approval_binding_version_check CHECK (
    binding_version IN (1, 2)
    AND (binding_version = 1 OR (requested_by_role IS NOT NULL
         AND synthetic_action_ref IS NOT NULL AND action_sha256 IS NOT NULL))
  ),
  CONSTRAINT ai_assessment_approval_action_ref_check CHECK (
    (synthetic_action_ref IS NULL AND action_sha256 IS NULL)
    OR (synthetic_action_ref IN (
        'guardian.synthetic.finance.bank-change.v1',
        'guardian.synthetic.support.refund.v1'
      ) AND action_sha256 IS NOT NULL)
  ),
  CONSTRAINT ai_assessment_approval_simulation_receipt_check CHECK (
    (simulated_at IS NULL AND simulation_result_code IS NULL
      AND simulation_result_sha256 IS NULL AND replay_binding_sha256 IS NULL)
    OR (status = 'approved' AND synthetic_action_ref IS NOT NULL
      AND simulated_at IS NOT NULL
      AND simulation_result_code IN (
        'synthetic_bank_change_approved_in_clone',
        'synthetic_refund_approved_in_clone'
      )
      AND simulation_result_sha256 IS NOT NULL AND replay_binding_sha256 IS NOT NULL)
  ),
  CONSTRAINT ai_assessment_approval_decision_check CHECK (
    (status = 'pending' AND decided_by_user_id IS NULL AND decided_at IS NULL)
    OR (status IN ('approved', 'denied')
        AND decided_by_user_id IS NOT NULL AND decided_at IS NOT NULL)
    OR (status = 'expired' AND decided_by_user_id IS NULL)
  ),
  CONSTRAINT ai_assessment_approval_no_self_approval_check CHECK (
    decided_by_user_id IS NULL OR decided_by_user_id <> requested_by_user_id
  )
);
ALTER TABLE public.ai_assessment_approval_requests
  ADD COLUMN IF NOT EXISTS requested_by_role text,
  ADD COLUMN IF NOT EXISTS binding_version integer NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS synthetic_action_ref text,
  ADD COLUMN IF NOT EXISTS decided_by_role text,
  ADD COLUMN IF NOT EXISTS simulated_at timestamptz,
  ADD COLUMN IF NOT EXISTS simulation_result_code text,
  ADD COLUMN IF NOT EXISTS simulation_result_sha256 text,
  ADD COLUMN IF NOT EXISTS replay_binding_sha256 text;
CREATE UNIQUE INDEX IF NOT EXISTS ai_assessment_approval_job_case_idx
  ON public.ai_assessment_approval_requests (workspace_id, job_id, case_id);
CREATE INDEX IF NOT EXISTS ai_assessment_approval_workspace_status_expiry_idx
  ON public.ai_assessment_approval_requests (workspace_id, status, expires_at);
GRANT SELECT, INSERT ON TABLE public.ai_assessment_approval_requests TO app_runtime;
GRANT UPDATE (
  status, decided_by_user_id, decided_by_role, decided_at, simulated_at,
  simulation_result_code, simulation_result_sha256, replay_binding_sha256,
  updated_at
)
  ON TABLE public.ai_assessment_approval_requests TO app_runtime;
ALTER TABLE public.ai_assessment_approval_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_assessment_approval_requests FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS ai_assessment_approvals_select_member
  ON public.ai_assessment_approval_requests;
CREATE POLICY ai_assessment_approvals_select_member
  ON public.ai_assessment_approval_requests FOR SELECT TO app_runtime
  USING (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = ai_assessment_approval_requests.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
    )
  );

DROP POLICY IF EXISTS ai_assessment_approvals_insert_owner
  ON public.ai_assessment_approval_requests;
CREATE POLICY ai_assessment_approvals_insert_owner
  ON public.ai_assessment_approval_requests FOR INSERT TO app_runtime
  WITH CHECK (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND requested_by_user_id = NULLIF(current_setting('app.user_id', true), '')
    AND status = 'pending'
    AND decided_by_user_id IS NULL
    AND decided_at IS NULL
    AND binding_version IN (1, 2)
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = ai_assessment_approval_requests.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
        AND membership.role IN ('owner', 'admin')
    )
    AND EXISTS (
      SELECT 1 FROM public.ai_assessment_jobs AS job
      WHERE job.id = ai_assessment_approval_requests.job_id
        AND job.workspace_id = ai_assessment_approval_requests.workspace_id
        AND job.requested_by_user_id = ai_assessment_approval_requests.requested_by_user_id
        AND job.status = 'succeeded'
    )
  );

DROP POLICY IF EXISTS ai_assessment_approvals_update_approver
  ON public.ai_assessment_approval_requests;
CREATE POLICY ai_assessment_approvals_update_approver
  ON public.ai_assessment_approval_requests FOR UPDATE TO app_runtime
  USING (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = ai_assessment_approval_requests.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
        AND membership.role IN ('owner', 'admin')
    )
    AND status = 'pending'
    AND (
      (expires_at > now()
       AND requested_by_user_id <> NULLIF(current_setting('app.user_id', true), ''))
      OR expires_at <= now()
    )
  )
  WITH CHECK (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = ai_assessment_approval_requests.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
        AND membership.role IN ('owner', 'admin')
    )
    AND (
      (status IN ('approved', 'denied')
       AND decided_by_user_id = NULLIF(current_setting('app.user_id', true), '')
       AND decided_at IS NOT NULL
       AND decided_by_role IN ('owner', 'admin')
       AND requested_by_user_id <> decided_by_user_id)
      OR (status = 'expired'
          AND expires_at <= now()
          AND decided_by_user_id IS NULL
          AND decided_at IS NULL)
    )
  );

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
      OR position('guardian-agent-qwen-lab-customer-service-v1' IN existing_definition) = 0
      OR position('guardian-agent-qwen-lab-programming-v1' IN existing_definition) = 0
      OR position('guardian-agent-qwen-lab-browser-v1' IN existing_definition) = 0
      OR position('guardian-agent-qwen-lab-infrastructure-v1' IN existing_definition) = 0
      OR position('guardian-agent-qwen-lab-multiagent-v1' IN existing_definition) = 0
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
          'guardian-agent-qwen-lab-finance-v1',
          'guardian-agent-qwen-lab-customer-service-v1',
          'guardian-agent-qwen-lab-programming-v1',
          'guardian-agent-qwen-lab-browser-v1',
          'guardian-agent-qwen-lab-infrastructure-v1',
          'guardian-agent-qwen-lab-multiagent-v1'
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
      'guardian-agent-qwen-lab-finance-v1',
      'guardian-agent-qwen-lab-customer-service-v1',
      'guardian-agent-qwen-lab-programming-v1',
      'guardian-agent-qwen-lab-browser-v1',
      'guardian-agent-qwen-lab-infrastructure-v1',
      'guardian-agent-qwen-lab-multiagent-v1'
    )
    AND status IN ('running', 'failed')
    AND (
      status = 'failed'
      OR lease_owner_id::text =
        NULLIF(current_setting('app.ai_assessment_lease_owner', true), '')
    )
  );

COMMIT;
