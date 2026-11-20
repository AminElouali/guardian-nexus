-- Guardian Nexus migration 0007: persist exact signed v1 receipts for
-- agent-initiated MCP approval retries. Receipt and ledger formats are unchanged.
BEGIN;

CREATE TABLE IF NOT EXISTS public.workspace_approval_receipts (
  approval_id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL,
  receipt_id text NOT NULL,
  receipt_sha256 text NOT NULL,
  signed_receipt jsonb NOT NULL,
  approved_by_user_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT workspace_approval_receipts_workspace_id_workspaces_id_fk
    FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE,
  CONSTRAINT workspace_approval_receipts_approval_id_approval_requests_id_fk
    FOREIGN KEY (approval_id)
    REFERENCES public.ai_assessment_approval_requests(id) ON DELETE CASCADE,
  CONSTRAINT workspace_approval_receipts_receipt_id_check
    CHECK (receipt_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  CONSTRAINT workspace_approval_receipts_receipt_sha256_check
    CHECK (receipt_sha256 ~ '^[a-f0-9]{64}$'),
  CONSTRAINT workspace_approval_receipts_approved_by_check
    CHECK (approved_by_user_id <> ''),
  CONSTRAINT workspace_approval_receipts_signed_binding_check
    CHECK (
      jsonb_typeof(signed_receipt) = 'object'
      AND jsonb_typeof(signed_receipt->'payload'::text) = 'object'
      AND signed_receipt->>'payloadSha256'::text = receipt_sha256
      AND signed_receipt->'payload'::text->>'receiptId'::text = receipt_id
      AND signed_receipt->'payload'::text->>'workspaceId'::text = workspace_id::text
      AND signed_receipt->'payload'::text->>'approvalId'::text = approval_id::text
      AND signed_receipt->'payload'::text->>'approvedBy'::text = approved_by_user_id
    )
);
CREATE UNIQUE INDEX IF NOT EXISTS workspace_approval_receipts_receipt_id_uidx
  ON public.workspace_approval_receipts (receipt_id);

REVOKE ALL PRIVILEGES ON TABLE public.workspace_approval_receipts FROM app_runtime;
GRANT SELECT ON TABLE public.workspace_approval_receipts TO app_runtime;
GRANT INSERT (
  approval_id, workspace_id, receipt_id, receipt_sha256, signed_receipt,
  approved_by_user_id
) ON TABLE public.workspace_approval_receipts TO app_runtime;

ALTER TABLE public.workspace_approval_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_approval_receipts FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS workspace_approval_receipts_select_agent_execution
  ON public.workspace_approval_receipts;
CREATE POLICY workspace_approval_receipts_select_agent_execution
  ON public.workspace_approval_receipts FOR SELECT TO app_runtime
  USING (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND NULLIF(current_setting('app.agent_id', true), '') IS NOT NULL
    AND EXISTS (
      SELECT 1
      FROM public.workspace_agents AS agent
      WHERE agent.id::text = NULLIF(current_setting('app.agent_id', true), '')
        AND agent.workspace_id = workspace_approval_receipts.workspace_id
        AND agent.principal_user_id = NULLIF(current_setting('app.user_id', true), '')
        AND agent.revoked_at IS NULL
    )
    AND EXISTS (
      SELECT 1
      FROM public.ai_assessment_approval_requests AS approval
      JOIN public.ai_assessment_jobs AS job
        ON job.id = approval.job_id
       AND job.workspace_id = approval.workspace_id
      WHERE approval.id = workspace_approval_receipts.approval_id
        AND approval.workspace_id = workspace_approval_receipts.workspace_id
        AND approval.status = 'approved'
        AND approval.requested_by_user_id = NULLIF(current_setting('app.user_id', true), '')
        AND job.result->>'agentId'::text = NULLIF(current_setting('app.agent_id', true), '')
    )
  );

DROP POLICY IF EXISTS workspace_approval_receipts_insert_approver
  ON public.workspace_approval_receipts;
CREATE POLICY workspace_approval_receipts_insert_approver
  ON public.workspace_approval_receipts FOR INSERT TO app_runtime
  WITH CHECK (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND approved_by_user_id = NULLIF(current_setting('app.user_id', true), '')
    AND current_setting('app.approval_receipt_writer', true) = '1'
    AND EXISTS (
      SELECT 1
      FROM public.workspace_memberships AS approver
      WHERE approver.workspace_id = workspace_approval_receipts.workspace_id
        AND approver.user_id = NULLIF(current_setting('app.user_id', true), '')
        AND approver.role IN ('owner', 'admin')
    )
    AND EXISTS (
      SELECT 1
      FROM public.ai_assessment_approval_requests AS approval
      WHERE approval.id = workspace_approval_receipts.approval_id
        AND approval.workspace_id = workspace_approval_receipts.workspace_id
        AND approval.status = 'approved'
        AND approval.decided_by_user_id = NULLIF(current_setting('app.user_id', true), '')
        AND COALESCE(approval.action_sha256, '') = COALESCE(
          NULLIF(signed_receipt->'payload'::text->>'actionSha256'::text, ''),
          ''
        )
        AND approval.proposal_binding_sha256 =
          signed_receipt->'payload'::text->>'proposalBindingSha256'::text
        AND approval.requested_by_user_id =
          signed_receipt->'payload'::text->>'requestedBy'::text
    )
  );

COMMIT;
