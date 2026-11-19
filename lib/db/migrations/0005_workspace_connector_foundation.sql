-- Guardian Nexus migration 0005: encrypted workspace connector credentials
-- and receipt-gated, idempotent execution records. No ledger v1 shape changes.
BEGIN;

CREATE TABLE IF NOT EXISTS public.workspace_connector_credentials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL,
  service_id text NOT NULL,
  encrypted_secret text NOT NULL,
  nonce text NOT NULL,
  auth_tag text NOT NULL,
  encryption_key_id text NOT NULL,
  last_four text NOT NULL,
  created_by_user_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT workspace_connector_credentials_workspace_id_workspaces_id_fk
    FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE,
  CONSTRAINT workspace_connector_credentials_service_id_check
    CHECK (service_id ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
  CONSTRAINT workspace_connector_credentials_ciphertext_check
    CHECK (encrypted_secret ~ '^[A-Za-z0-9_-]{8,5462}$'),
  CONSTRAINT workspace_connector_credentials_nonce_check
    CHECK (nonce ~ '^[A-Za-z0-9_-]{16}$'),
  CONSTRAINT workspace_connector_credentials_auth_tag_check
    CHECK (auth_tag ~ '^[A-Za-z0-9_-]{22}$'),
  CONSTRAINT workspace_connector_credentials_key_id_check
    CHECK (encryption_key_id ~ '^[A-Za-z0-9._-]{1,64}$'),
  CONSTRAINT workspace_connector_credentials_last_four_check
    CHECK (length(last_four) = 4)
);
CREATE UNIQUE INDEX IF NOT EXISTS
  workspace_connector_credentials_workspace_service_uidx
  ON public.workspace_connector_credentials (workspace_id, service_id);
CREATE UNIQUE INDEX IF NOT EXISTS workspace_connector_credentials_nonce_uidx
  ON public.workspace_connector_credentials (nonce);

CREATE TABLE IF NOT EXISTS public.workspace_connector_executions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL,
  service_id text NOT NULL,
  credential_id uuid,
  idempotency_key_sha256 text NOT NULL,
  action_type text NOT NULL,
  action_sha256 text NOT NULL,
  receipt_id text NOT NULL,
  requested_by_user_id text NOT NULL,
  status text NOT NULL DEFAULT 'pending',
  response_summary text,
  failure_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  CONSTRAINT workspace_connector_executions_workspace_id_workspaces_id_fk
    FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE,
  CONSTRAINT workspace_connector_executions_credential_id_credentials_id_fk
    FOREIGN KEY (credential_id)
    REFERENCES public.workspace_connector_credentials(id) ON DELETE SET NULL,
  CONSTRAINT workspace_connector_executions_service_id_check
    CHECK (service_id ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
  CONSTRAINT workspace_connector_executions_idempotency_hash_check
    CHECK (idempotency_key_sha256 ~ '^[a-f0-9]{64}$'),
  CONSTRAINT workspace_connector_executions_action_type_check
    CHECK (action_type IN (
      'guardian.synthetic.support.refund.v1',
      'guardian.synthetic.finance.bank-change.v1',
      'guardian.support.reply.send.v1',
      'guardian.email.send.external.v1'
    )),
  CONSTRAINT workspace_connector_executions_action_hash_check
    CHECK (action_sha256 ~ '^[a-f0-9]{64}$'),
  CONSTRAINT workspace_connector_executions_receipt_id_check
    CHECK (receipt_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  CONSTRAINT workspace_connector_executions_status_check
    CHECK (status IN ('pending', 'executed', 'failed')),
  CONSTRAINT workspace_connector_executions_response_summary_check
    CHECK (response_summary IS NULL OR length(response_summary) <= 512),
  CONSTRAINT workspace_connector_executions_failure_code_check
    CHECK (failure_code IS NULL OR failure_code ~ '^[a-z0-9_]{1,64}$'),
  CONSTRAINT workspace_connector_executions_completion_state_check
    CHECK (
      (status = 'pending' AND completed_at IS NULL
        AND failure_code IS NULL AND response_summary IS NULL)
      OR (status = 'executed' AND completed_at IS NOT NULL
        AND failure_code IS NULL)
      OR (status = 'failed' AND completed_at IS NOT NULL
        AND failure_code IS NOT NULL)
    )
);
CREATE UNIQUE INDEX IF NOT EXISTS workspace_connector_executions_idempotency_uidx
  ON public.workspace_connector_executions
    (workspace_id, service_id, idempotency_key_sha256);

REVOKE ALL PRIVILEGES ON TABLE public.workspace_connector_credentials
  FROM app_runtime;
GRANT SELECT, DELETE ON TABLE public.workspace_connector_credentials
  TO app_runtime;
GRANT INSERT (
  workspace_id, service_id, encrypted_secret, nonce, auth_tag,
  encryption_key_id, last_four, created_by_user_id
) ON TABLE public.workspace_connector_credentials TO app_runtime;

REVOKE ALL PRIVILEGES ON TABLE public.workspace_connector_executions
  FROM app_runtime;
GRANT SELECT ON TABLE public.workspace_connector_executions TO app_runtime;
GRANT INSERT (
  workspace_id, service_id, credential_id, idempotency_key_sha256,
  action_type, action_sha256, receipt_id, requested_by_user_id, status
) ON TABLE public.workspace_connector_executions TO app_runtime;
GRANT UPDATE (
  status, response_summary, failure_code, updated_at, completed_at
) ON TABLE public.workspace_connector_executions TO app_runtime;

ALTER TABLE public.workspace_connector_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_connector_credentials FORCE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_connector_executions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_connector_executions FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS workspace_connector_credentials_select_admin
  ON public.workspace_connector_credentials;
CREATE POLICY workspace_connector_credentials_select_admin
  ON public.workspace_connector_credentials FOR SELECT TO app_runtime
  USING (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id =
        workspace_connector_credentials.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
        AND membership.role IN ('owner', 'admin')
    )
  );
DROP POLICY IF EXISTS workspace_connector_credentials_insert_admin
  ON public.workspace_connector_credentials;
CREATE POLICY workspace_connector_credentials_insert_admin
  ON public.workspace_connector_credentials FOR INSERT TO app_runtime
  WITH CHECK (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND created_by_user_id = NULLIF(current_setting('app.user_id', true), '')
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id =
        workspace_connector_credentials.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
        AND membership.role IN ('owner', 'admin')
    )
  );
DROP POLICY IF EXISTS workspace_connector_credentials_delete_admin
  ON public.workspace_connector_credentials;
CREATE POLICY workspace_connector_credentials_delete_admin
  ON public.workspace_connector_credentials FOR DELETE TO app_runtime
  USING (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id =
        workspace_connector_credentials.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
        AND membership.role IN ('owner', 'admin')
    )
  );
DROP POLICY IF EXISTS workspace_connector_executions_select_member
  ON public.workspace_connector_executions;
CREATE POLICY workspace_connector_executions_select_member
  ON public.workspace_connector_executions FOR SELECT TO app_runtime
  USING (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = workspace_connector_executions.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
    )
  );
DROP POLICY IF EXISTS workspace_connector_executions_insert_admin
  ON public.workspace_connector_executions;
CREATE POLICY workspace_connector_executions_insert_admin
  ON public.workspace_connector_executions FOR INSERT TO app_runtime
  WITH CHECK (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND requested_by_user_id = NULLIF(current_setting('app.user_id', true), '')
    AND status = 'pending'
    AND response_summary IS NULL
    AND failure_code IS NULL
    AND completed_at IS NULL
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = workspace_connector_executions.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
        AND membership.role IN ('owner', 'admin')
    )
  );
DROP POLICY IF EXISTS workspace_connector_executions_complete_pending
  ON public.workspace_connector_executions;
CREATE POLICY workspace_connector_executions_complete_pending
  ON public.workspace_connector_executions FOR UPDATE TO app_runtime
  USING (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND current_setting('app.connector_execution_writer', true) = '1'
    AND status = 'pending'
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = workspace_connector_executions.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
        AND membership.role IN ('owner', 'admin')
    )
  )
  WITH CHECK (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND current_setting('app.connector_execution_writer', true) = '1'
    AND status IN ('executed', 'failed')
    AND completed_at IS NOT NULL
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = workspace_connector_executions.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
        AND membership.role IN ('owner', 'admin')
    )
  );

COMMIT;
