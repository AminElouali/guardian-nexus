-- Guardian Nexus migration 0002: per-workspace agent identities.
-- The bearer credential is never stored here; only its SHA-256 is persisted.
BEGIN;

CREATE TABLE public.workspace_agents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL
    REFERENCES public.workspaces(id) ON DELETE CASCADE,
  display_name text NOT NULL
    CHECK (length(btrim(display_name)) BETWEEN 1 AND 120),
  principal_user_id text NOT NULL,
  credential_sha256 text NOT NULL UNIQUE
    CHECK (credential_sha256 ~ '^[a-f0-9]{64}$'),
  credential_version integer NOT NULL DEFAULT 1
    CHECK (credential_version > 0),
  created_by_user_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  last_used_at timestamptz
);
CREATE INDEX workspace_agents_workspace_created_idx
  ON public.workspace_agents (workspace_id, created_at);

GRANT SELECT, INSERT, UPDATE ON TABLE public.workspace_agents TO app_runtime;
ALTER TABLE public.workspace_agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_agents FORCE ROW LEVEL SECURITY;

CREATE POLICY workspace_agents_select_admin
  ON public.workspace_agents FOR SELECT TO app_runtime
  USING (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = workspace_agents.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
        AND membership.role IN ('owner', 'admin')
    )
  );
CREATE POLICY workspace_agents_authenticate_exact_credential
  ON public.workspace_agents FOR SELECT TO app_runtime
  USING (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND credential_sha256 =
      NULLIF(current_setting('app.agent_credential_sha256', true), '')
    AND revoked_at IS NULL
  );
CREATE POLICY workspace_agents_insert_admin
  ON public.workspace_agents FOR INSERT TO app_runtime
  WITH CHECK (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND created_by_user_id = NULLIF(current_setting('app.user_id', true), '')
    AND principal_user_id = NULLIF(current_setting('app.user_id', true), '')
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = workspace_agents.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
        AND membership.role IN ('owner', 'admin')
    )
  );
CREATE POLICY workspace_agents_update_admin
  ON public.workspace_agents FOR UPDATE TO app_runtime
  USING (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = workspace_agents.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
        AND membership.role IN ('owner', 'admin')
    )
  )
  WITH CHECK (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = workspace_agents.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
        AND membership.role IN ('owner', 'admin')
    )
  );

COMMIT;
