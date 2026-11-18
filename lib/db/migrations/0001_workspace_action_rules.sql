-- Guardian Nexus migration 0001: workspace-scoped, versioned action rules.
-- Apply once to a tenant database after roles and workspaces exist.
BEGIN;

CREATE TABLE public.workspace_action_rule_versions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL
    REFERENCES public.workspaces(id) ON DELETE CASCADE,
  action_type text NOT NULL
    CHECK (action_type IN (
      'guardian.synthetic.support.refund.v1',
      'guardian.synthetic.finance.bank-change.v1',
      'guardian.support.reply.send.v1',
      'guardian.email.send.external.v1'
    )),
  version integer NOT NULL CHECK (version > 0),
  rule_document jsonb NOT NULL
    CHECK (jsonb_typeof(rule_document) = 'object'),
  created_by_user_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX workspace_action_rule_versions_workspace_action_version_uidx
  ON public.workspace_action_rule_versions (workspace_id, action_type, version);
CREATE INDEX workspace_action_rule_versions_workspace_created_idx
  ON public.workspace_action_rule_versions (workspace_id, created_at);

CREATE TABLE public.workspace_action_rule_heads (
  workspace_id uuid NOT NULL
    REFERENCES public.workspaces(id) ON DELETE CASCADE,
  action_type text NOT NULL
    CHECK (action_type IN (
      'guardian.synthetic.support.refund.v1',
      'guardian.synthetic.finance.bank-change.v1',
      'guardian.support.reply.send.v1',
      'guardian.email.send.external.v1'
    )),
  active_version integer,
  draft_version integer,
  updated_by_user_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT workspace_action_rule_heads_pkey
    PRIMARY KEY (workspace_id, action_type),
  CONSTRAINT workspace_action_rule_heads_active_version_fk
    FOREIGN KEY (workspace_id, action_type, active_version)
    REFERENCES public.workspace_action_rule_versions
      (workspace_id, action_type, version),
  CONSTRAINT workspace_action_rule_heads_draft_version_fk
    FOREIGN KEY (workspace_id, action_type, draft_version)
    REFERENCES public.workspace_action_rule_versions
      (workspace_id, action_type, version),
  CONSTRAINT workspace_action_rule_heads_versions_check
    CHECK (
      (active_version IS NULL OR active_version > 0)
      AND (draft_version IS NULL OR draft_version > 0)
    ),
  CONSTRAINT workspace_action_rule_heads_version_state_check
    CHECK (
      active_version IS NULL
      OR draft_version IS NULL
      OR active_version <> draft_version
    )
);

REVOKE ALL PRIVILEGES ON TABLE public.workspace_action_rule_versions
  FROM app_runtime;
GRANT SELECT, INSERT ON TABLE public.workspace_action_rule_versions TO app_runtime;
GRANT SELECT, INSERT, UPDATE ON TABLE public.workspace_action_rule_heads
  TO app_runtime;
ALTER TABLE public.workspace_action_rule_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_action_rule_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_action_rule_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_action_rule_heads FORCE ROW LEVEL SECURITY;

CREATE POLICY workspace_action_rule_versions_select_member
  ON public.workspace_action_rule_versions FOR SELECT TO app_runtime
  USING (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = workspace_action_rule_versions.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
    )
  );
CREATE POLICY workspace_action_rule_versions_insert_admin
  ON public.workspace_action_rule_versions FOR INSERT TO app_runtime
  WITH CHECK (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND created_by_user_id = NULLIF(current_setting('app.user_id', true), '')
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = workspace_action_rule_versions.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
        AND membership.role IN ('owner', 'admin')
    )
  );
CREATE POLICY workspace_action_rule_heads_select_member
  ON public.workspace_action_rule_heads FOR SELECT TO app_runtime
  USING (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = workspace_action_rule_heads.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
    )
  );
CREATE POLICY workspace_action_rule_heads_insert_admin
  ON public.workspace_action_rule_heads FOR INSERT TO app_runtime
  WITH CHECK (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND updated_by_user_id = NULLIF(current_setting('app.user_id', true), '')
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = workspace_action_rule_heads.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
        AND membership.role IN ('owner', 'admin')
    )
  );
CREATE POLICY workspace_action_rule_heads_update_admin
  ON public.workspace_action_rule_heads FOR UPDATE TO app_runtime
  USING (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = workspace_action_rule_heads.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
        AND membership.role IN ('owner', 'admin')
    )
  )
  WITH CHECK (
    workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND updated_by_user_id = NULLIF(current_setting('app.user_id', true), '')
    AND EXISTS (
      SELECT 1 FROM public.workspace_memberships AS membership
      WHERE membership.workspace_id = workspace_action_rule_heads.workspace_id
        AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
        AND membership.role IN ('owner', 'admin')
    )
  );

COMMIT;
