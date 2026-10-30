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

COMMIT;
