-- Guardian Nexus migration 0008: make workspace audit append-only for runtime
-- and require active-workspace membership to read the workspace roster.
BEGIN;

CREATE OR REPLACE FUNCTION public.workspace_current_user_is_member(
  target_workspace_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
SET row_security = off
AS $function$
  SELECT EXISTS (
    SELECT 1
    FROM public.workspace_memberships AS membership
    WHERE membership.workspace_id = target_workspace_id
      AND membership.user_id = NULLIF(current_setting('app.user_id', true), '')
  )
$function$;
REVOKE ALL ON FUNCTION public.workspace_current_user_is_member(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.workspace_current_user_is_member(uuid) FROM app_runtime;
GRANT EXECUTE ON FUNCTION public.workspace_current_user_is_member(uuid) TO app_runtime;

REVOKE ALL PRIVILEGES ON TABLE public.workspace_audit_events FROM app_runtime;
REVOKE SELECT (
  id, workspace_id, actor_user_id, action, resource_type, resource_id,
  metadata, created_at
), INSERT (
  id, workspace_id, actor_user_id, action, resource_type, resource_id,
  metadata, created_at
), UPDATE (
  id, workspace_id, actor_user_id, action, resource_type, resource_id,
  metadata, created_at
), REFERENCES (
  id, workspace_id, actor_user_id, action, resource_type, resource_id,
  metadata, created_at
) ON TABLE public.workspace_audit_events FROM app_runtime;
GRANT SELECT, INSERT ON TABLE public.workspace_audit_events TO app_runtime;

DROP POLICY IF EXISTS workspace_memberships_select_scoped
  ON public.workspace_memberships;
CREATE POLICY workspace_memberships_select_scoped
  ON public.workspace_memberships FOR SELECT TO app_runtime
  USING (
    user_id = NULLIF(current_setting('app.user_id', true), '')
    OR (
      workspace_id::text = NULLIF(current_setting('app.workspace_id', true), '')
      AND public.workspace_current_user_is_member(workspace_id)
    )
  );

COMMIT;
