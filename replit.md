# EU Security Platform

Plataforma SaaS multi-tenant para inventario de activos y operaciones de seguridad de organizaciones europeas.

## Run & Operate

- `pnpm --filter @workspace/api-server run dev` — run the API server (port 5000)
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from the OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- Required env: `DATABASE_URL` — Postgres connection string

## Stack

- pnpm workspaces, Node.js 24, TypeScript 5.9
- API: Express 5
- DB: PostgreSQL + Drizzle ORM
- Validation: Zod (`zod/v4`), `drizzle-zod`
- API codegen: Orval (from OpenAPI spec)
- Build: esbuild (CJS bundle)

## Where things live

- `artifacts/eu-security-platform` — web app, Clerk sign-in, workspace onboarding and security console.
- `artifacts/api-server` — shared API, authentication middleware and tenant-scoped endpoints.
- `lib/api-spec/openapi.yaml` — API contract; regenerate clients after changes.
- `lib/db/src/schema/` — PostgreSQL schema for workspaces, memberships, assets and monthly usage.
- `docs/phase-1-and-enterprise-roadmap.md` — shipped scope, plan limits, deferred capabilities and recommended order.

## Architecture decisions

- Workspace membership and application roles are stored in PostgreSQL, not in user-editable browser state.
- Every tenant-scoped API operation verifies the Clerk user against the requested workspace and scopes the records to that workspace.
- Monthly AI/API/scan consumption is reserved atomically before trusted server-side work; provider calls must not be made directly from the browser.

## Product

- Phase 1 supports self-service account creation, owner-led workspace setup, basic roles, manual asset inventory and plan usage visibility.
- Connected cloud/security sources, actual findings, analysis jobs and enterprise identity features are intentionally deferred. See the roadmap document.

## User preferences

- Work in phases and stop for confirmation after each phase.
- The first phase implements tenant isolation and basic roles; enterprise capabilities should be documented before implementation.

## Gotchas

- Clerk browser auth uses same-origin session cookies. Keep the Clerk proxy before Express body parsers; do not add bearer-token transport to this web client.
- Do not expose an endpoint that lets a browser directly claim token or provider-API usage; reserve usage in trusted server-side connector/scan code.

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
