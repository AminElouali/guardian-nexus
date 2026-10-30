import pg from "pg";

if (
  process.env.NODE_ENV === "production" ||
  process.env.REPLIT_DEPLOYMENT === "1" ||
  process.env.ALLOW_DEV_DB_ROLE_BOOTSTRAP !== "true"
) {
  throw new Error(
    "Refusing database role bootstrap; run explicitly against development only.",
  );
}

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL must be set for the development database.");
}

const client = new pg.Client({ connectionString: process.env.DATABASE_URL });

try {
  await client.connect();
  const mode = process.argv[2] ?? "verify";
  if (mode === "harden") {
    await client.query(`
      ALTER ROLE app_runtime
        NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
        NOINHERIT NOREPLICATION NOBYPASSRLS;
    `);
  } else if (mode === "grant") {
    await client.query(`
      GRANT USAGE ON SCHEMA public TO app_runtime;
      GRANT SELECT, INSERT, UPDATE, DELETE
        ON TABLE public.workspaces,
                 public.workspace_memberships,
                 public.assets,
                 public.workspace_monthly_usage,
                 public.workspace_audit_events
        TO app_runtime;
    `);
  } else if (mode !== "verify") {
    throw new Error("Expected mode 'harden', 'verify' or 'grant'.");
  }

  const { rows } = await client.query(`
    SELECT rolname, rolsuper, rolbypassrls, rolcanlogin, rolcreatedb, rolcreaterole
    FROM pg_roles
    WHERE rolname = 'app_runtime'
  `);
  const role = rows[0];
  if (
    !role ||
    role.rolsuper ||
    role.rolbypassrls ||
    role.rolcanlogin ||
    role.rolcreatedb ||
    role.rolcreaterole
  ) {
    throw new Error("app_runtime failed the restricted-role checks.");
  }

  console.log(
    mode === "grant"
      ? "Development app_runtime role grants are ready."
      : "Development app_runtime role passed restricted-role checks.",
  );
} finally {
  await client.end();
}
