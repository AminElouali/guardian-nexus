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
  } else if (mode === "configure-login") {
    const password = process.env.APP_RUNTIME_DB_PASSWORD;
    if (!password) {
      throw new Error("APP_RUNTIME_DB_PASSWORD is not available to this development workflow.");
    }
    if (password.length < 32) {
      throw new Error("APP_RUNTIME_DB_PASSWORD must contain at least 32 characters.");
    }

    await client.query(`
      ALTER ROLE app_runtime
        NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
        NOINHERIT NOREPLICATION NOBYPASSRLS;
      GRANT USAGE ON SCHEMA public TO app_runtime;
      GRANT SELECT, INSERT, UPDATE, DELETE
        ON TABLE public.workspaces,
                 public.workspace_memberships,
                 public.assets,
                 public.workspace_monthly_usage,
                 public.workspace_audit_events
        TO app_runtime;
    `);

    const { rows: existingLoginRows } = await client.query(`
      SELECT 1 FROM pg_roles WHERE rolname = 'app_runtime_login'
    `);
    if (existingLoginRows.length === 0) {
      await client.query(`
        CREATE ROLE app_runtime_login
          LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
          NOINHERIT NOREPLICATION NOBYPASSRLS;
      `);
    }

    const { rows: quotedRows } = await client.query(
      "SELECT quote_literal($1) AS quoted_password",
      [password],
    );
    const quotedPassword = quotedRows[0]?.quoted_password;
    if (typeof quotedPassword !== "string") {
      throw new Error("Could not safely prepare the runtime database password.");
    }
    await client.query(`
      ALTER ROLE app_runtime_login
        WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
        NOINHERIT NOREPLICATION NOBYPASSRLS
        PASSWORD ${quotedPassword};
      GRANT app_runtime TO app_runtime_login WITH INHERIT FALSE, SET TRUE;
    `);

    const { rows: databaseRows } = await client.query(
      "SELECT quote_ident(current_database()) AS database_name",
    );
    const databaseName = databaseRows[0]?.database_name;
    if (typeof databaseName !== "string") {
      throw new Error("Could not determine the development database.");
    }
    await client.query(
      `GRANT CONNECT ON DATABASE ${databaseName} TO app_runtime_login`,
    );
  } else if (mode !== "verify") {
    if (mode !== "configure-login") {
      throw new Error(
        "Expected mode 'harden', 'verify', 'grant' or 'configure-login'.",
      );
    }
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

  if (mode === "configure-login" || mode === "verify") {
    const { rows: loginRows } = await client.query(`
      SELECT
        login.rolsuper,
        login.rolbypassrls,
        login.rolcanlogin,
        login.rolcreatedb,
        login.rolcreaterole,
        login.rolreplication,
        login.rolinherit,
        pg_has_role(login.oid, runtime.oid, 'MEMBER') AS is_runtime_member,
        pg_has_role(login.oid, runtime.oid, 'USAGE') AS inherits_runtime_privileges,
        (SELECT COUNT(*)::int
         FROM pg_auth_members AS memberships
         WHERE memberships.member = login.oid) AS membership_count,
        (SELECT bool_and(
           memberships.roleid = runtime.oid
           AND NOT memberships.admin_option
           AND NOT memberships.inherit_option
           AND memberships.set_option
         )
         FROM pg_auth_members AS memberships
         WHERE memberships.member = login.oid) AS membership_is_restricted,
        has_table_privilege(login.oid, 'public.assets', 'SELECT') AS direct_asset_read,
        has_table_privilege(login.oid, 'public.assets', 'INSERT') AS direct_asset_write
      FROM pg_roles AS login
      CROSS JOIN pg_roles AS runtime
      WHERE login.rolname = 'app_runtime_login'
        AND runtime.rolname = 'app_runtime'
    `);
    const login = loginRows[0];
    if (
      !login ||
      login.rolsuper ||
      login.rolbypassrls ||
      !login.rolcanlogin ||
      login.rolcreatedb ||
      login.rolcreaterole ||
      login.rolreplication ||
      login.rolinherit ||
      !login.is_runtime_member ||
      login.inherits_runtime_privileges ||
      login.membership_count !== 1 ||
      !login.membership_is_restricted ||
      login.direct_asset_read ||
      login.direct_asset_write
    ) {
      throw new Error("app_runtime_login failed the least-privilege checks.");
    }
  }

  console.log(
    mode === "grant"
      ? "Development app_runtime role grants are ready."
      : mode === "configure-login"
        ? "Development runtime login is configured and least-privileged."
        : "Development app_runtime role passed restricted-role checks.",
  );
} finally {
  await client.end();
}
