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
  await client.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_runtime') THEN
        CREATE ROLE app_runtime
          NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
          NOINHERIT NOREPLICATION NOBYPASSRLS;
      END IF;
    END
    $$;
  `);
  await client.query(`
    ALTER ROLE app_runtime
      NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
      NOINHERIT NOREPLICATION NOBYPASSRLS;
  `);
  await client.query(`
    GRANT USAGE ON SCHEMA public TO app_runtime;
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_runtime;
    GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_runtime;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public
      GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_runtime;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public
      GRANT USAGE, SELECT ON SEQUENCES TO app_runtime;
  `);

  const { rows } = await client.query(`
    SELECT rolname, rolsuper, rolbypassrls, rolcanlogin
    FROM pg_roles
    WHERE rolname = 'app_runtime'
  `);
  const role = rows[0];
  if (
    !role ||
    role.rolsuper ||
    role.rolbypassrls ||
    role.rolcanlogin
  ) {
    throw new Error("app_runtime failed the restricted-role checks.");
  }

  console.log("Development app_runtime role and table grants are ready.");
} finally {
  await client.end();
}
