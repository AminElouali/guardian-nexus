import { readFile } from "node:fs/promises";
import pg from "pg";

if (
  process.env.NODE_ENV === "production" ||
  process.env.REPLIT_DEPLOYMENT === "1" ||
  process.env.ALLOW_DEV_DB_ROLE_BOOTSTRAP !== "true"
) {
  throw new Error(
    "Refusing RLS policy update; run explicitly against development only.",
  );
}

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL must be set for the development database.");
}

const client = new pg.Client({ connectionString: process.env.DATABASE_URL });
try {
  await client.connect();
  const policies = await readFile(
    new URL("../sql/rls-policies.sql", import.meta.url),
    "utf8",
  );
  await client.query(policies);
  console.log("Development RLS policies and forced RLS are applied.");
} finally {
  await client.end();
}
