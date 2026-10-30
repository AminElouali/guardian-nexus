// The API must never inherit Replit's privileged migration/admin connection.
delete process.env.DATABASE_URL;
delete process.env.PGUSER;
delete process.env.PGPASSWORD;
