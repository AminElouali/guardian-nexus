# Auditor de catálogo RLS de desarrollo

`@workspace/api-server` ofrece `audit:development-rls-catalog`, un lector
independiente del guard OIDC del workflow CI. Lee el contrato versionado de
Drizzle, roles, bootstrap y `rls-policies.sql`; compara el catálogo real con
las 13 tablas, 36 políticas, roles, membresías, restricciones, índices,
columnas, RLS y privilegios declarados. Para `workspace_approval_ledger`
comprueba SELECT e INSERT por separado y rechaza privilegios adicionales,
incluidos privilegios UPDATE o REFERENCES por columna. MAINTAIN se comprueba
en PostgreSQL 17 o posterior.

El comando exige ambas opciones y no acepta modos de escritura:

```sh
pnpm --filter @workspace/api-server run audit:development-rls-catalog -- \
  --confirm-read-only \
  --expected-database=DB_NAME_CONFIRMED_OUT_OF_BAND
```

Antes de usarlo, una persona debe confirmar por un canal independiente el
nombre esperado de la base y que las credenciales de ejecución pertenecen a
esa base de desarrollo. La conexión se obtiene mediante el mismo pool que usa
la API (`APP_RUNTIME_DATABASE_URL` o la configuración runtime existente); no
se usa la conexión administrativa de Drizzle. El proceso abre una transacción
`READ ONLY`, compara el nombre internamente y comprueba que sesión y usuario
actual sean `app_runtime_login`. Se niega si la base no coincide, si no es
PostgreSQL 16+ o si no puede confirmar el modo de solo lectura.

El informe JSON incluye etapa, estado, versión principal, recuentos y códigos
fijos de discrepancia. No incluye nombres de base, host, puerto, URL,
credenciales, errores SQL sin sanitizar ni filas de aplicación. El auditor no
crea ni modifica objetos. La validación automatizada usa únicamente el
PostgreSQL efímero de `lab:local`; no se ejecuta automáticamente contra la
base de desarrollo de Replit.
