# PostgreSQL/RLS y aprobaciones: laboratorio desechable

**Estado en 2026-11-12: PREPARADO, NO EJECUTADO.** No se ha acreditado una
instancia PostgreSQL vacía y aislada para esta sesión; no se intentó conectar
ni detectar un servidor. En los workflows visibles no hay un servicio
PostgreSQL.

La documentación oficial consultada indica que Replit incluye una DB de
desarrollo por aplicación y una DB de producción al publicar, pero no una DB
adicional efímera/desechable para pruebas. La DB de desarrollo pertenece a este
mismo proyecto y no satisface el requisito de estar separada de la DB de
workflows/desarrollo. Referencias:

- [Development and production databases](https://docs.replit.com/features/data-and-storage/development-and-production)
- [SQL database](https://docs.replit.com/features/data-and-storage/sql-database)

Esta documentación y esos enlaces no son evidencia de RLS ni de persistencia
real.

## Workflow manual de GitHub Actions, limitado a `main`

`.github/workflows/postgres-approval-lab.yml` es un job aislado y reproducible,
pero solo se inicia mediante `workflow_dispatch`. No tiene disparadores `push`
ni `pull_request`. La condición del job requiere el repositorio canónico
`AminElouali/guardian-nexus`, `refs/heads/main` y una referencia de rama; si la
condición falla, el job —incluido su servicio PostgreSQL— no se crea. El
workflow aún no se ha ejecutado.

Al ejecutarse en un runner GitHub-hosted, el job declara su propio servicio
PostgreSQL `postgres:16`, crea `guardian_approval_lab_ci`, aplica Drizzle, crea
los roles restringidos, aplica el SQL RLS, verifica los roles/grants y ejecuta
el E2E de aprobaciones persistentes. GitHub destruye el servicio al acabar el
job. No usa la DB de Replit, URLs de secrets ni servicios externos de base de
datos. El test sigue usando únicamente identidades/datos ficticios y su worker
Python determinista; no ejecuta Qwen ni el broker/worker de producción.

Antes de las etapas de provisión, `verify-approval-lab-ci-target.ts` solicita un
token OIDC breve al endpoint que Actions proporciona al job. El auditor y el
E2E invocan el mismo guard justo antes de crear su pool. El verificador usa
únicamente el issuer y JWKS oficiales fijos de GitHub, exige
`RS256`, valida la firma y comprueba audiencia exclusiva, repositorio canónico,
evento `workflow_dispatch`, rama/ref `main`, `workflow_ref` exacto, workflow,
SHA del código, run ID/intento y vigencia. También exige `repository_id` y
`repository_owner_id` numéricos dentro del token firmado. Las URLs administrativas
y de `app_runtime_login` deben seguir apuntando al servicio PostgreSQL efímero
esperado. Marcadores derivados de variables de entorno ya no se aceptan como
prueba. El token, la URL de solicitud y las respuestas no se imprimen ni se
persisten. El job requiere `id-token: write`.

El auditor verifica OIDC antes de construir su `Pool`. El E2E verifica antes de
importar `@workspace/db`, que crea el pool de runtime al cargarse. Los tests
sintéticos usan claves TEST ONLY en memoria y un `fetch` simulado; ese seam no se
inyecta en los guards de producción y no puede abrir el gate por sí solo.

No hay un `repository_id` numérico fijado en una fuente local de confianza; por
ello se valida que el claim firmado exista y tenga formato numérico, pero el
valor no se compara con un ID inmutable previamente aprobado. El OIDC acredita
que GitHub firmó esos claims para el job, no que el host esté aislado, que RLS
sea semánticamente correcta, que las reglas de protección de `main` sean
suficientes ni que una persona concreta sea quien autorizó la ejecución. Esta
implementación no es una atestación del host ni una autorización para abrir los
gates de runtime.

Para activarlo hace falta que el commit esté en el repositorio GitHub canónico,
Actions esté habilitado y una persona autorizada inicie manualmente el
`workflow_dispatch` seleccionando `main`. Los artefactos de otras fuentes no
son aceptados por este workflow. El workflow sigue **PREPARADO_NO_EJECUTADO**:
no hay evidencia de ejecución CI/PostgreSQL; persistencia, roles efectivos y
RLS siguen sin validación real.

El orden dentro del job es: guard contra la DB administrativa `postgres`,
creación de la DB dedicada, guard contra la DB dedicada, Drizzle `push`,
`harden`, aplicación del SQL RLS, grants, configuración del login de runtime,
verificación de roles, auditoría del catálogo RLS y, por último, el E2E gated.
Los valores de conexión de servicio/runtime se derivan del ID, intento y SHA
públicos del run; no son secretos criptográficamente aleatorios, no provienen
de variables de repo ni se imprimen, y no deben reutilizarse. La seguridad de
esos valores depende de que solo existan dentro del servicio efímero del job. El
guard requiere exactamente esos valores, y durante la auditoría/E2E ambas URLs
deben apuntar a `127.0.0.1:5432/guardian_approval_lab_ci`.

### Informe del catálogo RLS

`artifacts/api-server/src/scripts/verify-rls-catalog.ts` ejecuta solo después
del guard CI exacto. Consulta únicamente catálogos PostgreSQL (`pg_class`,
`pg_policies`, `pg_roles`, `pg_auth_members`, `pg_has_role` y funciones de
privilegios); no selecciona filas de las tablas de aplicación. Produce
`guardian-postgres-rls-catalog-report.json` en el directorio temporal del
runner y el workflow lo sube como artefacto con retención de 14 días, incluso
si el chequeo falla.

La comparación deriva los nombres/tablas/comandos/roles de políticas del
esquema Drizzle y de `rls-policies.sql`; deriva grants y membresías del SQL de
provisionamiento existente. Comparte con `assertRlsRuntimeReady()` el contrato
de tablas y recuentos, y registra el hash de los archivos fuente. Falla si no
existen exactamente las 12 tablas/34 políticas esperadas, si owner/RLS
`ENABLE`/`FORCE`, owner distinto de `postgres` (el usuario que provisiona el
job), identidad de política, comando, modo permisivo, rol destino, forma de
`qual`/`with_check`, atributos de roles, membresías/`pg_has_role`, matriz de
privilegios de tabla o cualquier `UPDATE` por columna en las tres tablas
especiales no coincide. No invoca `assertRlsRuntimeReady()` durante la
auditoría: ese preflight intenta leer `result` de `ai_assessment_jobs` para
probar la restricción del worker, y el informe se limita deliberadamente a
catálogos sin filas de aplicación. El E2E separado del workflow continúa siendo
la validación de comportamiento.

El informe incluye las expresiones `qual` y `with_check` que devuelve
`pg_policies`, pero no afirma equivalencia semántica entre la expresión
deparseada por PostgreSQL y el SQL/Drizzle: no hay un AST canónico compartido
que permita compararlas de forma fiable. Por ello, una discrepancia semántica
requiere revisar esas expresiones o una validación de comportamiento adicional.
La salida contiene solo metadatos de catálogo y definiciones de políticas, y
hashes SHA-256 de esquema, SQL RLS, bootstrap y contrato de recuentos: no incluye
URLs, hosts, credenciales ni filas de aplicación.

## Barrera de seguridad

El test `artifacts/api-server/src/ai-assessment-synthetic-approval-e2e.test.ts`
escribe y elimina datos sintéticos. Solo puede ejecutarse después de que la
persona responsable del laboratorio confirme que:

- La instancia/cluster es nuevo, efímero, aislado y no contiene datos de clientes.
- La base es distinta de la utilizada por los workflows compartidos de Guardian
  Nexus; el test se ejecutará en un proceso puntual con conexión solo a la base
  de laboratorio. No se cambia `.replit` ni la configuración de los workflows.
- El endpoint local no es un túnel o proxy hacia una base compartida.
- El nombre es `guardian_approval_lab_<sufijo>` y la autoridad de la base permite
  crear y restringir los roles descritos abajo.

El guard local `isExplicitDisposableApprovalDatabase()` exige opt-in explícito,
`NODE_ENV=development`, no estar en despliegue, `DATABASE_URL` y
`APP_RUNTIME_DATABASE_URL` con el mismo host literal loopback, puerto, base
esperada y sin parámetros/fragmento. La URL runtime debe usar
`app_runtime_login`; se rechazan configuraciones fallback `PGHOST`/`PGPORT`/
`PGUSER`/`PGPASSWORD`/`PGDATABASE` y `APP_RUNTIME_DB_PASSWORD`. Esto evita
destinos remotos comunes o URLs admin/runtime divergentes, pero **no demuestra**
que un puerto local no sea un túnel ni que la instancia sea distinta de la DB
compartida. Esa prueba depende de la persona administradora del host. No se
deben imprimir URLs, credenciales ni valores de entorno.

## Preparación reproducible (no ejecutar hasta acreditar el destino)

Usar únicamente un proceso puntual cuyo entorno apunte a la base nueva; no
heredar ni reutilizar la conexión de la aplicación. Aplicar estos pasos en
orden:

1. La persona administradora provisiona la instancia y la DB vacías
   `guardian_approval_lab_<sufijo>` con un rol de administración limitado al
   laboratorio.
2. Crear el esquema con `pnpm --filter @workspace/db run push`. Es un cambio
   destructivo de esquema potencial; usarlo solo en esa DB vacía.
3. Endurecer/crear los roles de grupo:
   `pnpm --filter @workspace/db run harden-runtime-role:dev`. El modo `harden`
   crea o endurece `app_runtime` como `NOLOGIN`, `NOINHERIT` y
   `NOBYPASSRLS`, y prepara el rol de cola del worker con las mismas propiedades
   restrictivas.
4. Aplicar las políticas y grants idempotentes:
   `pnpm --filter @workspace/db run apply-rls-policies:dev`.
5. Otorgar solo los permisos declarados:
   `pnpm --filter @workspace/db run grant-runtime-role:dev`.
6. Configurar el login runtime con el mecanismo de secretos autorizado, sin
   copiar ni mostrar el valor:
   `pnpm --filter @workspace/db run configure-runtime-login:dev`.
7. Ejecutar `pnpm --filter @workspace/db run verify-runtime-role:dev` y exigir
   que termine correctamente. No continuar si roles, ownership, RLS o grants no
   coinciden con `assertRlsRuntimeReady()`.
8. Solo entonces, ejecutar el test de aprobación en el mismo entorno puntual:

   ```text
   pnpm --filter @workspace/api-server exec tsx --test src/ai-assessment-synthetic-approval-e2e.test.ts
   ```

   El proceso debe recibir el opt-in de laboratorio, el nombre exacto esperado
   y una conexión exclusivamente al destino acreditado. Si el guard omite el
   test o cualquier etapa falla, informar `SKIP`/fallo; no cambiar el gate para
   forzar éxito.

El test crea dos workspaces sintéticos y actores con roles distintos; ejercita
lecturas/decisiones entre tenants, autoaprobación, permisos de viewer, estados
pending/approved/denied/expired, revocación de rol, concurrencia, binding,
replay e idempotencia. La versión actual comprueba además los estados mediante
un pool de PostgreSQL nuevo. El arnés usa autenticación sintética y procesos
deterministas de fixture; **no es** inferencia Qwen, ejecución del broker ni
prueba de aislamiento del host. El test elimina los workspaces sintéticos, pero
no destruye la instancia: la eliminación final de la DB corresponde a la
persona administradora.

## Evidencia requerida para declarar Block A validado

- Conteo de las 12 tablas protegidas; `ENABLE` y `FORCE ROW LEVEL SECURITY`;
  predicados/policies efectivos y conteos esperados, no solo presencia de
  nombres.
- Informe de catálogo RLS del job temporal, con 12 tablas/34 políticas,
  propietarios, roles/membresías, privilegios efectivos y columnas actualizables;
  sus expresiones se revisan conforme a la limitación semántica indicada arriba.
- Roles `app_runtime`, `app_runtime_login`, `app_ai_assessment_worker` y login
  de worker segregados, sin `SUPERUSER`, `BYPASSRLS`, propiedad de tablas ni
  grants directos que eludan RLS.
- Pruebas positivas y negativas de lectura/escritura cruzada para los dos
  tenants y visibilidad correcta del rol worker de cola.
- Aprobaciones persistidas consultadas tras decisión desde una conexión nueva:
  binding de tenant/propuesta/actor/rol, expiración, replay, idempotencia,
  auditoría y transiciones sin dispatch en `pending`, `denied` o `expired`.
- Logs e informe sin URLs, contraseñas, tokens ni datos reales.

El estado actual solo acredita código y pruebas offline sintéticas. La conexión
a PostgreSQL, las policies y permisos efectivos, el comportamiento real entre
tenants y la persistencia E2E quedan pendientes hasta que exista la instancia
autorizada. Nada de esto acredita `hostBoundaryReady` ni habilita API/broker/
worker.
