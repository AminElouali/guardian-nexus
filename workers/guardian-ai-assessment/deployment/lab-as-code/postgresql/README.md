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

## Workflow portable de GitHub Actions

Se añadió `.github/workflows/postgres-approval-lab.yml` como job aislado y
reproducible. Este repositorio no tenía workflows de CI visibles al prepararlo;
no se ha comprobado si está conectado a GitHub ni si Actions está habilitado.
El workflow aún no se ha ejecutado.

Al ejecutarse en un runner GitHub-hosted, el job declara su propio servicio
PostgreSQL `postgres:16`, crea `guardian_approval_lab_ci`, aplica Drizzle, crea
los roles restringidos, aplica el SQL RLS, verifica los roles/grants y ejecuta
el E2E de aprobaciones persistentes. GitHub destruye el servicio al acabar el
job. No usa la DB de Replit, URLs de secrets ni servicios externos de base de
datos. El test sigue usando únicamente identidades/datos ficticios y su worker
Python determinista; no ejecuta Qwen ni el broker/worker de producción.

Antes de cada conexión, `verify-approval-lab-ci-target.ts` valida el workflow,
job, ID/intento/commit de ejecución, etapa, servicio, nombre de DB, usuario,
puerto y credencial derivada de esa ejecución. El E2E exige además que la URL
administrativa y la URL de `app_runtime_login` apunten al mismo destino exacto.
En contexto GitHub Actions, cualquier URL compartida, remota, con overrides o
que no coincida con el contrato del job falla cerrada; no hay fallback al guard
local de loopback. Las credenciales se derivan por ejecución, no se imprimen y
no se almacenan como secrets. La comprobación es un guard de configuración, no
una atestación criptográfica del proveedor de CI.

Para activarlo hace falta que el responsable suba el commit a un repositorio
GitHub con Actions habilitado (o dispare `workflow_dispatch`). No hay evidencia
de ejecución CI/PostgreSQL todavía; hasta que el job pase, persistencia, roles
efectivos y RLS siguen sin validación real.

El orden dentro del job es: guard contra la DB administrativa `postgres`,
creación de la DB dedicada, guard contra la DB dedicada, Drizzle `push`,
`harden`, aplicación del SQL RLS, grants, configuración del login de runtime,
verificación de roles, auditoría del catálogo RLS y, por último, el E2E gated.
Las contraseñas de servicio/runtime se derivan del ID, intento y SHA del run;
no provienen de variables de repo ni se imprimen. El guard requiere exactamente
esas credenciales, y durante la auditoría/E2E ambas URLs deben apuntar a
`127.0.0.1:5432/guardian_approval_lab_ci`.

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

El guard `isExplicitDisposableApprovalDatabase()` exige opt-in explícito,
`NODE_ENV=development`, no estar en despliegue, una URL PostgreSQL con host
literal `127.0.0.1` o `::1`, sin parámetros ni fragmento, y que el nombre
coincida exactamente con el nombre de laboratorio esperado. Eso evita destinos
remotos comunes, pero **no demuestra** que un puerto local no sea un túnel ni
que la instancia sea distinta de la DB compartida. Esa prueba depende de la
persona administradora del host. No se deben imprimir URLs, credenciales ni
valores de entorno.

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
