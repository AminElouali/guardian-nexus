# Correo y BBDD: atestación disponible para el runner Qwen — 2026-11-11

## Cambio

En el camino Qwen existente, la API construye el comando del contenedor para
`guardian-ai-assessment.qwen_policy_lab` y monta el código, modelo y wheelhouse.
El runner, sin embargo, valida la atestación firmada en
`/run/guardian-nexus/host-boundary-attestation.json` y la clave pública de
confianza en `/etc/guardian-nexus/host-boundary-attestor-ed25519.pem`. Esos
archivos no se entregaban al contenedor, por lo que no podía comprobar la
atestación antes de inicializar Qwen.

El constructor de argumentos Docker ahora agrega ambos archivos como bind
mounts de solo lectura al camino Qwen existente. La prueba focalizada confirma
para los perfiles de correo y bases de datos que:

- se conserva el comando existente de `qwen_policy_lab` por perfil;
- el contenedor mantiene `--network=none` y el usuario no privilegiado
  `65532:65532`;
- los archivos de atestación se montan en sus rutas esperadas, en modo
  `readonly`;
- no se añade ningún montaje del socket Docker.

La API continúa sin habilitar la cola mientras la identidad del broker no esté
verificada. La atestación ausente, inválida o mal vinculada sigue siendo un
bloqueo antes de cargar el modelo. Este cambio no ejecuta inferencia ni acredita
el aislamiento del host.

## Verificación ejecutada ahora

Todas las pruebas usaron respuestas sintéticas fijas o construyeron argumentos;
no cargaron Qwen ni lanzaron contenedores.

- API sandbox, `ai-assessment-sandbox.test.ts`: **8/8**.
- API evidencia v2, prueba focal de correo/BBDD: **1/1**.
- Worker Policy Lab, seis métodos unitarios seleccionados: **6/6**, cada uno
  ejecutado por separado:
  - `adapted_email_and_database_reads_require_policy_before_fixture_dispatch`
  - `all_email_database_adversarial_adapted_markers_are_policy_gated`
  - `email_and_database_abstention_never_runs_policy_or_dispatch`
  - `adversarial_proposals_require_policy_and_never_dispatch_across_origins_for_all_profiles`
  - `shared_tool_adapter_runs_only_after_allow_and_never_in_policy_off`
  - `remaining_profiles_adapted_markers_are_policy_gated_offline`
- Typecheck API: aprobado.
- `git diff --check`: aprobado.

No se ejecutaron inferencia Qwen, workers vivos, broker, Docker o socket,
PostgreSQL, servicios, red, migraciones, E2E ni despliegue. Los tests de Policy
usan dobles y datos ficticios; no son resultados de modelo.

## Estado y hashes

- `hostBoundaryReady` permanece cerrado/no acreditado; no se volvió a sondear.
- La disponibilidad de API/cola no fue cambiada.
- SHA-256 de `artifacts/api-server/src/lib/ai-assessment-sandbox.ts`:
  `79e5f402293ef6cb3bbbe09e2afb6b243744eaaef04b9622f6fef6c56a311fa7`
- SHA-256 de `artifacts/api-server/src/lib/ai-assessment-sandbox.test.ts`:
  `ec0e84636e8cc838d79d46ce9945737dc27c6865ca5c503e5871cba1a0b3fba3`

El siguiente requisito para activar el camino es una atestación independiente
actual, firmada y vinculada a los hashes vigentes, además de broker/API/worker
con identidades y permisos realmente separados. El siguiente perfil funcional
tras superar ese gate sigue siendo finanzas y su flujo de aprobación; no se
inició en este cambio.
