# Cobertura offline de argumentos Qwen para ocho perfiles — 2026-11-11

## Alcance

Se amplió la prueba existente del constructor de argumentos en
`artifacts/api-server/src/lib/ai-assessment-sandbox.test.ts` para los perfiles
de correo, bases de datos, finanzas, programación, atención al cliente,
navegador, infraestructura y multiagente.

La prueba solo construye arrays de argumentos; no invoca Docker ni inicia
contenedores. Comprueba en cada perfil los mounts de atestación y clave pública
en modo `readonly`, `--network=none`, usuario `65532:65532`, filesystem
read-only, capacidades eliminadas, `no-new-privileges`, ausencia de modo
privilegiado y ausencia de argumentos que incluyan `docker.sock`.

La inspección también encontró que paths Qwen ausentes o vacíos podían
interpolarse en los argumentos. Se añadió una validación acotada:
los cuatro paths Qwen deben ser strings absolutos no vacíos y no pueden incluir
separadores de mounts ni NUL. Perfiles desconocidos y configuraciones
incompletas fallan con error antes de devolver argumentos.

La prueba compara la disponibilidad del worker antes y después de construir
argumentos. Sigue `disabled` con
`assessment_broker_identity_unverified`. El constructor no establece ni expone
`hostBoundaryReady` o `integratedAssessmentReady`; no se modifica ninguna
readiness. Los ocho fixtures baseline y las categorías de evidencia Qwen no
cambiaron.

## Verificación ejecutada en esta iteración

En serie:

1. `pnpm --filter @workspace/api-server exec tsx --test src/lib/ai-assessment-sandbox.test.ts`
   — **9/9 aprobadas**, cero fallos y cero omitidas.
2. `pnpm --filter @workspace/api-server run typecheck` — **aprobado**.
3. `git diff --check` — **aprobado**.

No se ejecutaron Qwen, workers, broker, Docker, PostgreSQL, cola, E2E,
servicios externos, despliegues ni conexiones de red. No se abrió ni inspeccionó
el socket Docker. Estas pruebas verifican argumentos y validación de
configuración, no aislamiento real ni inferencia.

## Hashes SHA-256

- `artifacts/api-server/src/lib/ai-assessment-sandbox.ts`:
  `b73ba1d09711fb0cbb869ab890569bdcd1e093f2855eab131a4db130ee16db5c`
- `artifacts/api-server/src/lib/ai-assessment-sandbox.test.ts`:
  `16473225e64f31c3365c85ef10e29cbcc24487530bd06310204e0316148b4f3b`

## Bloqueo y siguiente paso

Este cambio no desbloquea Qwen. La última evidencia host registrada mantiene
`hostBoundaryReady=false`; falta una atestación independiente, actual y ligada
a los hashes vigentes, además de identidades/permisos API, broker y worker
verificados. Mantener la cola cerrada hasta acreditar esos requisitos.

Tras recibir y validar esa atestación por un verificador independiente, el
siguiente recorrido funcional debe comenzar por correo y después bases de datos.
Las aprobaciones persistentes siguen requiriendo una PostgreSQL de laboratorio
explícitamente desechable y pruebas RLS en ejecución.
