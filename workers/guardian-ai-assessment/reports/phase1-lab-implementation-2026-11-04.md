# Guardian Nexus — avance ejecutable de Fase 1

Fecha: 2026-11-04

HEAD de partida: `7b6aeb2c20db43ca0105eea411912b1549c83521`

Entorno: desarrollo local de Replit; sin publicación, despliegue, servicios externos ni datos de clientes.

## Trabajo implementado

### Revisión de los nueve `ALLOW` históricos

Se añadió una revisión reproducible, de solo análisis, del artefacto Qwen de
ocho perfiles ya existente. El código y el manifiesto comprueban exactamente
nueve casos históricos: dos de correo, cuatro de base de datos y tres de
lectura de facturas. Los nueve son lecturas sintéticas acotadas, con objetivo
de usuario coincidente y procedencia del contenido marcada como no confiable.
La clasificación es `scoped_synthetic_read_allow_not_general_safety_evidence`:
no se les etiqueta automáticamente como vulnerabilidades y tampoco se usa esta
muestra para afirmar seguridad general o eficacia contra prompt injection.

La fuente es el artefacto histórico
`generated-artifacts/guardian-qwen-policy-labs-e2e-v1.10.0.json`
(SHA-256 `2500000f271bdf95333a048551dab2d2b08fe0ee835434b336f5cffc3eed61ec`).
En ese artefacto constan 55 casos, 37 propuestas mediante marcadores Qwen
adaptados, cero `message.tool_calls` nativas y 18 casos sin propuesta. Esta
iteración no repitió inferencias ni cambió la política.

### SDK Python y consumo local de una aprobación

Se añadió `lib/guardian-agent-sdk-python`, versión `0.1.0`, cliente tipado
basado solo en biblioteca estándar durante la ejecución. Valida perfiles y
escenarios allow-listed, respuestas acotadas, JSON sin claves duplicadas,
URLs, redirecciones, decisiones de aprobación vinculadas a la propuesta,
reintentos idempotentes y errores redactados. Las decisiones de aprobación
son de un solo intento y no se reintentan automáticamente.

El paquete no tiene dependencias de ejecución (`Requires-Dist` vacío). La rueda
se construyó localmente con setuptools `80.9.0.post0`, se importó directamente
desde el archivo y contiene seis ficheros. Su SHA-256 es
`2cc45ee7ef083f0c09ad7938903f89f794e7ebd72cc6c97eb781b6bd059f803b`.
El módulo `pip` y la distribución `wheel` no están instalados en este entorno;
no se instalaron paquetes. La construcción con el backend local funcionó, pero
no se probó reproducibilidad bit a bit ni se generó un SBOM nuevo.

El E2E de aprobación ahora consume la API local desde un subproceso Python
asíncrono, enumera una propuesta de soporte y solicita una decisión aprobada.
Usa la identidad de prueba `x-guardian-test-user`, no una sesión Clerk.

### Kit de transferencia a un host Linux autorizado

Se añadieron plantillas de preflight, identidades PostgreSQL separadas,
configuración local de `pg_ident`/`pg_hba` y unidades de servicio de ejemplo en
`deployment/lab-as-code/`. Los scripts de provisión exigen confirmación
explícita, restringen la base de datos a nombres `guardian_lab_*`, no aceptan
contraseñas y verifican roles de login separados, `NOBYPASSRLS`, ausencia de
superusuario/propiedad de tablas y RLS forzado. El preflight comprueba UIDs,
GIDs, grupos, propietario/permisos del socket y denegación de acceso de la API.

El kit es una plantilla, no una instalación: no se crearon usuarios, roles,
permisos, unidades, bases ni procesos. Al ejecutarlo en este host, el preflight
terminó con `BLOCKED run_as_host_admin_for_identity_checks` (exit 1), antes de
inspeccionar o modificar el host. El requisito de identidad independiente y
broker Docker sigue sin acreditarse; el gate de evaluación no se abrió.

## Evidencia y pruebas

### E2E de aprobación sintética

Artefacto: `generated-artifacts/guardian-synthetic-approval-e2e.json`

SHA-256 del archivo: `b5ac74aa719fa6b4f614897693300e5653ace7cc2d4b232de003c97de5af1adf`

Hash de evidencia del E2E: `76b7cd37bebaddb52ab99ad904a3ca231b2a917ce3c08172ddc1628e7d376e44`
Hashes de las dos evidencias de aprobación:
`39a221adac8374cc3917df1afc239d34409195dd469c3ff975bec0b4bdc4a897`,
`8504f5bd1cec1893de29e60f2c5ffdc1c0a2158a2a486e302ca90f8367901117`.

Resultado **1/1**, con cinco solicitudes sintéticas persistidas: dos aprobadas
y simuladas una vez, una denegada sin simulación, una caducada sin simulación
y una prueba del cliente SDK Python. Se verificaron ganador único en carrera,
rechazo de replay, modificación del vínculo, cross-tenant, autoaprobación,
rol viewer y revocación del rol de aprobación. Tras la revocación, el API
respondió 403 y la propuesta permaneció pendiente sin simulación.

El artefacto registra `modelInference=false`,
`source=deterministic_fixture_worker_harness`,
`authenticationMode=synthetic_test_header`, `brokerUsed=false`,
`dockerCommandRequestedByHarness=false` y `externalEffects=false`. No es una
evaluación Qwen ni una sesión Clerk real. La ruta normal de evaluación continúa
cerrada cuando el broker no está disponible.

### Matriz de validación ejecutada en serie

| Área | Resultado | Alcance |
|---|---:|---|
| Worker Python | 160/160 | Todas las pruebas salvo `test_corpus_validation.py`, que requiere Garak ausente; no se instaló |
| Guardas del kit host | 4/4 | Repetidas después del último cambio del preflight; shell syntax incluido |
| API | 74/74 | Incluye RLS, RBAC, cola, idempotencia y contrato del broker |
| API + aprobación | 1/1 | E2E local sintético anterior; modelo falso y sin broker |
| SDK TypeScript | 13/13 | Contratos, autenticación, evidencia y aprobación |
| SDK Python | 8/8 | Unitarias y una comprobación de redirección solo loopback |
| UI integración | 8/8 | Componentes e informes usando artefactos de laboratorio existentes |
| Typecheck raíz | Pasó | Incluye web, API, scripts y referencias de librerías |
| Build API | Pasó | Bundling local |
| Build SDK TypeScript | Pasó | `tsc` |
| Typecheck/build web | Pasaron | Build con advertencia de sourcemap de `tooltip.tsx` y chunk JS >500 kB |
| Rueda Python | Pasó | Backend setuptools local; importación desde la rueda verificada |

El primer intento de ejecutar la prueba de componentes con `tsx` desde la raíz
no resolvió el alias Vite. Se ejecutó con el `tsconfig` del web y terminó 8/8;
no hizo falta cambiar el diseño ni el código de UI. El primer E2E bloqueaba el
bucle del servidor al usar un subproceso síncrono; se sustituyó por `spawn`
asíncrono con timeout y límite de salida, y el E2E pasó.

## Estado de objetivos y límites

| Estado | Alcance |
|---|---|
| **COMPLETO en Replit** | Revisión reproducible de los nueve `ALLOW` históricos; SDK Python sin dependencias runtime, empaquetado e importado; consumo de una aprobación sintética desde el SDK por la API local; pruebas seriales indicadas arriba; kit de transferencia y sus guardas estáticas. |
| **BLOQUEADO POR HOST** | Inferencia Qwen nueva y ejecución Docker aislada. El preflight anterior detectó socket Docker escribible por el UID compartido; el runner permanece fail-closed. El preflight del kit requiere permisos de administrador para verificar ambas identidades. No se lanzó Docker ni se elevaron privilegios. |
| **PENDIENTE** | Acreditar broker/API con UID y logins DB distintos en un host autorizado; sesión Clerk real; Garak en este host; nuevo SBOM/OSV; resolución legal de `langdetect`; verificación IPv6 en dual-stack. |

Las ocho verticales Qwen, los ocho fixtures, Policy Engine, RLS/RBAC/Clerk,
cola, límites Docker, UI visual y evidencias históricas se conservaron sin
cambios. No se conectaron sistemas ni se ejecutaron acciones externas.

Antes de pilotos con clientes siguen siendo bloqueantes el aislamiento real del
broker/API y las credenciales de DB separadas, además de revisión de
dependencias/licencias, un host IPv6 compatible cuando se requiera esa prueba
y validación de autenticación con una sesión Clerk de desarrollo autorizada.
