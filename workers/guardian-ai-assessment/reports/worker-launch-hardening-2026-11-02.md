# Endurecimiento del lanzamiento del worker — 2026-11-02

## Alcance

Hito local de desarrollo sobre los perfiles Garak/GVE y Qwen/GVE existentes.
No se reconstruyeron ni promovieron imágenes; no se modificaron producción,
clientes, despliegues ni datos reales; no se descargaron paquetes ni se habilitó
egress. La API sigue necesitando acceso al daemon Docker del entorno para lanzar
contenedores.

## Controles implementados

- `profile-image-lock.json` fija por perfil la etiqueta local, el image ID
  inmutable `sha256:…`, las etiquetas OCI esperadas y el SHA-256 de su
  Dockerfile. El worker vuelve a comprobar hashes de fuentes, inspecciona la
  imagen en el chequeo de disponibilidad y justo antes de ejecutar, valida ID y
  etiquetas y pasa el ID inmutable a `docker run`. Se usa `--pull=never`. Los
  perfiles y sus comandos son una lista cerrada; la solicitud no puede escoger
  una imagen, etiqueta, entrypoint o comando.
- Rechazos fail-closed comprobados para ID ausente/incorrecto, imagen
  retaggeada, etiquetas incorrectas/ausentes, lock manipulado y cambios entre
  solicitud y ejecución. En los casos rechazados el callback de lanzamiento no
  se invoca. Si una etiqueta cambia después de inspeccionarla, `docker run`
  conserva el image ID previamente validado.
- El entorno de cada proceso `docker` iniciado por la API solo contiene `PATH`,
  `HOME` y `DOCKER_CONFIG` apuntando a un directorio temporal único, propiedad
  del proceso y con permisos `0700`; no hereda `DOCKER_HOST`, contexto Docker
  del usuario ni otras variables de entorno. El directorio se elimina al salir
  el proceso. En una prueba local con `HOME=/tmp` y `DOCKER_CONFIG` no personal,
  `docker context show` devolvió `default` y `docker info` mostró
  `name=seccomp,profile=builtin`.
- Contratos comprobados para los dos perfiles: `network=none`, `--pull=never`,
  UID/GID 65532, rootfs de solo lectura, `cap-drop=ALL`,
  `no-new-privileges`, 64 PIDs, CPU/memoria y swap limitados, `/tmp` temporal
  `noexec`, mounts de Qwen/modelo/código/manifest/wheels en solo lectura, y
  ausencia de montaje de `docker.sock`. El runtime mantiene límites de salida
  de 64 KiB y duración: Garak 135 s; Qwen 180 s.
- No se añadió un perfil seccomp propio. La prueba inspecciona el estado real del
  proceso dentro de cada imagen; ambas devolvieron `Seccomp: 2` y
  `NoNewPrivs: 1`. Esto verifica que el filtro integrado del daemon se aplica en
  este host, no que exista una política seccomp personalizada o idéntica en
  otros hosts.
- El endpoint de solicitud de evaluaciones limita JSON a 8192 bytes. El exceso
  obtiene `413` con un cuerpo JSON fijo y no crea un job; el test de integración
  consulta también la base de desarrollo para comprobarlo.

## Identidad local comprobada

| Perfil | Image ID | Etiqueta de perfil | Estado |
|---|---|---|---|
| Garak/GVE | `sha256:88df6b6808fd6169ece85d229cfffeb366c0f4356bad4d5c626efa3b8885511d` | `garak-gve-v1` | Imagen local fijada |
| Qwen/GVE | `sha256:884d4f7bc6c11e03f6ced5cfcc9e88e7a8043d85923429f1a3a181953f07830f` | `qwen-gve-v1` | Imagen local fijada |

Los Dockerfiles están fijados por sus hashes en el lock. Estas imágenes son
construcciones locales sin `RepoDigest` de registro. Las etiquetas y los hashes
locales no constituyen una atestación firmada ni prueban por sí solos la
procedencia completa de la cadena de suministro; el lock declara
`signedAttestation: false`.

## Pruebas ejecutadas

- `python3 workers/guardian-ai-assessment/tests/verify_docker_seccomp.py`:
  pasó en ambas imágenes; confirmó image ID y etiquetas fijados,
  `network=none`, `Seccomp=2` y `NoNewPrivs=1`.
- Worker Python bajo la imagen Garak fijada por ID, sin red, rootfs de solo
  lectura, UID no-root, capacidades eliminadas, límites y `/tmp` `noexec`:
  **87/87**. Este conteo corresponde a la suite descubierta en esta ejecución;
  no se reutiliza el conteo histórico 98/98.
- API/security tras dejar terminar los trabajos E2E: **41/41**, incluyendo
  RLS/RBAC, aislamiento tenant, leases, recuperación e idempotencia.
- E2E completo previo a la última reducción del entorno del proceso Docker:
  **3/3** (Garak/GVE, Qwen local, tool calls nativas y selección autónoma en las
  pruebas correspondientes); integración de panel/exportación **5/5**.
- E2E dirigido después de reducir el entorno del proceso Docker a valores
  locales no personales: **1/1**, con evaluación real Garak y Qwen por la cola,
  persistencia/API, autorización de tenant y 413 sin fila creada.
- Pruebas nuevas de contrato del launcher y límite JSON: **6/6**. Se verifican
  rechazo antes del callback de Docker, pinning por image ID, flags de ambos
  perfiles y respuesta 413.
- `pnpm --filter @workspace/api-server run typecheck`: pasó.
- `pnpm --filter @workspace/api-server run build`: pasó.
- `PORT=8081 BASE_PATH=/__mockup pnpm run build`: pasó typecheck y builds del
  API, web y mockup. Vite conservó el aviso no bloqueante de bundle web de
  649,34 kB.
- `python3 -m py_compile workers/guardian-ai-assessment/tests/verify_docker_seccomp.py`
  y `git diff --check`: pasaron.

Una ejecución inicial de la suite API se solapó con un job E2E que reclamaba la
misma cola PostgreSQL de desarrollo y falló únicamente la aserción de un lease
recuperado (0 frente a 1). Se observó el contenedor Qwen activo; al terminar el
E2E, la suite serial pasó 41/41. No se cambió la aserción ni el comportamiento
de recuperación.

## Límites y riesgo residual

- El proceso API sigue teniendo capacidad de llamar al daemon Docker del host.
  El cambio restringe el entorno del CLI y fija argumentos/perfiles/imágenes,
  pero no crea una frontera de privilegios frente a una eventual toma del
  proceso API. Para reducir esa autoridad materialmente hace falta un broker de
  ejecución aislado o un daemon rootless con permisos acotados, fuera del
  alcance seguro de este hito.
- No se probó una carrera contra un daemon concurrentemente retaggeado; la
  propiedad se verifica mediante pruebas unitarias del gate compartido y uso
  efectivo del image ID inmutable en el E2E. Docker no puede resolver un ID
  inexistente mediante pull porque se conserva `--pull=never`.
- No se ejecutaron pruebas nuevas de salida IPv4/UDP/DNS o IPv6 en este hito.
  El aislamiento configurado sigue en `network=none`; IPv6 permanece
  **NO VERIFICADO** por `kernel_protocol_unavailable` en el entorno anterior.
- No se vuelve a escanear OSV ni se declara remediación de las vulnerabilidades
  históricas de Debian/Python. Licencias, procedencia completa de wheels,
  reproducibilidad de imagen/rueda y validación legal siguen siendo pendientes.
- La suite E2E usa identidades de prueba locales, no una nueva sesión Clerk real
  en navegador. El código de Clerk no se modificó.

## Archivos de código añadidos o modificados

- `artifacts/api-server/package.json`
- `artifacts/api-server/src/app.ts`
- `artifacts/api-server/src/ai-assessment-e2e.test.ts`
- `artifacts/api-server/src/security.test.ts`
- `artifacts/api-server/src/lib/ai-assessment-worker.ts`
- `artifacts/api-server/src/lib/ai-assessment-sandbox.ts`
- `artifacts/api-server/src/lib/ai-assessment-sandbox.test.ts`
- `artifacts/api-server/src/middlewares/ai-assessment-json.ts`
- `artifacts/api-server/src/middlewares/ai-assessment-json.test.ts`
- `workers/guardian-ai-assessment/profile-image-lock.json`
- `workers/guardian-ai-assessment/tests/verify_docker_seccomp.py`

## SHA-256 de los artefactos principales

- `artifacts/api-server/src/lib/ai-assessment-sandbox.ts`:
  `03c9f89e6bc337b5875e5c07dea5e2da7f5d154d676425fdf1582ce75f4eb679`
- `artifacts/api-server/src/lib/ai-assessment-sandbox.test.ts`:
  `0dc4ea7214752646c98cc571016d5e232276196b1f11818e350b23689bc4f638`
- `artifacts/api-server/src/lib/ai-assessment-worker.ts`:
  `1100c406acc370fba709b5fa95faec201d6c51732b11f67b2aec340c7e3f9b9c`
- `artifacts/api-server/src/app.ts`:
  `3b512575a5ba15348637a334c922d5bc7652201e18662dd778765ab1359f8d57`
- `artifacts/api-server/src/middlewares/ai-assessment-json.ts`:
  `24e03351855ab4e3f0b6c2701c41385d463f41b8d5bc7862c4199f2cad5c0dfe`
- `artifacts/api-server/src/middlewares/ai-assessment-json.test.ts`:
  `f40e3f26f1b2e9b4f405f8f72c7dd3687985e4672fb38488ef9a2ef533d634d3`
- `workers/guardian-ai-assessment/profile-image-lock.json`:
  `65abf26937994966353494e1dde87cae42cbf82246282b072c5554e907dcde6c`
- `workers/guardian-ai-assessment/tests/verify_docker_seccomp.py`:
  `baa3746338e04b4d26d434f25ef4838732d72610829e9a3ec2d50cddfe8ef2ff`
- Dockerfile Garak: `2af214022f54dd9896ce2dbe6787941f1b4fdd610621bc9e7132a28ab04295ef`.
- Dockerfile Qwen: `7e57aca56509e08a486389e16782135faf27b08a13a88a6fd245c675f38e39be`.
