# Bloqueo fail-closed del ejecutor local — 2026-11-03

## Alcance y resultado

Base: HEAD `0a668a289851913d1d2cd67ee3ec8c8acf64bd8f`, árbol limpio.

Se sacó el acceso de la API al módulo ejecutor: las rutas ahora usan un módulo
de admisión sin `child_process` que declara el broker no disponible, y el
arranque API no inicia el consumidor de la cola. Las funciones de inspección,
parada y lanzamiento dentro del ejecutor también exigen la precondición de
broker. La política de disponibilidad exige un rol broker, UID distinta de la
API, acceso al socket solo desde el broker e identidad PostgreSQL propia
verificada. Sin estas condiciones la API no marca perfiles como disponibles ni
acepta un trabajo nuevo.

Se confirmó en este host: el proceso corre como UID `1000`, grupo `1000`; el
socket Docker es `root:1000`, modo `0660`, y el proceso puede leerlo y escribirlo.
Por ello **la API conserva autoridad Docker a nivel del host**. No se cambiaron
permisos del socket/daemon ni se intentó elevar privilegios. El cambio bloquea
las rutas normales de consumo/lanzamiento desde la aplicación, pero no revoca
la capacidad Unix del proceso y no constituye separación de autoridad.

No se añadió un broker activo ni se conectó el grant HMAC al lanzamiento. El
grant existente sigue siendo preparación con pruebas unitarias; su consumo
durable y atómico en PostgreSQL, junto con credenciales de DB exclusivas del
broker, no están implementados/verificados. La comprobación positiva de la
frontera es una prueba unitaria con datos sintéticos, no prueba del host real.

## Evidencia y validación

- `pnpm --filter @workspace/api-server typecheck` — pasó.
- `pnpm --filter @workspace/api-server test` — **74/74**; incluye rechazo de
  disponibilidad/encolado sin broker, validación de grants, RLS y pruebas de
  acceso cruzado a jobs/workspaces.
- `sh workers/guardian-ai-assessment/scripts/run-local.sh --unit-tests` —
  **134/134**.
- SDK `test` — **13/13**; SDK `build` — pasó.
- UI TypeScript — pasó; integración de componentes — **8/8**.
  La primera invocación del test UI falló por un alias `@/components` no
  resuelto desde el tsconfig equivocado; con el tsconfig de la app pasó 7/8 y
  reveló una referencia obsoleta al JSON v1.9 ausente. Se actualizó la
  referencia al artefacto local v1.10 existente y el rerun pasó 8/8.
- Build API — pasó. Build UI — pasó con aviso existente de sourcemap y chunk
  de `683.58 kB`. `pnpm run typecheck` y `git diff --check` — pasaron.
- Workflow API reiniciado y escuchando en el puerto `8080`.
- El bundle API compilado mide `3.9 MB`; la búsqueda de marcadores del CLI
  Docker del worker en `dist/index.mjs` no encontró coincidencias. Esto es una
  comprobación de contenido del bundle, no de permisos del proceso.
- No se ejecutó E2E que lance Qwen/Garak en esta iteración: el guard ahora
  rechaza esa ejecución porque no existe identidad de broker verificada. No se
  atribuyen resultados nuevos de inferencia.
- Revisión local offline, sin repetir escaneo: SBOM de imagen
  `sbom.cdx.json` tiene 124 componentes (SHA-256
  `8eb49149a21afac04818f94ac0183eb799ed740b8f2254a9f63c453c279c5d97`);
  SBOM compuesto tiene 139 (SHA-256
  `2602cdf1fcff5a059e49086bf9c2251c536bcef80977faf9b22df7e07852331c`).
  El JSON OSV local conserva exit code `1`, SHA-256
  `c80e9efec40dbed890c691d33ac85cebe98dcd5aa646cedef7a3698ae326e6c2`.
  Son artefactos existentes del 2 de noviembre, no un escaneo nuevo ni prueba
  de explotabilidad/remediación. No hubo cambios de paquetes ni revisión nueva
  de licencias.

## Cambios funcionales, no remediaciones del host

- La API ya no inicia automáticamente el poller de trabajos.
- Los caminos locales de encolado/disponibilidad/lanzamiento fallan cerrados
  sin broker verificado; la ruta de solicitud comprueba disponibilidad antes
  de insertar el job.
- La comprobación pura y sus casos negativos verifican UID compartida, API con
  acceso al socket, socket ausente e identidad de DB sin verificar.
- El test de informe UI ahora consume la evidencia v1.10 local disponible en
  vez del archivo v1.9 que no existe. No se regeneró ni alteró evidencia Qwen.

Esto **no demuestra** que la API no pueda abrir el socket Docker; la comprobación
de permisos confirma lo contrario en el host actual. La separación real exige
un host donde se puedan usar identidades Unix distintas, ACL del socket
exclusivas para broker y un principal/credential PostgreSQL no legible por la
API. Hasta entonces no debe habilitarse el worker local desde esta API.

## No revalidados en este hito

No se repitió inferencia Qwen, E2E Docker, análisis OSV/SBOM, revisión de
licencias, sesión Clerk real ni prueba IPv6. Los resultados anteriores
permanecen históricos; no se presentan como nuevas verificaciones. IPv6,
Clerk, advisories/licencias y la autoridad Docker del host siguen pendientes.
