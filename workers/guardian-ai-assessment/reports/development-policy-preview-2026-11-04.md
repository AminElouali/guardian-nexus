# Guardian Nexus — previsualización determinista del laboratorio

Fecha: 2026-11-04  
Alcance: desarrollo local; sin publicación, despliegue ni cambios en producción.  
HEAD inicial: `ab5f8a7c4fed8cb1517c515297c9d6cd0c74eb41`.

## Resultado

Se añadió una previsualización fresca de las decisiones deterministas existentes
para los ocho perfiles sintéticos, visible desde la página de evaluaciones. La
ruta es:

`POST /workspaces/{workspaceId}/ai-security-assessments/lab/policy-preview`

La UI presenta los casos, procedencia, decisión Policy ON, simulación ficticia
permitida y contrafactual Policy OFF sin crear un job. El selector de perfil
solo permite los IDs del catálogo; el cuerpo HTTP acepta únicamente `profileId`.
La ruta responde solo en desarrollo, exige el contexto autenticado del
workspace y owner/admin, tiene límite JSON de 8 KiB, devuelve `Cache-Control:
no-store` y no escribe historial ni `ai_assessment_jobs`. La respuesta y el
hash de suite se validan antes de devolverlos; un hash inconsistente falla en
cerrado.

El proceso API invoca únicamente `python3 -S -B -m
guardian_ai_assessment.policy_lab` con perfil allow-listed, entorno reducido,
sin shell, timeout de 5 s y tope de stdout de 64 KiB. La concurrencia queda
limitada a una invocación por proceso API. El E2E comprueba que una petición
válida no añade jobs y que la evidencia indica `modelInference=false` y
`dockerCommandRequestedByHarness=false`.

## Límites de seguridad y alcance

- Es una vista de fixtures deterministas; no ejecuta Qwen, Garak ni Docker.
  Las decisiones no son inferencias ni resultados de agentes externos.
- **No es una frontera de aislamiento.** El subproceso comparte identidad con
  la API. La red del host y el acceso del proceso al socket Docker no se
  aíslan ni se verifican. La evidencia/UI los marca como
  `host_network_unisolated`, `shared_api_identity` y `not_assessed`; no se
  presenta como ejecución del worker `--network=none`.
- Las propuestas se procesan solo mediante herramientas sintéticas en memoria;
  no hay envío, transacción, modificación de datos ni llamada externa.
  Policy OFF permanece contrafactual sobre clones y nunca despacha.
- El resultado es efímero: no se crea un job ni un registro de auditoría durable
  para esta vista. Se muestran hashes de la evidencia devuelta.
- El E2E usa el harness autenticado de desarrollo para probar owner/admin,
  viewer, falta de autenticación y tenant cruzado. No equivale a probar una
  sesión Clerk real en un navegador.
- No se ejecutó inferencia Qwen nueva ni se abrió el gate del worker aislado.
  Docker broker independiente, IPv6 dual-stack, advisories, licencias y
  revisión de cadena de suministro siguen fuera de lo verificado aquí.

## Defectos encontrados y correcciones

1. El esquema Zod generado elimina propiedades desconocidas por defecto. La
   ruta ahora verifica el objeto JSON exacto antes de parsear; una propiedad
   extra se rechaza con 400. No se amplió el contrato.
2. El catálogo OpenAPI no incluía `propose_synthetic_refund`, ya usado por el
   fixture de soporte. Se añadió exclusivamente ese nombre existente y se
   regeneraron los clientes/esquemas.
3. Una aserción del test de cifrado modificaba el último carácter Base64URL,
   que podía ser una mutación sin efecto por bits de relleno. El test ahora
   cambia un carácter de los bytes del tag GCM y verifica que se rechace el
   texto alterado; no se cambió el formato ni el código criptográfico.

## Verificación ejecutada

| Capa | Resultado |
|---|---:|
| API unit/integration | 79/79 |
| API E2E de aprobación sintética y preview | 1/1 |
| UI/componentes | 10/10 |
| SDK TypeScript | 13/13 |
| SDK Python | 8/8 |
| Worker, todos los módulos salvo `test_corpus_validation.py` | 200/200 |
| Typecheck monorepo (`pnpm typecheck`) | pasó |
| Build API | pasó |
| Build web | pasó; advertencias existentes de sourcemap `tooltip.tsx` y chunk >500 KiB |
| `git diff --check` | pasó |

El descubrimiento completo del worker registró 201 pruebas y un error de carga:
`ModuleNotFoundError: No module named 'garak'` en
`test_corpus_validation.py`. No se instaló Garak ni se omitió ese error al
informar el resultado; se ejecutaron los otros 30 módulos, incluyendo
`test_policy_lab.py` (33/33).

El E2E de desarrollo reportó el digest:
`201cc673614c61bc6eefabc6dc933a93409d1c42afeade1646368f89fbcb1faa`.
Comprobó 401 sin autenticación de harness, 403 por tenant/rol no autorizado,
400 por perfil/campos desconocidos y 200 para owner/admin; también `no-store`,
`modelInference=false`, cero comando Docker solicitado y ausencia de nuevos
jobs de evaluación.

Manifiesto SHA-256 de los 16 archivos de código, contrato y pruebas:
`workers/guardian-ai-assessment/reports/development-policy-preview-2026-11-04.sha256`,
hash del manifiesto
`8e97afe1d1d9855c0d718cfcbb3fadae7ddb670e21a241e4ab3c8bbc3b8f8bee`.
Los 16 hashes verificaron con `sha256sum -c`.

La captura automatizada de `/ai-evaluations` mostró la pantalla Clerk de inicio
de sesión. Por tanto, la UI autenticada real no se verificó con navegador; las
pruebas de componentes y el E2E usan harnesses de desarrollo.

## Estado

La demo de fixtures es utilizable desde la ruta autenticada de desarrollo y
permite recorrer los ocho perfiles sin abrir el gate Qwen/Docker. No demuestra
ocho agentes LLM, eficacia general, aislamiento del proceso API ni preparación
para clientes. La inferencia Qwen, broker host-separado, sesión Clerk real de
navegador, Garak-dependent corpus suite, IPv6, vulnerabilidades y revisión
legal permanecen sin verificar o bloqueados.
