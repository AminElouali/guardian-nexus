# Ocho laboratorios sintéticos de políticas de agentes — 2026-11-02

## Alcance y estado

Se añadió una versión local de laboratorio para correo, bases de datos,
finanzas, programación, atención al cliente, navegador, infraestructura y
delegación multiagente. Los ocho perfiles entran por la cola autenticada
existente; el contrato de evidencia v2 registra identidad/actor, herramienta,
recurso, sensibilidad, procedencia, permisos, decisión, estado de ejecución y
trazas redactadas. No se añadió una migración de tablas.

**No son ocho agentes LLM.** Cada perfil ejecuta fixtures deterministas y
herramientas ficticias. No envía prompts a Qwen; no se contabiliza como
inferencia, selección autónoma ni prueba de resistencia del modelo. La política
se decide fuera del LLM y antes de invocar el adaptador sintético.

## Ejecución reproducible

- Worker: `guardian-ai-assessment-lab-0.5.1`.
- Motor/política/adaptador: `guardian-agent-policy-lab-v2`,
  `guardian-policy-engine-synthetic-v2`,
  `guardian-synthetic-tool-adapter-v1`.
- Evidencia: versión 2, semilla fija `20261102`, corpus
  `guardian-agent-lab-corpus-v1`.
- Se solicitaron los ocho perfiles por la cola/API de desarrollo. Los ocho
  trabajos terminaron en `succeeded`; cada uno contiene un caso benigno y uno
  adversarial. Hay 16 casos: 8 en español y 8 en inglés.
- Política ON: primero evalúa recurso/workspace, permisos, operación,
  procedencia y necesidad de aprobación. Solo las 8 propuestas benignas
  autorizadas llegaron al adaptador ficticio. Las 6 denegaciones y 2 decisiones
  `require_approval` no invocaron herramientas.
- Política OFF: únicamente contrafactual en clones efímeros en memoria. No
  invocó el adaptador ni produjo efectos externos o persistentes.
- Totales medidos: 16 propuestas e intentos; 8 allow, 6 deny, 2
  `require_approval`; 8 ejecuciones simuladas; 0 ejecuciones no autorizadas; 0
  operaciones reales; 0 cambios persistentes; 0 llamadas externas. El brazo
  OFF estimó 16 acciones posibles y registró 12 cambios solo en clones. Estos
  conteos describen únicamente estos fixtures; no son tasas generales.

| Perfil | Caso benigno | Caso adversarial | Resultado adversarial |
| --- | --- | --- | --- |
| Correo | Lectura/borrador local | Envío y exfiltración externa | DENY |
| Bases de datos | Lectura de una fila sintética | Exportación entre espacios | DENY |
| Finanzas | Lectura de factura ficticia | Solicitud de transferencia | Requiere aprobación |
| Programación | Propuesta de diff | Comando del host | DENY |
| Atención al cliente | Borrador de respuesta | Solicitud de reembolso | Requiere aprobación |
| Navegador | Lectura de página `.invalid` local | Envío de formulario externo | DENY |
| Infraestructura | Lectura de configuración ficticia | Concesión de rol admin | DENY |
| Multiagente | Delegación de solo lectura | Escalada de permisos | DENY |

Las herramientas no acceden a cuentas, redes, archivos del host, cloud ni
servicios externos. Los eventos guardan hashes de argumentos, no argumentos,
prompts ni respuestas en bruto. Las respuestas de herramienta son datos
sintéticos; las acciones permitidas tampoco producen mutaciones reales.

## Evidencia y pruebas

- Artefacto redactado local:
  `generated-artifacts/guardian-agent-policy-labs-e2e.json`
  — SHA-256 `9c258d2f6d556428400719ad7af1210da6e9c3aac5e54b003eaf339fddf3b79e`.
- Hashes SHA-256 `evidenceSha256` por trabajo:
  - correo: `baaa345446fbaf21d07dda4b18a256d311db7004d8cdcbc348432a97471bde12`
  - bases de datos: `896fdfeaae77284f2fbadad0616c942eaa4832ca92472e76a6bb1c86409ef398`
  - finanzas: `8875877dc7cdcc2a48ab143ec896e4f6a0d05851c3e0376d81e9a5619ee9c0c9`
  - programación: `1d7241d10ce7872f9f4bf8ceba0acad6e51a14433c1830c3e1b9a60d51edea1d`
  - atención al cliente: `a10018c1d169ec49d1b47f78c7a7a71eaf227cd4380006b25ac45cf47baa7cd3`
  - navegador: `34b7761664d58b1deeedf68e28dedf4e15fcbfd70772081fd16bb34af9e065e0`
  - infraestructura: `e2ae7740d255fbf2a3529159b1970cfa46b0db88b7a39361a55c7cbb26cd5f79`
  - multiagente: `1024745f4084699c10c3a7bfa348003d86d7cdfd6b326266545701bcbb61cf48`
- E2E integral en serie, antes del último guard de argumentos: **4/4**
  (cola/API/persistencia para Qwen local, evidencia Qwen de herramientas, ocho
  perfiles sintéticos y Qwen autónomo); regresión de componentes/informe/JSON:
  **6/6**.
- Después del guard fail-closed para argumentos de delegación malformados:
  E2E dirigido de los ocho perfiles **1/1**, pruebas de política **6/6** y
  pruebas del adaptador **5/5**.
- API/security: **53/53**. Typecheck API y UI, build API y build web pasaron.
  El build web mantiene advertencias preexistentes de sourcemap de `tooltip.tsx`
  y tamaño de chunk superior a 500 kB; no impidieron el build.
- Worker: pruebas de política **6/6**; adaptador y entradas malformadas
  **5/5**; validación de corpus Garak **3/3** dentro de la imagen local fijada,
  con `--network=none`, usuario no-root y rootfs de solo lectura.
- La batería Python completa ejecutada en el host antes del último guard tuvo
  **101 tests pasados** y un error de importación en `test_corpus_validation`
  porque `garak` no está instalado en el host. Esa prueba específica sí pasó
  dentro de la imagen Garak fijada. No se presenta la ejecución parcial del
  host como suite completa.
- La página pública se comprobó en preview. No se automatizó una sesión real de
  Clerk en navegador; la UI autenticada se verificó con pruebas de componente
  y E2E de API con identidad de prueba.

## Límites que permanecen

- Son pruebas de autorización sobre propuestas estructuradas ficticias. No se
  inyectó texto a un LLM en estos ocho perfiles y no se midió su capacidad para
  detectar prompt injection.
- `require_approval` bloquea la llamada al adaptador y queda registrada como
  decisión; aún no existe una bandeja de aprobación humana ni una reanudación
  posterior de la acción.
- No hay conectores empresariales ni operaciones reales.
- Garak y los perfiles Qwen existentes conservan sus rutas y evidencia
  separadas; los resultados de esta batería no se atribuyen a esos motores.
- Este cambio no resuelve la autoridad del proceso API sobre Docker, advisories
  OSV/Debian, revisión jurídica de licencias, ni la verificación IPv6 dual-stack.
  No demuestra preparación para clientes ni certificación.
