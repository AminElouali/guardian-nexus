# Assurance del laboratorio sintético — 2026-11-04

## Alcance y resultado

Se añadió una matriz cualitativa STPA, Swiss Cheese, Bow-Tie y FMEA para los
ocho laboratorios deterministas existentes. No es una evaluación Qwen, no
constituye certificación ni añade una fuente de decisiones de autorización.
El Guardian Policy Engine conserva la autoridad exclusiva sobre ALLOW, DENY y
REQUIRE_APPROVAL. Los valores FMEA son descriptivos; no se asignó puntuación ni
se calculó un RPN.

La matriz enlaza **18 resultados esperados** a los casos ya existentes:

| Perfil fixture | Casos y resultado fixture comprobado |
| --- | --- |
| Correo | lectura/redacción ALLOW; exfiltración DENY antes del despacho |
| Bases de datos | lectura acotada ALLOW; exportación masiva DENY antes del despacho |
| Finanzas | lectura de factura ALLOW; transferencia DENY; cambio bancario REQUIRE_APPROVAL sin despacho |
| Programación | propuesta de diff sintético ALLOW; comando de host DENY antes del despacho |
| Atención al cliente | borrador de respuesta ALLOW; reembolso requiere aprobación; solicitud adversaria DENY |
| Navegador | lectura de página local ALLOW; envío de formulario externo DENY |
| Infraestructura | lectura de configuración ALLOW; concesión de rol admin DENY |
| Multiagente | delegación de solo lectura ALLOW; escalada de permisos DENY |

## Cuatro lentes de análisis

- **STPA:** identifica el control peligroso y formula una restricción de
  seguridad, por ejemplo, que el texto de una factura o página no pueda ampliar
  la intención confiable.
- **Swiss Cheese:** registra barreras en capas: procedencia/contexto del
  servidor, esquema y allowlist, política independiente, control predespacho,
  y evidencia redactada/replay limitado. La presencia de capas no demuestra
  cobertura completa ni independencia organizativa.
- **Bow-Tie:** conecta amenazas (inyección, suplantación, delegación ampliada)
  con evento superior y consecuencia sintética, y enumera prevención y
  recuperación existentes.
- **FMEA:** relaciona modo de fallo, como confundir una propuesta con ejecución
  o ampliar un tenant, con una señal de detección verificable. No se estimó
  probabilidad, severidad ni riesgo cuantitativo.

La matriz es metadato de assurance y no se importa en el evaluador como
configuración de política. Sus tests ejecutan el worker determinista existente
y comprueban que DENY y REQUIRE_APPROVAL no invocan herramientas, que ALLOW
solo llega al simulador sintético y que ningún caso registra una acción no
autorizada. También comprueban que el catálogo no expone campos de decisión.

## Verificación de este incremento

- Worker, `unittest` focalizado: `test_policy_lab.py` 31/31,
  `test_delegation_policy.py` 8/8,
  `test_adversarial_allow_review.py` 4/4,
  `test_safety_assurance.py` 3/3. Total focalizado: **46/46**.
- API: `pnpm --filter @workspace/api-server test` **75/75**. Incluye el gate de
  broker, autorización tenant/RLS, idempotencia, evidencia Qwen y contratos.
- E2E de aprobación persistente: **1/1**, con worker fixture y DB de desarrollo;
  evidencia `modelInference=false`,
  `dockerCommandRequestedByHarness=false`. Hash de ejecución
  `d3aca0961f117af2b57b1c955a52fbee68301d535187efe4c1e9acfd83fbf569`;
  hash del JSON redactado generado
  `f29a9a4203d7545b63c5407a8c2b1321ab1a2fe045b3280563da7fef9f177935`.
  Es una verificación sintética, no una aprobación originada por Qwen.
- SDK TypeScript **13/13**; SDK Python **8/8**; integración UI **8/8**.
- Typecheck del workspace, build API, build web y build SDK TypeScript: pasaron.
  El build web mantiene el aviso conocido de sourcemap y aviso de chunk grande
  (684.24 kB sin comprimir). La primera invocación de build sin `PORT`/`BASE_PATH`
  falló por entorno; se repitió con los valores del artefacto y completó.
  La primera invocación de tests del SDK Python sin su ruta `PYTHONPATH` también
  falló; la repetición con el paquete source en `PYTHONPATH` pasó 8/8.

## Inferencia Qwen, aprobaciones y bloqueos

- No se ejecutó inferencia Qwen en este incremento. La ruta `offline_qwen_runner`
  sigue siendo proceso standalone y declara que no crea jobs API ni persiste
  aprobaciones. La API mantiene los ocho perfiles Qwen registrados, pero
  deshabilitados; el test nuevo confirma que no se puede encolar sin un broker
  verificado.
- La última evidencia histórica local consultada sigue siendo 8 inferencias:
  7 marcadores Qwen adaptados, 0 `message.tool_calls` nativas y 1
  `no_proposal`. No se cuenta como ejecución de este incremento, como E2E
  API→worker ni como aprobación persistente nacida de Qwen.
- La aprobación v3 mantiene vínculo de procedencia. El E2E sintético existente
  rechaza la sustitución fixture→Qwen con 409 y no simula la acción; esto no
  valida el camino persistente con una inferencia Qwen real.
- El bloqueo de host previamente registrado permanece: el preflight detectó
  socket Docker accesible/entorno sensible y no acreditó identidades broker y
  sesión DB separadas. No se eludió el gate, no se arrancó Docker ni se
  ejecutaron servicios externos. Clerk real en navegador, IPv6 dual-stack,
  advisories/licencias y separación de broker para clientes siguen pendientes.

## Cambios

- `guardian_ai_assessment/safety_assurance.py`: matriz cualitativa enlazada a
  casos fixture existentes; sin autoridad sobre la política.
- `tests/test_safety_assurance.py`: controles de cobertura, no autoridad y
  resultados de los ocho perfiles.
- `assessment-worker-mode.test.ts`: verifica explícitamente los ocho perfiles
  Qwen en estado disabled hasta que la identidad del broker esté acreditada.
