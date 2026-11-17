# Diseño: catálogo de acciones y gateway de cumplimiento

**Tipo:** diseño y estado de implementación local. Las etiquetas
**IMPLEMENTADO** y **PROYECTADO** de cada sección distinguen el código que ya
existe de las capacidades que todavía no deben usarse en entornos reales.

## Resumen ejecutivo

Guardian Nexus ya puede registrar y verificar aprobaciones para formas
sintéticas concretas, pero no constituye todavía un punto de cumplimiento
general entre un agente y cualquier herramienta empresarial. La siguiente
arquitectura separaría cuatro responsabilidades:

1. **Catálogo versionado:** describe acciones permitidas y sus argumentos.
2. **Policy Engine:** decide si una propuesta se permite, se deniega o requiere
   aprobación.
3. **Aprobación y ledger:** vinculan una decisión humana a una acción exacta y
   conservan evidencia verificable.
4. **Gateway/guard:** controla el acceso a la herramienta real y solo la invoca
   después de verificar la autorización y reclamar el recibo para un solo uso.

El catálogo no convierte por sí mismo una herramienta en segura. La aplicación
debe impedir que el agente alcance directamente las credenciales o el endpoint
del proveedor saltándose el gateway.

## Estado actual observado en el repositorio

### Avance local de esta fase

- **IMPLEMENTADO en código, solo sintético:** manifiesto versionado en
  `lib/db/src/approval-action-catalog.ts`; contiene los dos flujos sintéticos
  existentes y las acciones de respuesta de soporte y correo de prueba. Los
  argumentos son estrictos, el destino está limitado a dominios `.test` y
  `.guardian.invalid`, y lo desconocido se deniega por defecto.
- **IMPLEMENTADO en código:** previsualización en memoria, API de propuestas
  para las dos acciones genéricas nuevas, aprobaciones persistentes y binding
  SHA-256 de tipo y argumentos validados. La referencia permitida de acciones
  se deriva del manifiesto para Drizzle y se refleja en
  `lib/db/sql/rls-policies.sql`. La base de desarrollo no se ha migrado.
- **IMPLEMENTADO como prueba aislada:** `lib/guardian-guard` verifica un recibo
  v1 offline, reclama su consumo a Guardian y solo después entrega un correo
  sintético a un servidor SMTP local de captura. Las pruebas cubren el
  destinatario de sandbox, argumentos alterados, caducidad, clave no confiable,
  replay e indisponibilidad del ledger.
- **IMPLEMENTADO en la interfaz:** la sección “Pasarela de acciones” permite
  previsualizar y proponer las dos acciones nuevas, muestra aprobaciones y
  actividad disponible, conserva recibos aprobados en memoria y ofrece una
  guía de conexión. No genera credenciales y no conecta proveedores externos.
- **PROYECTADO:** despliegue del guard como ruta obligatoria, aislamiento de
  credenciales/red frente al agente, identidad autenticada de workload,
  persistencia de reglas editables, conectores de producción y operación en
  modo sombra sobre herramientas reales.

- `workers/guardian-ai-assessment/guardian_ai_assessment/tool_adapter.py`
  contiene una lista fija de herramientas sintéticas y una allow-list de
  operaciones por vertical. `evaluate_synthetic_action_policy` aplica reglas
  de alcance, permisos, procedencia e instrucciones de aprobación; no acepta
  acciones arbitrarias.
- `artifacts/api-server/src/lib/ai-assessment-approval-actions.ts` contiene
  combinaciones exactas de perfil, caso, herramienta y argumentos para el
  cambio bancario y el reembolso sintéticos. La simulación opera sobre una
  copia en memoria.
- `lib/db/src/schema/ai-assessment-jobs.ts` y
  `lib/db/sql/rls-policies.sql` tienen una comprobación de referencias de
  acción sincronizada con el manifiesto, que admite cuatro identificadores
  versionados. La comprobación de procedencia de inferencia es otra constraint,
  distinta, y permanece sin cambios.
- `artifacts/api-server/src/lib/approval-ledger-crypto.ts` implementa
  recibos, eventos y checkpoints v1. El recibo v1 ya lleva
  `actionSha256` y `proposalBindingSha256`, pero no un identificador explícito
  del agente ni un esquema completo de argumentos.
- `artifacts/api-server/src/lib/approval-ledger-service.ts` actualiza una
  aprobación y añade su evento dentro de una transacción; la cadena se
  serializa mediante bloqueo transaccional por workspace. El consumo actual
  registra un evento, pero el ledger no es un adaptador general para
  herramientas empresariales.
- `lib/db/src/schema/approval-ledger.ts` y
  `lib/db/sql/rls-policies.sql` definen un ledger append-only. El rol runtime
  recibe SELECT e INSERT, con RLS, `FORCE ROW LEVEL SECURITY` y políticas por
  workspace; no debe concedérsele UPDATE, DELETE o TRUNCATE.
- `verifier/verify_approval_ledger.py` verifica bundles y checkpoints sin
  conectarse a Guardian Nexus. Un checkpoint externo reciente sigue siendo
  necesario para detectar un truncamiento de cola; el verificador no obtiene
  ese checkpoint por red.

Estos componentes proporcionan piezas reutilizables, no una garantía de que
una herramienta real obedezca una decisión. El punto de ejecución de una
herramienta real aún necesita un guard que sea obligatorio y no evitable.

## A. Modelo genérico de acción

### Catálogo como datos versionados

La primera versión del catálogo debería ser un manifiesto versionado y
revisable, cargado por el Policy Engine y el gateway desde el mismo artefacto
de despliegue. No se recomienda empezar con una tabla nueva: añade políticas,
permisos y sincronización de versiones sin resolver la obligación principal
de impedir que el agente eluda el guard.

Cada definición de acción incluiría, como mínimo:

| Campo | Propósito |
| --- | --- |
| `actionType` | Identificador estable y versionado, por ejemplo `org.support.refund.v1`. |
| `argumentsSchema` | Esquema estricto de argumentos: campos requeridos, tipos, límites y prohibición de propiedades desconocidas. |
| `riskClass` | Categoría de riesgo versionada; no es por sí sola una decisión. |
| `defaultDecision` | Política por defecto, que debe ser `deny` o `require_approval` para acciones no revisadas; nunca permitir por desconocimiento. |
| `approvalRules` | Si se exige aprobación, roles admisibles, separación entre solicitante y aprobador y cantidad de aprobadores si aplica. |
| `receiptTtl` | Vigencia máxima de la autorización, con límite superior impuesto por el servidor. |
| `requiresIndependentApprover` | Exige que el aprobador sea distinto del solicitante/agente. |
| `toolBinding` | Adaptador registrado, versión y operación exacta a la que se puede despachar. |
| `policyVersion` | Versión del conjunto de reglas con el que se evaluó la propuesta. |

El manifiesto debe ser inmutable por versión. Cambiar argumentos permitidos,
riesgo, política o adaptador genera una nueva versión; las aprobaciones
pendientes se mantienen ligadas a la versión que las creó y pueden invalidarse
explícitamente, pero no reinterpretarse silenciosamente.

### Binding criptográfico

El servidor validaría primero los argumentos contra el esquema exacto y
canonicalizaría un objeto de acción que contenga, como mínimo, el identificador
versionado, los argumentos validados, el workspace, el recurso/destino, la
identidad que propone y la versión del catálogo/política. El hash debe cubrir
los valores normalizados que realmente recibirá el adaptador, no una
representación de entrada que luego pueda transformarse.

El recibo se liga a los hashes exactos de la propuesta y la acción. El gateway
reconstruye el objeto desde la solicitud de ejecución y su catálogo confiable,
recalcula los hashes y los compara antes del despacho. Diferencias de acción,
argumentos, workspace, recurso, identidad, versión, caducidad o aprobación
producen rechazo. El agente no puede suministrar la decisión, permisos
efectivos, identidad del aprobador ni catálogo confiable.

Para no cambiar los hashes históricos, las dos acciones sintéticas existentes
conservan su algoritmo y referencias actuales. Las nuevas acciones usan una
regla de canonicalización/hash explícitamente versionada y probada en ambos
extremos. La versión del identificador de acción y su contenido canónico deben
permitir seleccionar la regla sin heurísticas.

### Compatibilidad del recibo v1 y bundles existentes

- No se añaden campos a `ApprovalReceiptPayloadV1`, no se cambian dominios de
  firma, canonicalización, algoritmos ni reglas de expiración del formato v1.
- Los recibos y bundles v1 existentes siguen siendo bytes inmutables: el
  verificador TypeScript y `verifier/verify_approval_ledger.py` deben seguir
  aceptándolos con sus claves de confianza y checkpoint correspondientes.
- El campo v1 `actionSha256` puede ligar una nueva acción si el gateway dispone
  del catálogo confiable y conoce cómo reconstruir su forma canónica. El recibo
  v1 no prueba por sí solo los argumentos ni quién era el agente; esa
  comprobación depende de que el guard obtenga la acción esperada por un canal
  autenticado y recalcule el hash.
- No se debe cambiar el significado histórico de `requestedBy` ni inferir de
  ese campo una identidad de agente.
- Si una implementación requiere incorporar `agentId`, emisor de identidad,
  clave de agente, identidad del guard u otros atributos firmados, debe
  especificarse un recibo v2 y un verificador que soporte v1 y v2 en paralelo.
  No se deben hacer pasar esos atributos por campos v1 existentes.

## B. Cambio de esquema mínimo y riesgos

### Constraint correcta

La ampliación afecta a
`ai_assessment_approval_action_ref_check`: actualmente vincula
`synthetic_action_ref` a dos valores exactos y exige `action_sha256` cuando hay
referencia. La constraint
`ai_assessment_approval_provenance_check` valida la procedencia de inferencia
(`modelInference`, `executionMode`, `toolCallOrigin`) y **no debe sustituirse
ni relajarse** para habilitar acciones nuevas.

El cambio mínimo de esta fase sustituye la lista cerrada anterior por la lista
exacta de identificadores derivados del manifiesto versionado, manteniendo la
regla de que referencia y hash de acción son ambos nulos o ambos presentes.
No se usa una expresión genérica para aceptar nombres desconocidos: solo los
cuatro identificadores enumerados en `APPROVAL_ACTION_CATALOG` son aceptados.
Esto no constituye autorización: el API y el guard siguen validando que la
acción esté soportada y sus argumentos cumplan su esquema.

### Migración controlada

1. Revisar el catálogo, las referencias actuales y todas las filas existentes
   con consultas de metadatos/valores acotadas a las columnas de aprobación;
   no cambiar datos para hacer pasar una constraint.
2. Probar en PostgreSQL desechable que la nueva constraint acepta todas las
   referencias históricas válidas, rechaza referencias malformadas y exige el
   hash asociado. Probar también las transiciones de aprobación pendientes y
   aprobadas.
3. Aplicar el cambio de constraint en una migración revisada y transaccional.
   Si se necesita minimizar el bloqueo, estudiar `NOT VALID` y
   `VALIDATE CONSTRAINT` en el motor/versión objetivo antes de elegir el
   procedimiento. No borrar la constraint anterior hasta que la nueva esté
   instalada y validada.
4. Mantener sin cambios la constraint de procedencia de inferencia, las
   policies y flags RLS, los grants del ledger, el índice único parcial de
   consumo y las FKs no-cascading. No conceder permisos de escritura o
   ejecución adicionales para acomodar nuevas acciones.
5. Ejecutar la auditoría independiente del catálogo y las pruebas con el rol
   runtime, no solo con el rol propietario. Confirmar además que una acción con
   nombre formalmente válido pero ausente del catálogo no llega al gateway.
6. Aplicar primero solo a una base desechable. No aplicar a desarrollo o
   producción sin backup verificable, revisión de DDL y autorización
   específica.

Riesgos: la constraint de formato no puede demostrar que una acción está
revisada; los registros históricos pueden tener referencias antiguas o
inconsistentes; el cambio puede bloquear escrituras durante la validación; y
un error de sincronización entre catálogo, API y guard podría aceptar una
versión distinta de la que se aprobó. Por ello el catálogo debe tener un hash
de versión incluido en el binding de toda propuesta nueva.

### Recuentos del auditor

La auditoría de catálogo actual espera **13 tablas, 149 columnas, 37 índices,
54 constraints, 36 policies y 3 roles**. Si la primera iteración solo reemplaza
`ai_assessment_approval_action_ref_check` en el mismo objeto y no añade una
tabla de catálogo, los recuentos estructurales esperados permanecen
**13/149/37/54/36/3**; cambia el hash de fuente/definición de constraint, no la
cantidad.

Si una fase futura decide persistir definiciones de acciones en una tabla,
deberá presentar recuentos nuevos derivados del esquema fuente y contabilizar
sus índices, constraints, policies y privilegios en el contrato del auditor
antes de implementarla. No se debe ajustar manualmente el número esperado ni
aceptar objetos sin inventario.

La prueba de migración desechable debe verificar definiciones semánticas, no
solo nombres: constraint, índices, RLS habilitado/forzado, policies, roles y
privilegios efectivos, incluidos grants heredados y por columna. Debe comparar
las políticas `USING`/`WITH CHECK` y comprobar que los grants append-only del
ledger siguen siendo solo SELECT e INSERT. El código de la auditoría vigente
está en `artifacts/api-server/src/lib/development-rls-catalog-audit.ts` y el
contrato compartido en `lib/db/src/rls-catalog-contract.ts`.

## C. Punto de cumplimiento: gateway/guard

### Flujo propuesto

1. El agente presenta una propuesta al API. La identidad autenticada, el
   workspace y el perfil de permisos se obtienen del contexto confiable; no
   se aceptan como autoridad desde argumentos del modelo.
2. El API resuelve una definición habilitada del catálogo, valida argumentos,
   aplica política y registra la solicitud. `DENY` termina ahí;
   `REQUIRE_APPROVAL` crea una aprobación ligada al hash; `ALLOW` solo puede
   pasar a un adaptador registrado, nunca a una herramienta arbitraria.
3. Un aprobador independiente revisa la propuesta exacta. Al aprobar, el
   API emite el recibo firmado y registra el evento del ledger dentro de la
   transacción ya definida para el flujo v1.
4. El agente no recibe credenciales del conector ni acceso de red directo al
   proveedor. Solo puede invocar el gateway, que recibe la acción solicitada,
   el recibo y las referencias autenticadas necesarias.
5. El guard carga su almacén de claves públicas fuera del bundle, verifica
   criptográficamente el recibo, la vigencia, el workspace, la aprobación y
   los hashes reconstruidos de acción y argumentos. Para evidencia de cadena
   completa exige el bundle y un checkpoint vigente obtenido por canal
   confiable. No llama a Guardian para verificar firmas.
6. Antes de llamar a la herramienta, el guard reclama atómicamente el uso del
   recibo mediante el servicio/registro de consumo. Un rechazo, replay,
   discrepancia o imposibilidad de alcanzar el ledger produce **fail closed**:
   no se llama a la herramienta.
7. El guard invoca solo el adaptador correspondiente a la acción y registra
   el resultado verificable sin guardar secretos ni argumentos sensibles en
   el ledger.

### Consumo, replay y límites de transacción

El índice parcial único existente impide más de un evento
`approval.receipt_consumed` por recibo. Ese control es una parte de la
protección; el guard debe tratar el conflicto como rechazo y no ejecutar la
herramienta. Un consumo offline puramente criptográfico no puede evitar un
replay: se requiere estado compartido durable o una autoridad de consumo que
haga compare-and-set/insert único.

La transacción PostgreSQL no puede ser atómica con una llamada a un proveedor
externo. La siguiente fase debe resolver explícitamente la ventana entre
consumo y efecto externo. Diseño recomendado para acciones reales: reclamar el
recibo e insertar una intención de ejecución durable con un identificador
idempotente en la misma transacción; ejecutar después mediante un adaptador que
admita idempotencia; registrar el resultado como evento posterior. Si el
proveedor no ofrece idempotencia y se pierde la respuesta, el estado será
ambiguo y requerirá reconciliación humana; no se reintentará a ciegas. El
contrato actual de ledger solo contempla aprobación y consumo, así que nuevos
eventos/estado de ejecución requieren una propuesta de esquema aparte.

### Modelo de amenazas

| Amenaza | Control propuesto | Límite residual |
| --- | --- | --- |
| El agente intenta invocar directamente la herramienta | No exponer credenciales ni ruta de red al agente; solo el guard recibe acceso. | Si agente y herramienta comparten credenciales o red sin aislamiento, el guard puede ser evadido. |
| El guard está comprometido | Aislar su identidad, limitar conectores, firmar/registrar builds, separar aprobación y revisar resultados. | Un guard comprometido con credenciales de herramienta puede ejecutar acciones fuera de política. La firma de un recibo no protege el host. |
| Robo del recibo | Binding a workspace/acción/argumentos, TTL breve, verificación de identidad y consumo único. | El atacante que roba el recibo y también controla el contexto autorizado puede intentar ganarlo primero; se requiere autenticación del caller y alertas. |
| Ledger/checkpoint no disponible | Fallar cerrado y no despachar. | Disponibilidad reducida; no sustituirlo con caché “permitir si no hay respuesta”. |
| Checkpoint antiguo | Obtener el checkpoint más reciente por canal independiente. | Un checkpoint válido solo acredita hasta su secuencia; la firma por sí sola no prueba actualidad. |

## D. Identidad de agentes

Un agente debe tener un identificador estable y separado del usuario humano,
una organización/workspace propietario, versión de runtime, emisor de
identidad, clave o credencial de workload, permisos acotados y estado
revocable. La autenticación debería provenir de identidad de workload
verificable (por ejemplo, OIDC con audiencia y sujeto restringidos), no de un
`agentId` autodeclarado por el prompt. Los permisos del agente son un límite
máximo; no reemplazan membresía, política ni aprobación humana.

El recibo v1 contiene solicitante y aprobador, no una identidad de agente
distinta. El servidor puede ligar el hash de acción y el binding al agente,
pero un tercero no puede leer una identidad de agente firmada que v1 no
incluye. Si se requiere prueba portable de esa identidad, proponer v2 con
`agentId`, emisor/identificador de workload, versión del catálogo/política y
eventualmente `guardId` como campos firmados. El verificador debe conservar
compatibilidad dual con v1 y v2; los bundles históricos no se reescriben.

## E. Conectores y frameworks

**Proyectado:** un servidor/adaptador MCP puede publicar únicamente las
herramientas autorizadas del catálogo y redirigir cada llamada al gateway.
Las credenciales de proveedor residen en el adaptador de confianza, nunca en
el contexto MCP enviado al modelo. El adapter valida el esquema de argumentos,
fuerza la decisión del gateway y devuelve un resultado redactado.

**Proyectado:** adaptadores para frameworks de agentes deben implementar la
misma interfaz versionada del gateway, no copiar reglas de autorización.
Frameworks distintos no deben tener rutas alternativas directas al proveedor.
Las herramientas MCP que no pasen por el guard se consideran no gobernadas.

**PROYECTADO / no probado:** agentgateway podría integrarse como punto de
entrada si la versión desplegada permite delegar autorización mediante una
interfaz external-authz y si esa interfaz entrega al autorizador el método,
destino, identidad autenticada y cuerpo exacto que el guard necesita vincular.
En ese diseño, un adaptador estrecho traduciría la solicitud a la API del
guard; agentgateway no debería recibir una regla que permita continuar cuando
el autorizador no responde. Este repositorio no incluye configuración,
adaptador ni prueba de compatibilidad con agentgateway, por lo que no se afirma
que esa integración funcione.

El repositorio contiene herramientas sintéticas y conectores de Microsoft/AWS,
pero no se ha verificado un servidor MCP ni una integración general con un
framework de agentes. No deben presentarse como implementados.

## F. Modo sombra y transición a cumplimiento

En modo sombra se observan propuestas y llamadas ya realizadas por un sistema
externo, se reconstruye la decisión que habría emitido Guardian y se compara
con el resultado. El modo sombra **no bloquea ni protege**: no debe afirmarse
que hace cumplir la política, y debe limitarse a datos autorizados y
redactados.

Transición sugerida por acción y tenant:

1. Modo sombra con el mismo catálogo y reglas que se usarán en cumplimiento.
2. Revisar falsos positivos/negativos, llamadas sin binding, acciones
   desconocidas y discrepancias entre el guard y el policy service.
3. Habilitar enforcement solo cuando el guard sea la única ruta de salida, el
   fail-closed esté probado y exista un mecanismo de rollback de configuración
   que no reabra accesos directos.
4. Activar primero acciones de bajo riesgo y sin efectos externos; después
   acciones con aprobación y conector idempotente. Mantener kill switch que
   deshabilite despacho (deny), no que lo permita sin política.

## G. Hoja de ruta y criterios de salida

| Fase | Entrega | Criterio comprobable de salida |
| --- | --- | --- |
| 0. Base existente | Reutilizar recibos v1, ledger, RLS, grants, verificador offline y flujos sintéticos. | Tests actuales y auditorías del laboratorio siguen pasando; sin cambios incompatibles en bundles v1. |
| 1. Catálogo versionado | Esquemas de acciones, políticas por defecto, versiones y hashes reproducibles; todavía sin conectores reales. | Vector común de canonicalización/hash reproducido por API y verificador; acciones desconocidas rechazadas; decisiones ALLOW/DENY/REQUIRE_APPROVAL probadas. |
| 2. Ampliación de contrato | Sustituir solo la restricción de action ref, conservar procedencia, RLS y privilegios. | Migración PostgreSQL desechable compatible con filas históricas; auditoría semántica limpia; grants append-only sin cambios. |
| 3. Gateway sintético obligatorio | Guard delante de simuladores, consumo único, fallos cerrados y evidencia. | Pruebas de bypass, replay, expiración, mismatch, concurrencia, indisponibilidad y crash; ninguna llamada a simulador sin autorización. |
| 4. Identidad de agente y recibo portable | Diseño/implementación versionada para identidad de workload, posiblemente recibo v2. | Emisor, audiencia, agente y clave verificados; v1 continúa verificándose; rotación y revocación probadas. |
| 5. Modo sombra | Integración observacional sin efectos y con registro redactado. | Métricas con denominadores y revisión humana; copy distingue observación de enforcement. |
| 6. Primer conector real | Un conector de riesgo limitado, con credenciales aisladas y soporte de idempotencia/reconciliación. | Pruebas contractuales del proveedor, guard como único camino, fail-closed, recovery y revisión de seguridad independiente. |
| 7. Enforcements adicionales | MCP y adaptadores de frameworks que llaman al mismo gateway. | Prueba de que no existe ruta directa desde agente a credenciales/herramienta; catalogación y revocación verificables. |

**Implementado hoy:** contrato criptográfico v1 sin cambios; catálogo versionado
en código para cuatro acciones sintéticas; previsualización en memoria;
propuestas/aprobaciones para correo y respuesta de soporte de prueba; binding
canónico de acción/argumentos; guard aislado probado con SMTP local de captura;
interfaz para propuestas, aprobaciones, recibos y actividad. El ajuste de
constraint está probado únicamente en PostgreSQL desechable.

**Proyectado:** aplicar esa constraint a la base de desarrollo o producción;
guard obligatorio con identidad y red aisladas; conectores reales; envío a
destinatarios externos; reglas editables persistentes; MCP/framework adapters,
modo sombra operativo e identidad criptográfica de agentes. El SMTP local de
prueba no demuestra envío real ni aislamiento del agente en producción.

## H. Preguntas abiertas para decisión

1. ¿Qué primera categoría de acción real se habilitaría y qué recursos quedan
   expresamente fuera de alcance?
2. ¿Qué roles pueden aprobar cada clase de riesgo? ¿Se exige siempre
   separación solicitante/aprobador y doble aprobación para acciones críticas?
3. ¿Cuál es el TTL máximo por clase de acción y quién puede revocar una
   aprobación pendiente?
4. ¿Qué emisor de identidad de workload se acepta para agentes y cómo se
   revocan sus credenciales?
5. ¿Se requiere v2 del recibo para que un tercero pueda verificar
   `agentId`/guard, o basta inicialmente con binding v1 y evidencia del
   servidor?
6. ¿Quién opera la clave del ledger y el firmante de checkpoints, y por qué
   canal independiente se publica el checkpoint reciente?
7. ¿Qué política de fail-closed y recuperación se aplica cuando el ledger o
   proveedor no está disponible, o cuando el resultado externo queda ambiguo?
8. ¿Qué conectores se autorizan primero, qué idempotency keys soportan y qué
   evidencia mínima puede conservarse sin almacenar datos sensibles?
9. ¿Qué tenant, jurisdicción, retención, revisión humana y límites de coste se
   requieren antes de un piloto?

La respuesta a estas preguntas debe preceder a cualquier cambio que habilite
acciones reales. Este diseño no constituye certificación, evaluación legal ni
garantía de aislamiento del host.
