# Plan proyectado de conectores y clasificación de acciones

> **Estado mixto:** la taxonomía completa y los conectores de proveedores siguen **PROYECTADOS**. La base común de la etapa 1 está **IMPLEMENTADA en código y en el laboratorio local** con un adaptador falso sin red; no hay servicios reales conectados.

## 1. Principio de clasificación

Las acciones se clasifican por lo que hacen, no por el servicio o conector que las ejecuta. Una herramienta, sea nativa, genérica o MCP, no determina por sí sola qué se permite. Guardian clasifica cada acción con sus argumentos y aplica la regla correspondiente. Toda acción que no esté clasificada queda bloqueada.

## 2. Tipos de riesgo

La propuesta usa ocho tipos de riesgo:

1. **Leer:** consultar información sin modificarla.
2. **Escribir dentro:** crear o cambiar información dentro de la organización.
3. **Enviar fuera:** comunicar información a personas o sistemas externos.
4. **Mover dinero:** realizar pagos, reembolsos, compras o acciones con coste económico.
5. **Dar permisos:** cambiar accesos, roles, credenciales o autorizaciones.
6. **Borrar o exportar:** eliminar datos o sacarlos de su sistema, incluidos los accesos públicos a esos datos.
7. **Ejecutar o desplegar:** ejecutar código, trabajos o cambios de infraestructura.
8. **Comprometer a la empresa:** aceptar firmas, contratos u otras obligaciones formales.

Una acción puede llevar más de un tipo si sus efectos lo justifican. Las notas de clasificación son obligatorias:

- Una regla de reenvío automático y la creación de un enlace público cuentan como **Borrar o exportar**.
- Crear recursos en la nube cuenta como **Mover dinero**, además de cualquier otro tipo aplicable.
- Pasar credenciales entre agentes queda **siempre bloqueado**.

**IMPLEMENTADO en el catálogo actual:** los cuatro tipos sintéticos/de demo
tienen `riskTypes` versionados en código. El catálogo representa los ocho
valores, pero no hay conectores operativos para todas las áreas de esta tabla.
Una acción desconocida o sin clasificación sigue denegada.

## 3. Etiquetas adicionales

Cada acción debe incluir dos etiquetas, independientes de su tipo de riesgo:

- **Sensibilidad del dato:** `normal` o `sensible`.
- **Volumen:** el límite de cantidad aplicable, por ejemplo el máximo de importe de un reembolso.

El volumen debe validarse en el servidor. Si se alcanza un límite, se aplica la regla definida para ese tramo; superar el máximo permitido o no tener regla aplicable no concede autorización.

## 4. Áreas y ejemplos de acciones

Los ejemplos son propuestas de clasificación, no permisos concedidos. El catálogo definitivo debe definir el identificador versionado, los argumentos permitidos, sus límites y los tipos de riesgo.

| Área | Ejemplos | Tipos de riesgo propuestos |
|---|---|---|
| Correo | Leer un mensaje; redactar; enviar a un destinatario interno o externo; crear un reenvío automático | Leer; Escribir dentro; Enviar fuera; Borrar o exportar |
| Soporte | Consultar un ticket; responder; ofrecer una compensación o reembolso | Leer; Escribir dentro; Enviar fuera; Mover dinero |
| Finanzas | Consultar un saldo; preparar o ejecutar un pago; cambiar datos bancarios | Leer; Mover dinero; Dar permisos |
| Datos | Consultar, modificar o borrar un registro; crear una exportación | Leer; Escribir dentro; Borrar o exportar |
| Código | Leer repositorios; modificar código; ejecutar una tarea; publicar una versión | Leer; Escribir dentro; Ejecutar o desplegar |
| Cloud | Consultar recursos; crear o modificar recursos; cambiar permisos; borrar recursos | Leer; Escribir dentro; Mover dinero; Dar permisos; Ejecutar o desplegar; Borrar o exportar |
| Web | Leer información; publicar o modificar contenido; generar un enlace público | Leer; Escribir dentro; Enviar fuera; Borrar o exportar |
| Documentos y archivos | Leer, editar, compartir, firmar, exportar o borrar un documento | Leer; Escribir dentro; Enviar fuera; Borrar o exportar; Comprometer a la empresa |
| CRM/Ventas | Consultar o cambiar una ficha; enviar una propuesta; aceptar condiciones comerciales | Leer; Escribir dentro; Enviar fuera; Comprometer a la empresa |
| Usuarios y permisos | Invitar, cambiar roles, revocar accesos o gestionar credenciales | Dar permisos |
| Multiagente | Delegar una tarea o transferir un resultado; compartir una credencial | Según la acción delegada; la transferencia de credenciales queda siempre bloqueada |
| Chat interno (conector genérico o MCP) | Leer una conversación; publicar o reenviar un mensaje | Leer; Escribir dentro; Enviar fuera; Borrar o exportar |
| Calendario (conector genérico o MCP) | Consultar, crear o cancelar una reunión; invitar asistentes externos | Leer; Escribir dentro; Enviar fuera; Borrar o exportar |
| Teléfono/SMS (conector genérico o MCP) | Consultar una llamada; enviar un SMS o iniciar una llamada | Leer; Enviar fuera |
| Redes sociales (conector genérico o MCP) | Leer publicaciones; publicar, responder o borrar contenido | Leer; Escribir dentro; Enviar fuera; Borrar o exportar |
| Firma electrónica (conector genérico o MCP) | Preparar, enviar o firmar un documento | Leer; Enviar fuera; Comprometer a la empresa |
| RRHH/nóminas (conector genérico o MCP) | Consultar un expediente; cambiar datos; ejecutar una nómina | Leer; Escribir dentro; Mover dinero. La etiqueta de sensibilidad suele ser `sensible`. |
| Tienda online (conector genérico o MCP) | Consultar pedidos; cambiar un pedido; emitir un reembolso o publicar un producto | Leer; Escribir dentro; Mover dinero; Enviar fuera |
| Publicidad (conector genérico o MCP) | Consultar métricas; modificar una campaña o presupuesto; publicar un anuncio | Leer; Escribir dentro; Mover dinero; Enviar fuera |

## 5. Plantillas propuestas

Las plantillas son puntos de partida versionados; al seleccionarlas se deberían guardar como borradores y requerir una activación explícita.

- **Prudente:** toda acción que mueva dinero o envíe información fuera de la empresa pide aprobación. Las demás acciones se bloquean salvo que una regla las permita de forma explícita.
- **Equilibrada:** las tareas rutinarias y acotadas pueden permitirse; las acciones de mayor importe, sensibles, externas o de alto impacto piden aprobación. Lo no clasificado se bloquea.
- **Solo lectura:** actualmente bloquea todas las acciones, incluida la lectura. **Permitir acciones de tipo Leer está pendiente de decisión de Amin**; no se debe interpretar esta plantilla como autorización de lectura hasta que esa decisión se tome.

## 6. Plan por etapas

Estado por etapa:

1. **Base común de conectores — IMPLEMENTADA parcialmente en código:** bóveda AES-256-GCM por workspace, identificador de clave, permisos por workspace, clasificación de las cuatro acciones del catálogo, verificación y consumo atómico del recibo v1, registro idempotente, estados pendiente/ejecutado/fallido y desconexión. Solo se registra un adaptador falso en el E2E desechable; la aplicación no registra adaptadores de proveedores y falla cerrada si no hay uno.
2. **Proxy MCP — Fases 1 y 2 IMPLEMENTADAS en el laboratorio:** hay un endpoint JSON-RPC con herramientas y esquemas escritos por Guardian, credencial de agente, decisión de reglas, aprobación humana, recibo v1 guardado para reintentos y un destino falso en proceso. No se ha conectado ningún servicio MCP real.
3. **Conector genérico configurable por el cliente — PROYECTADO:** aún no se permite que clientes definan nuevos adaptadores o acciones.
4. **Conectores nativos para la demo — PROYECTADOS:** correo en un sandbox como Mailtrap y Stripe en modo de prueba. Ambos están pendientes de confirmar; no se presupone que estén configurados ni conectados.
5. **Verificador “sin recibo no se abre” — PROYECTADO para producción:** `lib/guardian-guard` demuestra el patrón con SMTP local, pero todavía no es un límite de seguridad desplegado que el agente no pueda evitar.
7. **Aislamiento de producción y objetivos de servicio — PROYECTADO:** medir p50 y p95 por separado para decisiones automáticas y aprobaciones humanas. Usar esos resultados para fijar un tiempo de respuesta verificable antes de prometerlo a clientes. Si las mediciones lo requieren, evaluar servidores en la UE y caché de reglas en memoria.

**Reglas de evolución y operación — PROYECTADAS:** cada cambio de esquema debe incluir una migración versionada y una prueba que parta de la forma anterior del esquema. Además, realizar periódicamente una auditoría de solo lectura de la base de desarrollo para detectar desajustes pronto.

### Proxy MCP — fase 1 IMPLEMENTADA (clasificador)

Hay una función pura y determinista que clasifica llamadas contra una lista explícita de dos herramientas de un servidor MCP ficticio de demostración. Recibe el texto JSON original de los argumentos para detectar claves duplicadas antes de que un parser ordinario las descarte. La acción y los riesgos proceden del catálogo de Guardian; los argumentos se validan de forma estricta y se calcula una huella canónica usando la canonicalización compartida del proyecto. Nombres o argumentos desconocidos o malformados se rechazan de forma cerrada. Las descripciones, títulos, anotaciones, esquemas y respuestas que aporte MCP no influyen en el resultado.

Esta fase por sí sola no implementaba un proxy, conexión a servicios ni autorización para ejecutar herramientas. La clasificación tampoco equivale a aprobar o permitir una acción; las llamadas desconocidas deben bloquearse.

### Proxy MCP — fase 2 IMPLEMENTADA (solo laboratorio)

El API acepta solicitudes MCP JSON-RPC por HTTP en modo de respuesta simple. La ruta autentica la credencial del agente dentro del workspace indicado, pero solo usa ese identificador para buscarla; la identidad y los permisos se obtienen de la credencial validada. `tools/list` entrega definiciones redactadas por Guardian y nunca consulta ni reenvía metadatos de un destino MCP.

Las llamadas usan el texto JSON original de los argumentos y el clasificador estricto. Las acciones desconocidas se bloquean antes del destino. Las cuatro acciones actuales requieren aprobación independiente; si una regla dice **Permitir**, el proxy la eleva a aprobación y deja constancia de `rule_allow_escalated_to_approval`. Si una acción futura no requiere aprobador independiente, una decisión Permitir falla cerrada en esta fase.

Una solicitud pendiente responde inmediatamente con su identificador. La misma llamada y los mismos argumentos consultan esa solicitud; si otra persona la aprueba, el siguiente reintento recupera el recibo v1 firmado, lo verifica y ejecuta mediante el mecanismo de un solo uso e idempotencia existente. El recibo se conserva en una tabla append-only con RLS forzada; no se alteraron los formatos v1 de recibo ni de ledger. También se ofrece `guardian_approval_status`, limitado a las solicitudes del agente.

El único destino registrado es falso y solo se inyecta en el E2E del laboratorio; puede devolver texto adversarial, que se devuelve al agente como contenido de datos sin interpretarlo. Hay límites de tamaño de solicitud/respuesta y tiempo del destino. La aplicación normal no registra destinos y bloquea la ejecución si no hay uno. **No hay conexión de red a servidores MCP reales, registro persistente de servidores, notificación automática al agente ni prueba de aislamiento de producción.**

**PROYECTADO:** registrar y autenticar servidores MCP reales, conectar el proxy con sus herramientas, definir cómo notificar al agente cuando se apruebe una solicitud y proporcionar un justificante específico para futuras acciones con permiso automático.

**Limitación conocida — PROYECTADA:** el clasificador actual solo acepta identificadores en minúsculas ASCII; algunos servidores MCP reales usan nombres `camelCase`. En la fase 3 de registro de servidores, Guardian guardará el nombre exacto declarado para cada herramienta y lo comparará literalmente. Cualquier variante, incluidas diferencias de mayúsculas, homoglifos o caracteres invisibles, se rechazará.

## 7. Estado actual

**IMPLEMENTADO hoy:** cuatro acciones sintéticas o de demostración: reembolso sintético, cambio de banco sintético, respuesta de soporte y correo externo; existe una entrada por API autenticada con credencial por agente. En la base común, las credenciales de conectores se cifran y solo se informa su estado y últimos cuatro caracteres; la ejecución requiere un recibo aprobado y un adaptador registrado, consume el recibo una sola vez y usa una clave de idempotencia. El único adaptador implementado es falso y exclusivo de pruebas, sin acceso de red.

Esto no equivale a conectores productivos para los servicios enumerados, ni demuestra que una herramienta externa esté obligada a pasar por Guardian. La clave maestra de cifrado se proporciona mediante configuración del proceso; el laboratorio crea una clave efímera y no persistente. El despliegue, la custodia y la rotación operativa de claves maestras, la taxonomía completa y las etapas restantes de conectores son **PROYECTADOS**.

## 8. Decisiones abiertas

1. **“Qué habría pasado”, opción 3:** decidir si se guardan datos mínimos de las acciones para futuras comparaciones, qué campos se conservan y durante cuánto tiempo. Hasta entonces, no reconstruir argumentos a partir de hashes ni de fixtures.
2. **Orden de conectores — decidido:** Amin priorizó el proxy MCP antes que el conector genérico configurable por cliente; las fases posteriores siguen proyectadas.
3. **Correo de demostración:** confirmar Mailtrap y el alcance del sandbox.
4. **Pagos de demostración:** confirmar Stripe exclusivamente en modo de prueba y sus límites.
5. **Lectura:** decidir si la plantilla Solo lectura debe permitir acciones de tipo Leer, y bajo qué etiquetas de sensibilidad y volumen.
