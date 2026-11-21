# Plan proyectado de conectores y clasificación de acciones

> **Estado mixto:** la taxonomía completa y la mayoría de conectores de proveedores siguen **PROYECTADOS**. La base común de la etapa 1 está **IMPLEMENTADA** con un adaptador falso; el conector Gmail está **IMPLEMENTADO en modo prueba en la rama de trabajo** y requiere configurar OAuth antes de conectarlo.

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

**IMPLEMENTADO en el catálogo actual:** las 30 acciones sintéticas tienen
`riskTypes` versionados en código. Las 29 herramientas del proxy MCP añaden
etiquetas de sensibilidad y volumen. El catálogo representa los ocho tipos,
pero no hay conectores operativos para todas las áreas de esta tabla. Una
acción desconocida o sin clasificación sigue denegada.

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
- **Solo lectura:** solo permite las acciones tipadas como **Leer**; todas las acciones que escriben, envían, mueven dinero, cambian permisos, borran, ejecutan o comprometen a la empresa quedan denegadas.

## 6. Plan por etapas

Estado por etapa:

1. **Base común de conectores — IMPLEMENTADA parcialmente en código:** bóveda AES-256-GCM por workspace, identificador de clave, permisos por workspace, verificación y consumo atómico del recibo v1, registro idempotente, estados pendiente/ejecutado/fallido y desconexión. El catálogo contiene 30 acciones sintéticas distribuidas en ocho servicios; solo se registra un adaptador falso en el E2E desechable. La aplicación no registra adaptadores de proveedores y falla cerrada si no hay uno.
2. **Proxy MCP — Fases 1 y 2 IMPLEMENTADAS en el laboratorio:** hay un endpoint JSON-RPC con herramientas y esquemas escritos por Guardian, credencial de agente, decisión de reglas, aprobación humana, recibo v1 guardado para reintentos y un destino falso en proceso. No se ha conectado ningún servicio MCP real.
3. **Conector genérico configurable por el cliente — PROYECTADO:** aún no se permite que clientes definan nuevos adaptadores o acciones.
4. **Conectores nativos para la demo — IMPLEMENTADO en esta rama para Gmail (modo prueba); el resto PROYECTADO:** Gmail envía una plantilla fija a destinatarios permitidos solo después de aprobación humana, con OAuth de envío e identidad mínima. No lee el buzón ni acepta contenido libre. Stripe y otros proveedores siguen pendientes; no se presupone que estén configurados ni conectados.
5. **Verificador “sin recibo no se abre” — PROYECTADO para producción:** `lib/guardian-guard` demuestra el patrón con SMTP local, pero todavía no es un límite de seguridad desplegado que el agente no pueda evitar.
6. **Aprobaciones por tramo y varias personas — IMPLEMENTADO en código, pendiente de validación de esta rama:** cada versión de reglas puede guardar un umbral monetario; por debajo solo puede aprobar una persona administradora y por encima la propietaria. El cambio bancario sintético requiere dos aprobaciones de personas distintas. El recibo v1 se emite solo al completar las aprobaciones requeridas; los votos quedan en la auditoría append-only.
7. **Aislamiento de producción y objetivos de servicio — PROYECTADO:** medir p50 y p95 por separado para decisiones automáticas y aprobaciones humanas. Usar esos resultados para fijar un tiempo de respuesta verificable antes de prometerlo a clientes. Si las mediciones lo requieren, evaluar servidores en la UE y caché de reglas en memoria.

**Reglas de evolución y operación — PROYECTADAS:** cada cambio de esquema debe incluir una migración versionada y una prueba que parta de la forma anterior del esquema. Además, realizar periódicamente una auditoría de solo lectura de la base de desarrollo para detectar desajustes pronto.

### Proxy MCP — fase 1 IMPLEMENTADA (catálogo y clasificador)

Hay una función pura y determinista que clasifica llamadas contra una lista explícita de 29 herramientas de un servidor MCP ficticio de demostración. El catálogo contiene 30 acciones versionadas (las cuatro existentes y 26 nuevas) para Correo, Soporte, Finanzas, Datos, Código, Web, Cloud y Multiagente, asociadas a los perfiles de laboratorio existentes. Recibe el texto JSON original de los argumentos para detectar claves duplicadas antes de que un parser ordinario las descarte. La acción y los riesgos proceden del catálogo de Guardian; los argumentos se validan de forma estricta y se calcula una huella canónica usando la canonicalización compartida del proyecto. Nombres o argumentos desconocidos o malformados se rechazan de forma cerrada. Las descripciones, títulos, anotaciones, esquemas y respuestas que aporte MCP no influyen en el resultado.

La plantilla Equilibrada define las acciones rutinarias de lectura o respuesta interna como ALLOW simulado, las acciones sensibles como aprobación y las acciones prohibidas como DENY. Prudente eleva los ALLOW de catálogo a aprobación; Solo lectura permite únicamente las acciones clasificadas como lectura. Si un workspace no tiene una regla activa, se deniega. Un ALLOW del proxy es solo una decisión de autorización en esta etapa: no llama al destino ni produce efectos externos.

### Proxy MCP — fase 2 IMPLEMENTADA (solo laboratorio)

El API acepta solicitudes MCP JSON-RPC por HTTP en modo de respuesta simple. La ruta autentica la credencial del agente dentro del workspace indicado, pero solo usa ese identificador para buscarla; la identidad y los permisos se obtienen de la credencial validada. `tools/list` entrega definiciones redactadas por Guardian y nunca consulta ni reenvía metadatos de un destino MCP.

Las llamadas usan el texto JSON original de los argumentos y el clasificador estricto. Las acciones desconocidas se bloquean antes del destino. Las decisiones **Permitir** para acciones que requieren aprobación independiente se elevan a aprobación y dejan constancia de `rule_allow_escalated_to_approval`, salvo la excepción acotada de reembolso sintético descrita abajo. Las acciones sintéticas expresamente marcadas sin aprobador independiente pueden responder ALLOW como simulación; no se invoca ningún servicio ni se ejecuta la acción.

La regla Equilibrada de soporte interno sin compensación puede evaluar como ALLOW, pero `guardian.support.reply.send.v1` conserva el requisito de aprobador independiente de la acción existente; por eso el proxy la eleva a aprobación humana. La lectura web y la respuesta interna de correo son ejemplos de ALLOW simulado sin ese requisito.

**IMPLEMENTADO — reembolso sintético con límite:** la herramienta MCP `issue_synthetic_refund` usa el motor de reglas versionadas. Con una regla activa y un límite explícito, una cantidad dentro del límite puede obtener `ALLOW`; una cantidad superior requiere aprobación. Sin regla activa también requiere aprobación, y la plantilla Solo lectura deniega. Además, los ALLOW automáticos se acumulan por workspace durante 15 minutos; si el historial no puede leerse con seguridad o el total superaría el límite configurado, se pide aprobación. La decisión automática queda auditada con la regla y su versión y es idempotente para la misma llamada. Este resultado es solo una autorización sintética: no mueve dinero, no llama a un proveedor ni ejecuta un reembolso real. El máximo por solicitud sigue siendo el del catálogo.

Una solicitud pendiente responde inmediatamente con su identificador. La misma llamada y los mismos argumentos consultan esa solicitud; si otra persona la aprueba, el siguiente reintento recupera el recibo v1 firmado, lo verifica y ejecuta mediante el mecanismo de un solo uso e idempotencia existente. El recibo se conserva en una tabla append-only con RLS forzada; no se alteraron los formatos v1 de recibo ni de ledger. También se ofrece `guardian_approval_status`, limitado a las solicitudes del agente.

El único destino registrado es falso y solo se inyecta en el E2E del laboratorio; puede devolver texto adversarial, que se devuelve al agente como contenido de datos sin interpretarlo. Hay límites de tamaño de solicitud/respuesta y tiempo del destino. La aplicación normal no registra destinos y bloquea la ejecución si no hay uno. **No hay conexión de red a servidores MCP reales, registro persistente de servidores, notificación automática al agente ni prueba de aislamiento de producción.**

**PROYECTADO:** registrar y autenticar servidores MCP reales, conectar el proxy con sus herramientas, definir cómo notificar al agente cuando se apruebe una solicitud y proporcionar un justificante específico para futuras acciones con permiso automático.

### Aprobaciones por importe y por varias personas — fase 3

**IMPLEMENTADO en esta rama; pendiente de validación y revisión:** el documento inmutable de cada versión de reglas puede guardar un umbral de aprobación monetario, limitado por el servidor. En acciones del catálogo que declaran un campo de importe, los importes hasta el umbral requieren una persona administradora; por encima requieren la persona propietaria. El umbral, la regla y su versión quedan vinculados a la evidencia de la propuesta.

El cambio bancario sintético requiere dos aprobaciones de usuarios distintos. Cada voto se registra en `workspace_audit_events`; el registro es append-only, se serializa por solicitud y repetir el voto de la misma persona no cuenta de nuevo. La solicitud permanece pendiente y no emite recibo hasta reunir las aprobaciones necesarias. El recibo v1 y el evento v1 del ledger no cambian. Los grupos configurables de aprobadores y reglas de importe personalizadas por grupo siguen **PROYECTADOS**.

### Catálogo de los ocho servicios — fase 1 IMPLEMENTADA

El servidor de demostración ficticio publica solo los nombres, descripciones y esquemas escritos por Guardian. Las herramientas cubren correo interno y externo, soporte, finanzas, consultas/exportaciones de datos, cambios de código, navegación web, recursos cloud y delegación entre agentes. Cada una enlaza a un identificador versionado del catálogo, al perfil de laboratorio de su servicio y a riesgos tipados. El catálogo y el clasificador no conectan proveedores ni ejecutan esas acciones: las salidas son simulaciones sintéticas.

**IMPLEMENTADO en la fase 2 (solo acciones sintéticas):** owner/admin pueden guardar borradores versionados por workspace con condiciones para importe, dominios exactos de destinatarios, sensibilidad derivada del catálogo, volumen por ventana de 1 minuto, 5 minutos, 15 minutos, 1 hora o 1 día, y entorno de pruebas/producción. Las decisiones usan el motor de reglas existente y cada resultado registra la regla y la versión; los datos de contexto no se aceptan desde los argumentos del agente. Las consultas de volumen se serializan por workspace y acción y se cuentan desde el historial de auditoría. Si falta contexto, no se concede ALLOW.

**Límites verificados:** solo existe el entorno `test` porque el proxy solo tiene destinos sintéticos; una regla para `production` no habilita una conexión de producción. Las propuestas aprobables conservan el contexto confiable agregado en la evidencia v2, ligado a su hash, para que la verificación y la comparación histórica usen el mismo volumen observado; propuestas antiguas sin ese contexto se cuentan como no reevaluables, sin reconstruirlo desde hashes o fixtures. La interfaz permite una condición combinada y una decisión de fallback; el historial anterior se conserva como versiones. Receipt v1 y ledger event v1 no cambian.

**PROYECTADO para fases posteriores:** conectores reales y contexto de entorno de producción; múltiples reglas ramificadas por condición dentro de una sola edición; condiciones de destinatario o sensibilidad extraídas por conectores que puedan verificar esos datos; y doble aprobación o aprobación por tramo.

La migración versionada `0009_expand_approval_action_catalog.sql` amplía las cuatro restricciones de referencia de acción para incluir el catálogo actual. La fase de laboratorio verifica la lista literal de la migración frente a `APPROVAL_ACTION_REFS`, aplica la migración y comprueba su idempotencia. **No se afirma que esta migración esté aplicada en Development o producción.**

**PROYECTADO:** añadir, mediante una ampliación versionada del ledger, un evento
firmado para registrar también las denegaciones. Hoy `DENY`, llamadas
desconocidas o rechazadas, solicitudes pendientes y la escalada de `ALLOW` a
aprobación quedan en `workspace_audit_events` con hashes y motivos seguros; no
se añaden eventos ni se cambia el formato del ledger v1.

**Limitación conocida — PROYECTADA:** el clasificador actual solo acepta identificadores en minúsculas ASCII; algunos servidores MCP reales usan nombres `camelCase`. En la fase 3 de registro de servidores, Guardian guardará el nombre exacto declarado para cada herramienta y lo comparará literalmente. Cualquier variante, incluidas diferencias de mayúsculas, homoglifos o caracteres invisibles, se rechazará.

### Gmail — IMPLEMENTADO en esta rama (modo prueba)

La tarjeta de Conexiones permite a owner/admin conectar una cuenta Google mediante OAuth con `gmail.send`, `openid` y `email`. El token de actualización se cifra con la bóveda existente por workspace y nunca se devuelve al navegador. La lista permitida comienza con la propia cuenta; solo admite direcciones exactas o dominios exactos. El agente puede enviar únicamente una plantilla fija, y el envío requiere aprobación humana incluso si la regla del workspace indica permitir. El resultado idempotente guarda el ID del mensaje en auditoría, no el cuerpo.

La integración queda como no configurada hasta que existan las variables OAuth y la bóveda del proceso. Las pruebas usan HTTP simulado y no contactan Google. No se añadió esquema ni migración: se reutilizan las tablas de credenciales, OAuth y ejecuciones ya existentes.

## 7. Estado actual

**IMPLEMENTADO hoy:** catálogo sintético de 30 acciones y lista MCP de 29 herramientas para ocho servicios; acceso al proxy por credencial propia del agente; reglas versionadas y plantillas; aprobaciones con recibo v1 y verificación/consumo de un solo uso. Los ALLOW del catálogo en el proxy son decisiones de simulación, salvo el reembolso automático ya existente, que también solo autoriza y audita: no mueve dinero. En la base común, las credenciales de conectores se cifran y solo se informa su estado; la ejecución requiere recibo, consumo único e idempotencia. El adaptador falso sigue reservado al laboratorio; Gmail es el primer conector externo limitado a una plantilla y una lista permitida en modo prueba.

Esto no equivale a conectores productivos para los servicios enumerados, ni demuestra que una herramienta externa esté obligada a pasar por Guardian. La clave maestra de cifrado se proporciona mediante configuración del proceso; el laboratorio crea una clave efímera y no persistente. El despliegue, la custodia y la rotación operativa de claves maestras, la aplicación de condiciones configurables por workspace y las aprobaciones por tramo o dobles son **PROYECTADOS**.

## 8. Decisiones abiertas

1. **“Qué habría pasado”, opción 3:** decidir si se guardan datos mínimos de las acciones para futuras comparaciones, qué campos se conservan y durante cuánto tiempo. Hasta entonces, no reconstruir argumentos a partir de hashes ni de fixtures.
2. **Orden de conectores — decidido:** Amin priorizó el proxy MCP antes que el conector genérico configurable por cliente; las fases posteriores siguen proyectadas.
3. **Correo de demostración — decidido:** Gmail en modo prueba, limitado a destinatarios permitidos y a una plantilla fija. No se usa Mailtrap.
4. **Pagos de demostración:** confirmar Stripe exclusivamente en modo de prueba y sus límites.
5. **Flexibilidad por empresa:** definir los límites configurables por workspace (dominios, volúmenes, datos y entorno) y las reglas de aprobación por importe o doble aprobación. La plantilla Solo lectura ya permite solo las acciones tipadas como lectura; el alcance por sensibilidad y volumen sigue pendiente.

### Pruebas sintéticas con Promptfoo

**IMPLEMENTADO — Fase 1:** `redteam:mcp` ejecuta ataques deterministas y locales
contra el proxy usando la base desechable del laboratorio; no usa LLM ni API
externas. La configuración generativa de Fase 2 permanece **desactivada** y no
forma parte del comando ni del workflow. Activarla requeriría una clave de API
del proveedor de modelo elegido (por ejemplo, `OPENAI_API_KEY`); no se ha creado
ni consultado ninguna clave.
