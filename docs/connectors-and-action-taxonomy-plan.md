# Plan proyectado de conectores y clasificación de acciones

> **Estado: PROYECTADO.** Este documento describe una propuesta de evolución; no significa que estos conectores, permisos o controles estén implementados.

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

Todas las etapas siguientes son **PROYECTADAS**:

1. **Base común de conectores:** caja fuerte de credenciales por workspace; verificación del recibo antes de ejecutar; idempotencia; registro del resultado; desconexión y revocación; y clasificación según los tipos de riesgo.
2. **Proxy MCP:** situar un proxy delante de servicios que ya ofrecen MCP. Las descripciones y nombres de herramientas recibidos se tratan como datos no fiables; Guardian clasifica la acción mediante su propio catálogo y no delega esa decisión al servidor MCP.
3. **Conector genérico configurable por el cliente:** permitir que cada cliente describa una conexión y sus acciones, manteniendo validación estricta, denegación por defecto y límites de riesgo.
4. **Conectores nativos para la demo:** correo en un sandbox como Mailtrap y Stripe en modo de prueba. Mailtrap y Stripe están **pendientes de confirmar**; no se presupone que estén configurados ni conectados.
5. **Verificador “sin recibo no se abre”:** un componente que el cliente instala en sus sistemas para comprobar el recibo antes de permitir la acción. La integración y el despliegue de ese componente siguen proyectados.

## 7. Estado actual

**IMPLEMENTADO hoy:** cuatro acciones sintéticas o de demostración: reembolso sintético, cambio de banco sintético, respuesta de soporte y correo externo; además, existe una entrada por API directa autenticada con credencial por agente.

Esto no equivale a conectores productivos para los servicios enumerados, ni demuestra que una herramienta externa esté obligada a pasar por Guardian. El resto de la taxonomía, las plantillas propuestas y las etapas de conectores descritas aquí son **PROYECTADAS**.

## 8. Decisiones abiertas

1. **“Qué habría pasado”, opción 3:** decidir si se guardan datos mínimos de las acciones para futuras comparaciones, qué campos se conservan y durante cuánto tiempo. Hasta entonces, no reconstruir argumentos a partir de hashes ni de fixtures.
2. **Orden de conectores:** confirmar si se prioriza el proxy MCP antes que el conector genérico configurable por cliente.
3. **Correo de demostración:** confirmar Mailtrap y el alcance del sandbox.
4. **Pagos de demostración:** confirmar Stripe exclusivamente en modo de prueba y sus límites.
5. **Lectura:** decidir si la plantilla Solo lectura debe permitir acciones de tipo Leer, y bajo qué etiquetas de sensibilidad y volumen.
