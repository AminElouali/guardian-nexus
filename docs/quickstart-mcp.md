# Conecta un agente de prueba a Guardian Nexus por MCP

Guardian Nexus recibe propuestas de herramientas por MCP, autentica al agente y aplica la regla activa del workspace. Las herramientas de esta demo y sus destinos son **sintéticos**: no envían correo, no mueven dinero y no modifican servicios externos.

## Estado

**IMPLEMENTADO:** el proxy HTTP MCP publica herramientas de una lista permitida de Guardian para ocho servicios de demostración. El agente se autentica con una credencial del workspace; las reglas versionadas deciden si la propuesta se simula como permitida, se bloquea o necesita aprobación. Una aprobación produce un recibo firmado y ligado a la acción exacta.

**PROYECTADO:** conexión a servidores MCP reales, registro de destinos de clientes, conectores productivos, grupos configurables de aprobadores y notificación automática al agente cuando se aprueba una solicitud.

## 1. Crea un agente

Un propietario o administrador del workspace registra el agente desde la pantalla **Agentes**. La credencial se muestra una sola vez. Guárdala en el gestor seguro del agente; Guardian conserva solo su huella. Si se pierde, revócala y crea otra.

No copies credenciales reales en ejemplos, capturas, tickets o registros.

## 2. Configura el endpoint MCP

Configura un cliente MCP HTTP con la URL de tu entorno:

```text
https://<dominio-de-Guardian>/api/workspaces/<ID-DEL-WORKSPACE>/mcp
```

Envía la credencial en `Authorization: Bearer …`. El identificador del workspace sirve para localizar la credencial; los permisos se determinan por la credencial autenticada y las reglas de RLS.

Envía `initialize` y luego `tools/list`. El proxy devuelve únicamente herramientas definidas por Guardian, con sus descripciones y esquemas estrictos. El servidor de destino no puede cambiar su clasificación con metadatos, descripciones ni respuestas.

## 3. Herramientas sintéticas disponibles

Las herramientas pertenecen al servidor de demostración ficticio y no representan conexiones a servicios reales:

| Servicio | Herramientas de demostración |
|---|---|
| Correo | `reply_internal_email`, `send_external_email`, `send_sensitive_external_email`, `create_forwarding_rule` |
| Soporte | `reply_to_support`, `issue_synthetic_refund`, `close_customer_account` |
| Finanzas | `read_finance_record`, `pay_known_vendor`, `pay_new_vendor` |
| Datos | `query_synthetic_data`, `export_customer_data`, `modify_data_batch`, `delete_data_batch` |
| Código | `open_pull_request`, `merge_pull_request_main`, `deploy_to_production`, `access_repository_secret` |
| Web | `read_synthetic_web_page`, `submit_personal_data_form`, `purchase_synthetic_item`, `submit_credentials_unapproved_site` |
| Cloud | `read_cloud_resource`, `create_cloud_resource`, `change_cloud_iam_permissions`, `delete_or_public_cloud_resource` |
| Multiagente | `delegate_equal_or_lower`, `delegate_higher_permissions`, `self_assign_or_bypass_approval` |
| Guardian | `guardian_approval_status` |

El catálogo de 30 acciones clasifica cada acción con uno o más de estos riesgos:
leer, escribir dentro, enviar fuera, mover dinero, dar permisos, borrar o
exportar, ejecutar o desplegar, y comprometer a la empresa. Las herramientas
también tienen etiquetas de sensibilidad (`normal` o `sensible`) y volumen. Son
ejemplos iniciales, no un catálogo completo para todas las empresas. El
catálogo es fijo; crear nuevas acciones sigue **PROYECTADO**.

Los argumentos deben cumplir exactamente el esquema recibido en `tools/list`. Campos adicionales, tipos incorrectos, nombres desconocidos o JSON ambiguo se rechazan.

## 4. Interpreta la decisión

- **ALLOW** significa que la regla activa autoriza la simulación. La respuesta indica que no se ha llamado a ningún servicio ni se ha producido un efecto externo.
- **DENY** bloquea la propuesta.
- **REQUIRE_APPROVAL** crea o devuelve una solicitud pendiente. La respuesta incluye el identificador y señala que se debe reintentar con los mismos argumentos después de la aprobación.

Las acciones que requieren aprobación independiente no se ejecutan aunque una regla diga Permitir: se elevan a aprobación. Si no existe una regla activa, el resultado es denegación.

Cuando una solicitud pendiente se aprueba, el siguiente reintento con la misma herramienta y argumentos recupera el recibo v1 firmado y continúa por el flujo protegido. La aprobación no se puede usar para otros argumentos, agentes o workspaces.

## 5. Aprobación y reintentos

Una persona distinta del solicitante debe aprobar la solicitud desde la bandeja. El solicitante no puede aprobar su propia acción. `guardian_approval_status` permite al mismo agente consultar el estado.

**Aprobaciones por importe y varias personas — implementado en esta rama, pendiente de validación:** cada versión de reglas puede fijar un umbral monetario (máximo 10.000 €). Para acciones que tienen un importe catalogado, hasta el umbral aprueba una persona administradora y por encima la persona propietaria. El cambio de cuenta bancaria sintético requiere dos aprobaciones de personas diferentes. Repetir el voto de una misma persona no suma; la solicitud sigue pendiente y no se emite el recibo hasta completar el número requerido. Los votos quedan en la auditoría append-only. El recibo v1 y el evento v1 del ledger no cambian.

Si una acción protegida ya se completó y el agente reintenta la misma llamada por un problema de red, Guardian devuelve el resultado anterior con `replayed: true`; no la ejecuta otra vez. Se rechazan los usos desde otro agente o workspace, con argumentos cambiados o con una solicitud caducada.

## 6. Reglas y plantillas

Las plantillas **Prudente**, **Equilibrada** y **Solo lectura** crean borradores; una persona autorizada debe activarlos. El catálogo clasifica acciones por su efecto y riesgo, no por el nombre del servicio. Lo no clasificado queda bloqueado. Solo lectura permite únicamente acciones definidas como lectura.

**IMPLEMENTADO en el laboratorio:** owner/admin puede configurar condiciones versionadas por workspace desde **Reglas → Ajusta una acción**: importe, dominios exactos de confianza, sensibilidad del dato, volumen por minuto/5 minutos/15 minutos/hora/día y entorno. Cada regla tiene una decisión cuando se cumple y una decisión de fallback; Guardar crea un borrador y la activación sigue siendo independiente. El motor del servidor recibe la sensibilidad del catálogo, el entorno de pruebas del destino sintético y el volumen calculado desde auditoría; nunca confía en esos valores si los aporta el agente. Un contexto que no se puede comprobar no concede permiso.

**Límites:** el único entorno disponible es `test`; elegir `production` en una condición no crea ni habilita un conector productivo. Las propuestas nuevas sujetas a volumen guardan en su evidencia v2 el contexto agregado usado, ligado a su hash, para verificarlo y comparar decisiones históricas. Propuestas antiguas que no conservan ese contexto se cuentan como no reevaluables; no se reconstruye desde hashes ni ejemplos.

**PROYECTADO:** registrar acciones nuevas, conectar sistemas reales, medir datos personales dinámicos con un conector fiable, configurar grupos de aprobación y aplicar tramos de importe a grupos personalizados.

## Seguridad y límites

- Las credenciales de agente se guardan como hashes y se pueden revocar.
- Las reglas y los datos se aíslan por workspace mediante RLS.
- Los recibos aprobados se firman y ligan al hash de la acción y sus argumentos.
- El proxy no interpreta como instrucciones el texto que devuelve un destino.
- El catálogo y el destino MCP de pruebas son sintéticos. No introduzcas datos reales ni lo uses como conector productivo.
