# EU Security Platform — fase 1 y siguientes

## Fase 1 implementada

- Inicio de sesión y registro mediante Clerk gestionado.
- Workspaces multi-tenant con pertenencia persistida por usuario.
- Verificación de sesión, pertenencia al workspace y permisos en el servidor.
- Roles básicos: owner, admin, analyst y viewer. El owner es el único que puede cambiar roles; los viewers solo leen.
- Inventario manual de activos con aislamiento por workspace y límite de activos por plan.
- Resumen de consumo mensual y catálogo inicial de planes.
- Reserva atómica de uso mensual para que futuras llamadas de IA, análisis o proveedores no excedan los límites por tenant.
- No se simulan hallazgos ni análisis. Los hallazgos solo existirán cuando se conecten fuentes y se ejecute un análisis real.

## Límites iniciales de los planes

Estos son límites de producto iniciales y se pueden ajustar antes del lanzamiento comercial.

| Plan | Activos | Usuarios | Análisis/mes | Tokens/mes | Consultas API/mes | Soporte |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Pequeña | 50 | 10 | 4 | 100.000 | 2.500 | Correo electrónico |
| Mediana | 500 | 100 | 30 | 1.000.000 | 25.000 | Prioritario |
| Grande | 5.000 | 1.000 | 100 | 10.000.000 | 250.000 | Dedicado |

En esta fase se aplican los límites de activos y se ha preparado el contador mensual atómico para reservar tokens, análisis y consultas. No hay conectores que generen ese consumo todavía, por lo que la cola de trabajos, los reintentos y la adaptación a límites de Microsoft, AWS y del proveedor de IA quedan para la fase de conectores.

## Pendiente y orden recomendado

1. **Invitaciones y gestión de miembros**: altas, bajas, recuperación de acceso y límites de usuarios por plan. Es el requisito previo para que una organización pueda operar con más de su propietario.
2. **Auditoría exportable**: eventos de inicio de sesión, cambios de roles, activos, configuración y ejecuciones; retención configurable y exportación para auditoría y SIEM.
3. **Identidad empresarial**: SAML/OIDC, aprovisionamiento JIT/SCIM y mapeo de grupos del IdP a roles del workspace. Requiere definir antes la política de dominio verificado y quién puede invitar o asignar roles.
4. **Jerarquía de cuentas**: una cuenta cliente con varios workspaces/tenants, permisos de administración delegada y reporting agregado con separación explícita entre tenants.
5. **Conectores y trabajos**: credenciales por tenant protegidas, cola durable, límites de concurrencia y solicitudes por proveedor, backoff exponencial con jitter, respeto de Retry-After y circuito de pausa ante límites. La reserva de tokens/API debe ocurrir antes de ejecutar cada trabajo.
6. **Despliegue dedicado en UE**: región y residencia de datos, gestión de claves, actualización/operación, copias de seguridad y requisitos de aislamiento acordados con cada cliente.

## Decisiones y límites de seguridad

- El ID de workspace que envía el navegador nunca concede acceso por sí solo. Cada operación verifica la membresía contra el ID del usuario autenticado y filtra los registros por workspace.
- Los roles viven en la base de datos de la aplicación y se aplican en el servidor; no se confía en metadatos enviados por el cliente.
- No se incluye todavía invitación de miembros, SSO empresarial, registro de auditoría, sincronización de proveedores, análisis de seguridad ni despliegue privado.
- El catálogo de planes es configuración inicial de producto, no un sistema de cobro o suscripción.
