# Guardian Nexus — fase 1 y siguientes

## Fase 1 implementada

- Inicio de sesión y registro mediante Clerk gestionado.
- Workspaces multi-tenant con pertenencia persistida por usuario.
- Verificación de sesión y permisos en el servidor; contexto de usuario y workspace dentro de transacciones.
- RLS habilitado y forzado en workspaces, miembros, activos, uso y eventos de auditoría. El API se autentica como `app_runtime_login`, un login sin privilegios elevados ni acceso directo a los datos; solo puede cambiar al rol `app_runtime`, sujeto a RLS.
- Roles básicos: owner, admin, analyst y viewer. El owner es el único que puede cambiar roles; los viewers solo leen.
- Inventario manual de activos con aislamiento por workspace y límite de activos por plan.
- Registro de auditoría para creación de workspaces, cambios de rol y altas/bajas de activos.
- Límites mensuales atómicos para análisis, tokens y consultas API en el helper de consumo; se obtiene el plan del workspace, no de datos enviados por el cliente.
- No se simulan hallazgos ni análisis. Los hallazgos solo existirán cuando se conecten fuentes y se ejecute un análisis real.

## Límites iniciales de los planes

Estos son límites de producto iniciales y se pueden ajustar antes del lanzamiento comercial.

| Plan | Activos | Usuarios | Análisis/mes | Tokens/mes | Consultas API/mes | Soporte |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Pequeña | 50 | 10 | 4 | 100.000 | 2.500 | Correo electrónico |
| Mediana | 500 | 100 | 30 | 1.000.000 | 25.000 | Prioritario |
| Grande | 5.000 | 1.000 | 100 | 10.000.000 | 250.000 | Dedicado |

En esta fase se aplica el límite de activos y existe una reserva atómica para tokens, análisis y consultas, pero todavía no hay llamadas de análisis, IA o proveedores que la consuman. La cola durable, la idempotencia, los reintentos y el respeto de límites de Microsoft, AWS y del proveedor de IA siguen pendientes. El límite de usuarios está definido en el catálogo, pero no puede imponerse hasta que exista un flujo para invitar o añadir miembros.

## Pendiente y orden recomendado

1. **Preparación de producción**: provisionar el login de runtime y aplicar/verificar las políticas y permisos mediante un procedimiento revisado y aprobado para producción antes de publicar. El trabajo actual configura solo desarrollo.
2. **Invitaciones y gestión de miembros**: altas, bajas, recuperación de acceso y aplicación de límites de usuarios por plan.
3. **Conectores consentidos de Microsoft 365/Entra y AWS**: permisos de solo lectura y mínimos; OAuth consentido para Microsoft y rol cross-account con ExternalId/STS para AWS; sin contraseñas ni credenciales permanentes.
4. **Cola y motores de seguridad reales**: jobs idempotentes, cuotas antes de ejecución, límites por proveedor, Retry-After y reintentos; validar Prowler y Maester en entornos autorizados antes de incorporarlos.
5. **Evidence & Risk y Compliance**: procedencia verificable, correlación y aplicabilidad versionada por país/sector. Separar preparación y evaluación de cualquier certificación.
6. **Auditoría exportable e identidad enterprise**: retención/exportación, SAML/OIDC, SCIM y jerarquías de cuenta solo tras definir permisos y despliegue/región UE.

## Decisiones y límites de seguridad

- El ID de workspace que envía el navegador nunca concede acceso por sí solo. Cada operación verifica la membresía del usuario autenticado dentro de la transacción y las consultas tenant-scoped también quedan sujetas a RLS.
- Los roles viven en la base de datos de la aplicación y se aplican en el servidor; no se confía en metadatos enviados por el cliente.
- El API se niega a arrancar si faltan políticas RLS calificadas, `FORCE ROW LEVEL SECURITY`, o si el login de runtime puede leer/escribir directamente o tiene privilegios elevados. Las pruebas usan la conexión de runtime para verificar aislamiento entre workspaces; una conexión administrativa separada solo prepara y limpia los datos de prueba.
- En desarrollo, `DATABASE_URL` queda reservado a migraciones y a scripts administrativos protegidos que solo apuntan a desarrollo. El API usa `APP_RUNTIME_DB_PASSWORD` junto con los datos de conexión PG de Replit, o `APP_RUNTIME_DATABASE_URL` si se configura una URL no privilegiada. El secreto se gestiona en Replit Secrets; no se copia al código ni al chat.
- Producción no se ha modificado ni publicado. Replit proporciona una conexión administrada para migraciones; el API debe recibir una URL de runtime no privilegiada y el rol/políticas equivalentes deben provisionarse de forma revisada antes de habilitar datos de clientes.
- El flujo de `drizzle-kit push` de este workspace no deja las expresiones de política en la base; `lib/db/sql/rls-policies.sql` se aplica explícitamente en desarrollo. La publicación requiere una migración/procedimiento equivalente verificado para producción.
- La auditoría actual registra cambios de workspace, roles y activos; no incluye inicios de sesión, retención configurable ni exportación.
- No se incluyen todavía invitaciones, SSO empresarial, conectores, escaneos, cola de trabajos, Compliance Engine ni despliegue privado.
- El catálogo de planes es configuración inicial de producto, no un sistema de cobro o suscripción.
