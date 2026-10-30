# Guardian Nexus — fase 1 y siguientes

## Fase 1 implementada

- Inicio de sesión y registro mediante Clerk gestionado.
- Workspaces multi-tenant con pertenencia persistida por usuario.
- Verificación de sesión y permisos en el servidor; contexto de usuario y workspace dentro de transacciones.
- RLS habilitado y forzado en workspaces, miembros, activos, uso, auditoría, preparaciones locales y conexiones, estados OAuth y jobs. El API se autentica como `app_runtime_login`, un login sin privilegios elevados ni acceso directo a los datos; solo puede cambiar al rol `app_runtime`, sujeto a RLS.
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

En esta fase se aplica el límite de activos y existe una reserva atómica para tokens, análisis y consultas. La conexión real de Microsoft 365 y AWS requiere consentimiento explícito por workspace; las preparaciones locales de la pantalla «Preparación» son registros separados y no llaman a los proveedores. La cola tiene persistencia, idempotencia, límites de tasa, `Retry-After`, reintento y reserva de cuota, pero todavía no hay worker, análisis real ni llamadas de inventario. El límite de usuarios está definido en el catálogo, pero no puede imponerse hasta que exista un flujo para invitar o añadir miembros.

## Pendiente y orden recomendado

1. **Preparación de producción**: provisionar el login de runtime y aplicar/verificar las políticas y permisos mediante un procedimiento revisado y aprobado para producción antes de publicar. El trabajo actual configura solo desarrollo.
2. **Invitaciones y gestión de miembros**: altas, bajas, recuperación de acceso y aplicación de límites de usuarios por plan.
3. **Habilitar los proveedores en cada entorno**: registrar la aplicación OAuth de Microsoft y configurar la identidad de carga de trabajo AWS y su principal de confianza antes de permitir conexiones reales. El código no solicita contraseñas ni claves AWS permanentes.
4. **Worker y motores de seguridad reales**: ejecutar jobs idempotentes solo después del consentimiento, aplicar cuotas y límites durante las llamadas reales, y validar Prowler y Maester en entornos autorizados antes de incorporarlos.
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
- El consentimiento de Microsoft usa OAuth delegado con `Organization.Read.All` y acceso al perfil básico OpenID; consulta solo el identificador del tenant para confirmar la autorización. El refresh token se cifra antes de guardarse. Microsoft debe conceder consentimiento a los permisos solicitados; una persona administradora puede tener que aprobarlo.
- La conexión AWS solicita un rol de la cuenta del cliente, genera un `ExternalId` distinto por espacio y verifica `AssumeRole` con una sesión STS de 900 segundos. La pantalla entrega una política de confianza que restringe el principal configurado y exige ese `ExternalId`; la política de permisos indicada es `SecurityAudit` de solo lectura. El servidor requiere identidad AWS de carga de trabajo (`AWS_ROLE_ARN` y `AWS_WEB_IDENTITY_TOKEN_FILE`) y `AWS_CONNECTOR_TRUSTED_PRINCIPAL_ARN`; no acepta claves permanentes del cliente.
- Las variables `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET` y `MICROSOFT_REDIRECT_URI` deben estar configuradas para habilitar Microsoft OAuth. El callback es `/api/oauth/microsoft/callback`. Los tokens de refresh se cifran con `CONNECTOR_ENCRYPTION_KEY` dedicado si se define; en su ausencia, se deriva una clave separada desde `SESSION_SECRET`.
- Owners y admins pueden configurar o revocar conectores. Cada operación de inicio, consentimiento y revocación queda en la auditoría del workspace. Las tablas de conexiones, estados OAuth de un solo uso y jobs tienen RLS forzado y políticas tenant-scoped.
- La pantalla «Preparación» conserva un flujo de registro local separado: no concede OAuth, no llama a STS y no confirma una conexión real. Su cancelación solo cambia ese registro; no sustituye la revocación del conector real.
- Revocar desde la plataforma deshabilita el acceso local, elimina el refresh token guardado y cancela los jobs pendientes. Para retirar el consentimiento de Microsoft también debe eliminarse el acceso de la aplicación desde Microsoft 365. Las sesiones AWS emitidas pueden seguir vigentes hasta 15 minutos; para corte inmediato, el cliente debe retirar la relación de confianza del rol.
- No hay worker ni motores de escaneo conectados. La autorización y la verificación del rol no ejecutan escaneos ni generan hallazgos.
- El catálogo de planes es configuración inicial de producto, no un sistema de cobro o suscripción.
