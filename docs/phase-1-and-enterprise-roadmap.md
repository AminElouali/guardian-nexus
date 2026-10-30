# Guardian Nexus — fase 1 y siguientes

## Fase 1 implementada

- Inicio de sesión y registro mediante Clerk gestionado.
- Workspaces multi-tenant con pertenencia persistida por usuario.
- Verificación de sesión y permisos en el servidor; contexto de usuario y workspace dentro de transacciones.
- RLS habilitado y forzado en workspaces, miembros, activos, uso, auditoría y preparaciones de integraciones. El API se autentica como `app_runtime_login`, un login sin privilegios elevados ni acceso directo a los datos; solo puede cambiar al rol `app_runtime`, sujeto a RLS.
- Roles básicos: owner, admin, analyst y viewer. El owner es el único que puede cambiar roles; los viewers solo leen.
- Inventario manual de activos con aislamiento por workspace y límite de activos por plan.
- Registro de auditoría para creación de workspaces, cambios de rol y altas/bajas de activos.
- Límites mensuales atómicos para análisis, tokens y consultas API en el helper de consumo; se obtiene el plan del workspace, no de datos enviados por el cliente.
- No se simulan hallazgos ni análisis. Los hallazgos solo existirán cuando se conecten fuentes y se ejecute un análisis real.

## Fase 2 — preparación previa al consentimiento

- Se pueden registrar, por workspace, un tenant de Microsoft Entra y una cuenta AWS. Las operaciones son idempotentes por proveedor y cuenta, requieren rol owner, quedan en auditoría y están sujetas a RLS.
- Microsoft muestra el permiso de aplicación `Organization.Read.All`, correspondiente a metadatos de organización; requiere consentimiento administrativo. No equivale a permisos para evaluar la postura completa.
- AWS genera un ExternalId aleatorio y único para el setup de cada workspace/cuenta. No se guarda una clave AWS ni se llama a STS.
- La UI distingue preparación pendiente de conexión activa. No se ha solicitado consentimiento externo, no hay tokens guardados, no hay llamadas reales a Graph o AWS y no se afirma que un proveedor esté conectado.
- La revocación disponible cancela únicamente el registro local. Si el cliente concedió permisos o creó una trust policy fuera de la plataforma, debe revocarlos también en el proveedor.
- Hay un lector Graph limitado a HTTPS `graph.microsoft.com/v1.0` y a GET, con prueba simulada de `429`/`Retry-After`. Aún no está conectado a OAuth, a una cola durable ni a un job de tenant.
- Las capacidades presentes en configuración son indicadores declarativos, no validaciones de credenciales o de acceso. Este entorno no cuenta con registro de aplicación Microsoft ni identidad de workload AWS acreditados.

## Límites iniciales de los planes

Estos son límites de producto iniciales y se pueden ajustar antes del lanzamiento comercial.

| Plan | Activos | Usuarios | Análisis/mes | Tokens/mes | Consultas API/mes | Soporte |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Pequeña | 50 | 10 | 4 | 100.000 | 2.500 | Correo electrónico |
| Mediana | 500 | 100 | 30 | 1.000.000 | 25.000 | Prioritario |
| Grande | 5.000 | 1.000 | 100 | 10.000.000 | 250.000 | Dedicado |

En esta fase se aplica el límite de activos y existe una reserva atómica para tokens, análisis y consultas, pero todavía no hay llamadas de análisis, IA o proveedores que la consuman. Los registros de preparación son idempotentes, pero no existen aún jobs externos, cuota por llamadas de proveedor ni cola durable. El lector Graph prueba `Retry-After`, pero la programación diferida para esperas largas y la política de reintentos de producción siguen pendientes. El límite de usuarios está definido en el catálogo, pero no puede imponerse hasta que exista un flujo para invitar o añadir miembros.

## Pendiente y orden recomendado

1. **Preparación de producción**: provisionar el login de runtime y aplicar/verificar las políticas y permisos mediante un procedimiento revisado y aprobado para producción antes de publicar. El trabajo actual configura solo desarrollo.
2. **Invitaciones y gestión de miembros**: altas, bajas, recuperación de acceso y aplicación de límites de usuarios por plan.
3. **Completar conectores consentidos**: registrar y verificar la aplicación OAuth multi-tenant de Microsoft, implementar `state`/callback y validación de tenant antes de solicitar consentimiento; definir una identidad de workload AWS no basada en claves permanentes, trust policy de mínimo privilegio y validación STS. Añadir revocación real en el proveedor.
4. **Cola y motores de seguridad reales**: jobs idempotentes, cuotas antes de ejecución, límites por proveedor, Retry-After con reprogramación diferida y reintentos; validar Prowler y Maester en entornos autorizados antes de incorporarlos.
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
- No se incluyen todavía invitaciones, SSO empresarial, conexiones reales de proveedores, escaneos, cola de trabajos, Compliance Engine ni despliegue privado. Las pantallas actuales guardan únicamente preparación local.
- El catálogo de planes es configuración inicial de producto, no un sistema de cobro o suscripción.

## Fuentes oficiales consultadas para la fase 2

- Microsoft Graph `GET /organization` y permisos: https://learn.microsoft.com/en-us/graph/api/organization-list?view=graph-rest-1.0
- Microsoft Entra consentimiento administrativo: https://learn.microsoft.com/en-us/entra/identity-platform/v2-admin-consent
- Microsoft Graph throttling y `Retry-After`: https://learn.microsoft.com/en-us/graph/throttling
- AWS ExternalId / confused deputy: https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html
- AWS STS `AssumeRole` y credenciales temporales: https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
