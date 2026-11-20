# Migraciones 0005–0007: base común de conectores, acciones y recibos

**Estado:** las migraciones 0005 y 0006 están **IMPLEMENTADAS en el repositorio**
y aplicadas en la base de **Development** (verificado el 2026-11-19).
**Production no se ha tocado.**

## Cambios de catálogo

`lib/db/migrations/0005_workspace_connector_foundation.sql` añade:

| Tabla | Columnas | Índices (incluida PK) | Constraints (incluida PK) | Policies |
|---|---:|---:|---:|---:|
| `workspace_connector_credentials` | 10 | 3 | 8 | 3 |
| `workspace_connector_executions` | 15 | 2 | 12 | 3 |

El contrato anterior a esta migración espera 16 tablas, 173 columnas, 44
índices, 72 constraints, 45 policies y 3 roles. Los cambios son exactamente
+2 tablas, +25 columnas, +5 índices, +20 constraints y +6 policies; los roles
no cambian. El contrato posterior es **18/198/49/92/51/3**.

`0007_workspace_approval_receipts.sql` añade la tabla append-only
`workspace_approval_receipts` con 7 columnas, 2 índices (incluida la PK), 7
constraints y 2 policies. Conserva el objeto firmado receipt v1 para que el
agente pueda reintentar tras una aprobación; no modifica receipt v1 ni ledger
event v1. El inventario del laboratorio pasa a **19/205/51/99/53/3**: +1 tabla,
+7 columnas, +2 índices, +7 constraints y +2 policies; siguen siendo 3 roles.

La auditoría también compara nombres y definiciones de constraints y policies,
flags RLS, roles y privilegios efectivos. No se ajustan los conteos para ocultar
diferencias.

## RLS y privilegios

- Las dos tablas tienen RLS habilitada y forzada.
- Las credenciales solo se pueden consultar, crear o desconectar dentro del
  workspace por owner/admin. La API no devuelve el secreto cifrado ni el texto
  descifrado.
- El historial de ejecuciones se puede consultar por miembros del workspace.
  Solo owner/admin pueden insertar una ejecución pendiente o completar una
  ejecución pendiente mediante el contexto de escritura de la API.
- Los grants de `app_runtime` están limitados por tabla y columna. El ledger
  existente mantiene intactos su formato v1, sus políticas y sus privilegios
  append-only.
- La tabla de recibos concede `SELECT` y `INSERT` solo en seis columnas; no
  concede `UPDATE`, `DELETE` ni `INSERT` sobre `created_at`. La policy de lectura
  exige que el recibo pertenezca a una aprobación del agente autenticado.

## Secuencia comprobada en el laboratorio

El laboratorio crea una base temporal y aplica, cada una en su propia
transacción, las migraciones SQL versionadas 0001–0007. Repite 0003–0007 para
comprobar idempotencia. Compara el catálogo resultante con el esquema
Drizzle: tablas, columnas, índices, constraints, policies, roles y matriz de
privilegios. También ejecuta la auditoría RLS/runtime y el E2E con un adaptador
falso sin red y una clave de bóveda efímera.

`CREATE TABLE IF NOT EXISTS` no debe considerarse una reparación automática de
una tabla preexistente con definición distinta: la auditoría compara el
contenido real y detiene el laboratorio ante cualquier deriva.

## Cifrado y rotación

La API cifra credenciales con AES-256-GCM, nonce aleatorio de 12 bytes,
etiqueta de autenticación de 16 bytes y datos autenticados ligados a workspace,
servicio e identificador de clave. El keyring se configura mediante
`WORKSPACE_CONNECTOR_KEYRING_JSON`; cada entrada contiene un `keyId` y una
clave AES de 32 bytes codificada en base64url. El laboratorio crea una clave
efímera para su proceso y no la incluye en informes.

Para rotar, se instala una clave nueva como activa y se conservan temporalmente
las anteriores para descifrar credenciales existentes. Cada conexión se vuelve
a introducir con el propietario del servicio y se reemplaza; después de
confirmar que ninguna fila usa el `keyId` anterior, esa clave puede retirarse.
No existe un endpoint para leer un secreto descifrado ni se registra en
auditoría.

## Antes de cualquier otra aplicación compartida

La aplicación a Development registrada arriba corresponde a la autorización de
Amin para esa operación. No autoriza cambios en Production ni futuras
migraciones compartidas. Cada aplicación posterior requiere una tarea aprobada
con checkpoint verificable cuando corresponda, auditoría previa, revisión del
SQL, auditoría posterior y plan de restauración.

## Estado de 0007

**IMPLEMENTADO en el repositorio y comprobado por el laboratorio local:** la
migración crea el almacenamiento de recibos firmados con RLS habilitada y
forzada, dos policies de workspace y privilegios mínimos por columna. La fase de
migraciones versionadas parte del esquema antiguo, aplica 0001–0007, compara el
inventario completo con Drizzle y repite 0007 para comprobar idempotencia.

**PROYECTADO para Development y Production:** la migración 0007 no se ha
aplicado a ninguna base compartida como parte del proxy MCP. Production no se ha
conectado ni modificado.

## Estado en Development — verificado el 2026-11-19

- **0005:** ya estaba aplicada al iniciar esta operación. El contrato anterior
  a 0005 es 16/173/44/72/45/3 y el posterior es 18/198/49/92/51/3. La fecha
  original de aplicación de 0005 no se registró en esta operación; estos son
  los recuentos del contrato, no una medición histórica del día de aplicación.
- **0006:** antes de aplicarla, Development tenía 18/198/49/92/51/3 y la única
  diferencia era la constraint
  `ai_assessment_approval_action_ref_check`, aún limitada a las dos acciones
  sintéticas antiguas. Después de aplicar 0006, el catálogo quedó en
  18/198/49/92/51/3, con cero diferencias respecto a Drizzle.
- Se aplicaron de nuevo 0005 y 0006 para comprobar idempotencia. La instantánea
  completa del catálogo tras esas segundas aplicaciones fue idéntica a la
  obtenida tras la primera 0006. RLS quedó habilitada y forzada en las 18 tablas;
  la auditoría de policies, roles, privilegios y append-only dio cero
  violaciones.
