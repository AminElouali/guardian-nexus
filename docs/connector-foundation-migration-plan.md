# Migración 0005: base común de conectores

**Estado:** la migración está **IMPLEMENTADA en el repositorio** y se prueba en
PostgreSQL desechable. En esta fase **no se aplica a desarrollo ni a
producción**.

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

## Secuencia comprobada en el laboratorio

El laboratorio crea una base temporal y aplica, cada una en su propia
transacción, las migraciones SQL versionadas 0001–0005. Repite 0003, 0004 y 0005
para comprobar idempotencia. Compara el catálogo resultante con el esquema
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

## Antes de cualquier aplicación compartida

Este documento no autoriza una aplicación en bases compartidas. Una tarea
separada tendría que incluir: checkpoint verificable, auditoría previa,
revisión de SQL, aplicación aprobada, auditoría posterior y plan de restauración.
Hasta entonces, desarrollo y producción quedan fuera del alcance.
