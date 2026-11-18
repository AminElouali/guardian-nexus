# Plan de migración: reglas persistentes por workspace

## Estado

- **IMPLEMENTADO:** manifiesto versionado de acciones y reglas iniciales; evaluación determinista; borradores y versiones inmutables por workspace; activación, simulación de borradores y reversión creando una versión nueva; auditoría de cada cambio; interfaz de reglas, plantillas de inicio y casos sintéticos.
- **IMPLEMENTADO:** las propuestas y previsualizaciones genéricas leen la regla activa. Sin configuración, el resultado es `deny` (`workspace_rule_not_configured`). Las decisiones persistidas incorporan el identificador y el hash de la versión usada.
- **IMPLEMENTADO:** migraciones SQL versionadas `0001_workspace_action_rules.sql` y `0003_workspace_rule_version_unique_constraint.sql`, probadas con PostgreSQL local desechable. La segunda adjunta el índice único existente como constraint, sin crear otro índice ni modificar filas.
- **IMPLEMENTADO:** aplicadas a la base de desarrollo el 18 de noviembre de 2026; la auditoría posterior confirmó 16 tablas, 173 columnas, 44 índices, 72 constraints, 45 policies y 3 roles. Producción no se tocó.
- **PROYECTADO:** aplicar cambios equivalentes a producción. La reversión operativa de una regla consiste en crear y activar una versión nueva basada en una anterior; no borra el historial.

## Cambios de catálogo

La migración añade dos tablas:

1. `workspace_action_rule_versions`: historial append-only con documento JSON validado por el servicio, número de versión, actor y fecha.
2. `workspace_action_rule_heads`: punteros a la versión activa y al borrador por workspace y tipo de acción.

Ambas tablas tienen RLS habilitado y forzado. Las versiones permiten a `app_runtime` solo `SELECT` e `INSERT`; los punteros permiten `SELECT`, `INSERT` y `UPDATE` con policies limitadas a owner/admin del mismo workspace. Se agregan dos policies de lectura/escritura de versiones y tres para los punteros. No se modifica el esquema del recibo v1, el ledger, sus grants, sus policies ni OIDC.

### Recuentos

La auditoría deriva los objetos desde Drizzle, SQL y el contrato de roles. Respecto al catálogo base previo:

| Categoría | Antes | Añadido | Esperado después |
|---|---:|---:|---:|
| Tablas | 13 | 3 | 16 |
| Columnas | 149 | 24 | 173 |
| Índices | 37 | 7 | 44 |
| Constraints | 54 | 18 | 72 |
| Policies | 36 | 9 | 45 |
| Roles | 3 | 0 | 3 |

El delta incluye 14 columnas, 4 índices, 13 constraints y 5 policies de las dos tablas de reglas; la tabla de agentes añade 10 columnas, 3 índices, 5 constraints y 4 policies. La migración 0003 convierte el índice único ya contado en una constraint respaldada por ese mismo índice, por lo que el total de índices no aumenta. No se ajustaron los conteos para ocultar diferencias: se alineó el SQL versionado con la constraint `unique(...)` del esquema Drizzle.

## Procedimiento futuro para una base compartida

Este procedimiento es una guía, no una autorización de ejecución.

1. Crear y verificar un punto de restauración de Replit para la base seleccionada.
2. Confirmar explícitamente el entorno, la base y la ventana de mantenimiento. No usar `drizzle-kit push` como sustituto de la migración versionada.
3. Ejecutar el auditor de catálogo en modo solo lectura y guardar el informe saneado. Debe coincidir con el inventario previo conocido; ante objetos sobrantes, cambios de grants o cualquier deriva no explicada, parar.
4. Aplicar `0001_workspace_action_rules.sql`, `0002_workspace_agents.sql` y `0003_workspace_rule_version_unique_constraint.sql` dentro de transacciones, en ese orden, mediante el mecanismo de migración aprobado para esa base.
5. Volver a ejecutar el auditor completo. Verificar tabla, columnas, índices, constraints, policies, roles y la matriz de privilegios. Confirmar en particular RLS habilitado y forzado y que las versiones no conceden `UPDATE`, `DELETE` o `TRUNCATE` a `app_runtime`.
6. Probar lectura, creación de borrador, activación, simulación, reversión como nueva versión y rechazo a un miembro que no sea owner/admin.
7. Si una comprobación falla, no continuar con la migración siguiente ni corregir datos automáticamente. Evaluar restaurar el punto anterior.

## Riesgos y límites

- La FK a `workspaces` usa `ON DELETE CASCADE`: eliminar un workspace elimina su historial de reglas y sus punteros.
- `workspace_action_rule_versions` es append-only para el rol de runtime; el historial no ofrece borrado individual.
- La validación completa del documento se realiza también en el servicio. Los checks SQL son una defensa estructural, no sustituyen esa validación.
- La reversión de una decisión de reglas es auditable y crea una versión; no hay un botón para borrar versiones.
- El “modo sombra” de la interfaz no persiste una política paralela ni autoriza acciones. La simulación es sintética y no despacha herramientas.
- El catálogo y la interfaz solo cubren acciones registradas; un tipo desconocido y toda acción sin regla activa permanecen bloqueados.
