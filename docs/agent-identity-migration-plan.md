# Plan de migración: identidad propia por agente

## Estado

- **IMPLEMENTADO:** registro de agentes por workspace, credencial opaca de alta entropía mostrada solo en la respuesta de creación/rotación y persistida únicamente como SHA-256; no se devuelve de nuevo en los listados.
- **IMPLEMENTADO:** autenticación de propuestas de agente con una credencial bearer, validación de workspace, estado de revocación y pertenencia del principal. La evidencia de propuesta registra el UUID del agente y la versión de regla.
- **IMPLEMENTADO:** rotación (invalida la credencial anterior e incrementa la versión), revocación, bloqueo de credenciales inválidas/revocadas/de otro workspace y prohibición de autoaprobación por el principal humano.
- **IMPLEMENTADO:** migración SQL versionada `lib/db/migrations/0002_workspace_agents.sql`, validada solo en el PostgreSQL desechable de `lab:local`.
- **IMPLEMENTADO:** `lib/db/migrations/0004_align_rule_check_constraint_names.sql` comprueba y alinea con Drizzle los nombres de dos constraints CHECK y tres claves foráneas heredadas de 0001/0002, sin cambiar filas. Pasó dos veces en el laboratorio desechable y se aplicó dos veces a Development el 18 de noviembre de 2026; la auditoría posterior confirmó 72/72 nombres de constraints coincidentes y los conteos de filas sin cambios.
- **IMPLEMENTADO:** tablas de reglas y agentes aplicadas a la base de desarrollo el 18 de noviembre de 2026 y verificadas con 16 tablas, 173 columnas, 44 índices, 72 constraints, 45 policies y 3 roles. Producción no se tocó.
- **PROYECTADO:** aplicación equivalente en producción.
- **PROYECTADO:** credenciales por acción o scopes configurables por agente, atestación de proceso y aislamiento del agente respecto a su principal humano.

## Cambios de catálogo

`workspace_agents` añade el identificador, workspace, nombre visible, principal humano, hash SHA-256, versión de credencial, creador, fecha de creación, revocación y último uso. La base nunca guarda el bearer original. Las policies exigen el workspace de sesión; el alta y los cambios administrativos requieren owner/admin. Una policy de lectura adicional permite localizar exactamente la fila cuya huella coincide con la credencial presentada, solo mientras no esté revocada.

La migración concede a `app_runtime` `SELECT`, `INSERT` y `UPDATE` sobre esta tabla, sujetos a RLS forzado. No cambia grants, policies ni constraints de otras tablas. Los endpoints administrativos no entregan el hash; el endpoint de propuesta solo compara la huella calculada y atribuye la propuesta al agente autenticado.

### Delta y recuentos

La migración `0002_workspace_agents.sql` añade:

| Categoría | Delta |
|---|---:|
| Tablas | 1 |
| Columnas | 10 |
| Índices | 3, incluido el índice de PK |
| Constraints | 5, incluida PK, FK y tres checks |
| Policies | 4 |
| Roles | 0 |

Con las migraciones 0001, 0002 y 0003 aplicadas al catálogo, el inventario completo esperado desde la base anterior es **16 tablas, 173 columnas, 44 índices, 72 constraints, 45 policies y 3 roles**. Las dos tablas de reglas aportan 14 columnas, 4 índices, 13 constraints y 5 policies; la tabla de agentes aporta 10 columnas, 3 índices, 5 constraints y 4 policies. La migración 0003 añade la constraint única al índice ya existente sin crear un índice adicional.

## Procedimiento futuro para una base compartida

Este procedimiento es una guía, no una autorización de ejecución.

1. Crear y verificar un punto de restauración de Replit para la base seleccionada.
2. Ejecutar el auditor de catálogo de solo lectura antes de cambiar nada. Confirmar la identidad de base y la matriz de privilegios. Si hay diferencias ajenas al inventario documentado, parar.
3. Aplicar `0001_workspace_action_rules.sql`, `0002_workspace_agents.sql`, `0003_workspace_rule_version_unique_constraint.sql` y `0004_align_rule_check_constraint_names.sql` en ese orden, cada una en transacción separada. La 0004 verifica las dos expresiones CHECK y las tres referencias a `workspaces` antes de renombrarlas; no modifica filas. No ejecutar bootstrap de roles ni cambiar contraseñas como parte de estas migraciones.
4. Ejecutar el auditor completo y comprobar exactamente **16/173/44/72/45/3**, 0 violaciones, RLS habilitado y forzado en las tres tablas y políticas de workspace.
5. Probar como owner/admin la creación, rotación y revocación; como viewer, el rechazo de administración; con credencial inválida o de otro workspace, el rechazo de propuestas; y la imposibilidad de que el principal apruebe su propia propuesta.
6. Confirmar que no se exponen credenciales en logs, listados ni respuestas posteriores. Si una verificación falla, parar y considerar restaurar el punto de restauración anterior.

## Riesgos y límites

- La credencial bearer es un secreto para el agente; el usuario debe guardarla en un gestor seguro. El panel la mantiene solo en memoria mientras se muestra y la oculta al cambiar de sección.
- SHA-256 protege contra recuperación directa de una credencial aleatoria de alta entropía, pero no protege si el host, el proceso API o el dispositivo donde se muestra están comprometidos.
- El principal humano del agente debe seguir siendo miembro del workspace. Si pierde acceso, el agente deja de poder proponer.
- La aprobación sigue siendo humana y separada; la identidad de agente no concede permiso para aprobar.
- El registro de identidad no conecta herramientas ni prueba que un agente externo use esta API. La aplicación del guard en todas las rutas de ejecución sigue siendo trabajo separado.
