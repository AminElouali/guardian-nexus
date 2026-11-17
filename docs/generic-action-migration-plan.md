# Plan de migración del catálogo de acciones

**Estado: DOCUMENTO; no se ha ejecutado en desarrollo ni producción.** El
cambio se ensaya únicamente en el PostgreSQL desechable de `lab:local`.

## Alcance exacto

La única diferencia de esquema prevista es sustituir la constraint
`ai_assessment_approval_action_ref_check` de
`public.ai_assessment_approval_requests`. La lista queda sincronizada con
`APPROVAL_ACTION_CATALOG` y contiene exactamente:

- `guardian.synthetic.finance.bank-change.v1`
- `guardian.synthetic.support.refund.v1`
- `guardian.support.reply.send.v1`
- `guardian.email.send.external.v1`

La regla de que `synthetic_action_ref` y `action_sha256` sean ambos nulos o
ambos presentes se conserva. La constraint de procedencia
`ai_assessment_approval_provenance_check`, las tablas, índices, FKs, políticas,
flags RLS, grants y roles no cambian. Los recuentos esperados del catálogo
siguen siendo **13 tablas / 149 columnas / 37 índices / 54 constraints /
36 policies / 3 roles**: se reemplaza una constraint, no se añade otra.

## SQL previsto

Este SQL refleja la definición en
`lib/db/sql/rls-policies.sql`. Debe revisarse contra el commit que se vaya a
aplicar; no es un comando para ejecutar automáticamente.

```sql
BEGIN;

ALTER TABLE public.ai_assessment_approval_requests
  DROP CONSTRAINT ai_assessment_approval_action_ref_check;

ALTER TABLE public.ai_assessment_approval_requests
  ADD CONSTRAINT ai_assessment_approval_action_ref_check CHECK (
    (synthetic_action_ref IS NULL AND action_sha256 IS NULL)
    OR (synthetic_action_ref IN (
      'guardian.synthetic.finance.bank-change.v1',
      'guardian.synthetic.support.refund.v1',
      'guardian.support.reply.send.v1',
      'guardian.email.send.external.v1'
    ) AND action_sha256 IS NOT NULL)
  );

COMMIT;
```

El cambio no elimina ni reescribe filas. PostgreSQL comprobará las filas
existentes al añadir la constraint; una violación debe abortar la transacción.
No se debe corregir una fila a mano para forzar el resultado.

### Reversión

La reversión de la definición de constraint es posible solo mientras no haya
filas que usen las dos referencias nuevas. Verificarlo es una condición previa;
si existe alguna, detenerse y diseñar una reversión de datos separada, sin
borrar ni reescribir aprobaciones.

```sql
BEGIN;

ALTER TABLE public.ai_assessment_approval_requests
  DROP CONSTRAINT ai_assessment_approval_action_ref_check;

ALTER TABLE public.ai_assessment_approval_requests
  ADD CONSTRAINT ai_assessment_approval_action_ref_check CHECK (
    (synthetic_action_ref IS NULL AND action_sha256 IS NULL)
    OR (synthetic_action_ref IN (
      'guardian.synthetic.finance.bank-change.v1',
      'guardian.synthetic.support.refund.v1'
    ) AND action_sha256 IS NOT NULL)
  );

COMMIT;
```

## Procedimiento futuro para desarrollo

1. La persona responsable crea un checkpoint de Replit de la base de desarrollo
   y confirma explícitamente cuál base se va a modificar. El checkpoint no es
   un backup portable ni sustituye una restauración probada.
2. Ejecutar el auditor independiente de catálogo en modo solo lectura. Guardar
   su informe saneado y detenerse si hay diferencias distintas a esta
   constraint. Revisar también filas de metadatos necesarias para confirmar que
   no hay valores de `synthetic_action_ref` fuera de los cuatro admitidos; no
   leer contenido de propuestas.
3. Revisar el SQL de arriba y compararlo con la definición Drizzle y el SQL del
   commit elegido. No usar `drizzle-kit push` como prueba de éxito. No ejecutar
   si la vista previa incluye cualquier otro objeto o una operación de pérdida
   de datos.
4. Aplicar la transacción exacta. Si hay error, comprobar que quedó revertida
   y detenerse; no reintentar con SQL distinto.
5. Volver a ejecutar el auditor. Exigir los mismos recuentos
   **13/149/37/54/36/3**, cero violaciones y el hash/definición de constraint
   esperado. Verificar que procedencia, RLS, policies y privilegios append-only
   no cambiaron.
6. Probar las propuestas, decisiones y verificación de recibos; no conectar
   proveedores externos. Si cualquier resultado no coincide exactamente,
   detenerse y considerar restauración del checkpoint por la persona usuaria.

## Riesgos y límites

- Añadir la constraint puede tomar un bloqueo y escanear la tabla. El tamaño y
  el tiempo de bloqueo de producción no se han medido.
- La lista expresa referencias registradas en el esquema, no una autorización
  de ejecución. El catálogo y el guard deben rechazar acciones no soportadas.
- El recibo v1, el binding, la constraint de procedencia, RLS y los privilegios
  del ledger no se alteran con este plan.
- No se ha demostrado la migración sobre datos de desarrollo ni producción.
