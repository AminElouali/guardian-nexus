# Contrato transversal de perfiles Qwen — 2026-11-04

## Cambio

Se añadió una prueba estática de contrato para evitar deriva en nombres de
perfil entre:

- lista de perfiles y fixtures de la API;
- constantes de perfil en el worker TypeScript;
- registros del worker Python y del runner offline;
- SDK TypeScript y SDK Python;
- claves de los casos seleccionados por el runner offline.

La prueba exige ocho IDs Qwen únicos e idénticos en cada componente, ocho
verticales fixture emparejadas y ocho casos offline seleccionados presentes en
el corpus fuente. Solo analiza código/contratos: **no importa pesos, no carga
el modelo, no crea jobs y no ejecuta inferencias**.

No cambió el contrato de runtime, la cola ni el gate. La API continúa
rechazando enqueue local mientras no se verifique la identidad independiente
del broker y la sesión de base de datos. El runner offline sigue fail-closed.

## Resultados

- `test_cross_layer_qwen_contract.py`: **2/2**.
- Worker focalizado: política/Qwen 31/31; delegación 8/8; revisión de nueve
  ALLOW históricos 4/4; assurance 3/3; contrato transversal 2/2.
  Total en esas cinco suites: **48/48**.
- Preflight de aislamiento offline: **11/11**, incluyendo la prueba de que el
  runner se detiene antes de cargar manifiestos/modelo cuando el límite de
  host está sin verificar.
- API: **75/75**.
- La primera invocación Python sin `PYTHONPATH` no pudo importar el paquete;
  repetida con `PYTHONPATH=workers/guardian-ai-assessment`, pasó. En el test
  transversal, las primeras ejecuciones detectaron un error en el propio
  extractor AST de prueba; se corrigió y la ejecución final pasó 2/2.

## Límite de evidencia

No se ejecutó Qwen, no se generaron resultados de inferencia y no se acreditó
un flujo API→worker Qwen. Los datos históricos siguen separados: ocho
inferencias standalone previas, siete propuestas adaptadas, cero
`message.tool_calls` nativas y una ausencia de propuesta. Los fixtures no se
presentan como inferencia.

El último preflight registrado continúa bloqueando el host por socket Docker
accesible, variables de entorno sensibles presentes y separación de broker/DB
no verificada. No se modificó el socket, el daemon, credenciales ni servicios.
