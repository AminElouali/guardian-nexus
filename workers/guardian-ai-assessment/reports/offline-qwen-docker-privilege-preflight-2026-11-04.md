# Preflight de privilegios Docker del runner Qwen offline — 2026-11-04

## Resultado

El runner autónomo ahora **se niega a iniciar** si el proceso puede usar un
endpoint Docker configurado o escribir un socket Docker local. No se creó un
modo de ejecución API/worker sin Docker ni se atribuye una frontera de
privilegios a un subproceso del mismo usuario. En el host actual, la evaluación
Qwen offline no es segura bajo el requisito de carecer de privilegios Docker:
el preflight detiene el proceso antes de cargar el modelo.

Base antes del cambio: commit `8d81f357dbf2aa510026b96bb57683779849f85c`,
árbol limpio.

## Cambio verificable

- `offline_qwen_runner.py` comprueba `DOCKER_HOST`, `DOCKER_CONTEXT` y
  `CONTAINER_HOST`, además de los sockets Docker conocidos. Ante un endpoint
  configurado, socket escribible, error de inspección o ruta que no sea socket,
  termina con un código de razón `offline_*`, sin imprimir el valor del
  endpoint. La comprobación ocurre antes de cargar artefactos o pesos.
- `run_qwen_policy_lab_offline.py` solo muestra códigos de razón acotados por
  una expresión allow-list; otros errores se reducen al tipo de excepción.
- La prueba del socket usa un socket Unix temporal, no el socket del host.
- Esto es un **preflight**, no un sandbox ni una revocación de permisos. No
  impide que otros procesos del mismo UID utilicen Docker.

## Bloqueo observado en el host

Lectura del host: proceso UID/GID `1000:1000`, grupo `1000`; `/var/run/docker.sock`
es un socket propiedad `0:1000`, modo `0660`, legible y escribible por el
proceso. No se cambió el socket, los grupos, el daemon ni los permisos.

El CLI devolvió antes de cargar el modelo:

```text
offline_qwen_suite_failed:offline_docker_socket_accessible
exit_code=1
```

El endpoint de control no se conectó. No se usó Docker para iniciar contenedores
en este incremento, ni se cambió de UID ni se intentó modificar permisos.

El artefacto anterior de ocho inferencias reales sigue en disco con SHA-256
`6a1e54658f745074a7a5a937204181c219ec28d184a866845dd09513497ee1d9`; declara
como runner `818e7cd792d470c18732e75894679f0ad8d20157ecdf331ecdf127cc5b4445b0`.
Ese hash **no coincide** con el runner actual
`e682cc964a0e6e695ad48c555b040ed3f1590a28e36a3a64c9afaef5641d4213`.
Por tanto, el artefacto es evidencia histórica del modelo, no evidencia de una
inferencia ejecutada después de este preflight. No se generó evidencia Qwen
nueva ni se modificó el artefacto histórico.

## Pruebas y builds

- Preflight/seccomp: `python3 -m unittest discover -s tests -p
  'test_offline_process_guard.py' -v`: **10/10**.
- Worker Python en el host, excluyendo únicamente
  `test_corpus_validation.py`: **143/143**. La suite completa del host detectó
  141 pruebas y tuvo un error de importación por `ModuleNotFoundError: garak`;
  no se instaló ninguna dependencia.
- No se ejecutó `scripts/run-local.sh --unit-tests`: ese comando iniciaría un
  contenedor Docker, lo cual contradiría la condición local de no usar una
  identidad con privilegios Docker. La suite dentro de la imagen, por tanto, no
  se volvió a validar en este incremento.
- API: **74/74**; typecheck y build pasaron.
- SDK: **13/13**; build pasó.
- `pnpm run typecheck`: pasó para librerías, API, UI, scripts y mockup.
- Dashboard: integración de componentes **8/8**. El build/typecheck de la UI
  pasó; el build conserva avisos de ubicación sourcemap de `tooltip.tsx` y de
  chunk JavaScript mayor de 500 kB.
- API/worker E2E: **0/9**. El `before` hook falla en
  `src/ai-assessment-e2e.test.ts:103` porque el worker informa `disabled` en vez
  de `ready`; no se entró en los cuerpos de prueba ni se crearon jobs de estos
  E2E. La comprobación de preparación RLS ocurre antes. La fase de componentes
  del dashboard del mismo comando sí terminó **8/8** con identidad sintética;
  no equivale a una sesión Clerk real.
- No se ejecutó inferencia Qwen nueva, ejecución de Garak ni flujo de
  aprobación persistente vinculado a una inferencia nueva.

## Hashes

El manifiesto complementario
`reports/offline-qwen-docker-privilege-preflight-2026-11-04.sha256` cubre los
archivos fuente, pruebas, informe, checkpoint y la evidencia histórica citada.
No incluye su propio hash.

## Siguiente desbloqueo y límites

Para reanudar E2E de worker o inferencia Qwen se requiere un host de desarrollo
que pueda demostrar una identidad de worker separada, inaccesibilidad real del
socket desde API y credenciales DB independientes para el broker. No se debe
sortear este bloqueo ejecutando un subproceso con el mismo UID, elevando
permisos, quitando controles del runner o habilitando el worker local actual.

Quedan sin verificar aquí: ejecución Qwen bajo el nuevo preflight, persistencia
de aprobaciones para esas inferencias, sesión Clerk real, aislamiento IPv6
dual-stack y remediación de supply-chain/licencias. No se modificó producción,
no se publicaron cambios ni se conectaron servicios externos.
