# Matriz offline de propuestas adaptadas: seis perfiles restantes

Fecha: 2026-11-10

## Alcance

- Punto de partida: HEAD `aec38e057d7f44125e8e0fcf4e9f1ba90e22febf`,
  rama `main`, árbol limpio.
- Se añadió únicamente una prueba a `tests/test_policy_lab.py`; no se cambió
  lógica de producción ni se modificaron los ocho fixtures baseline.
- La prueba cubre los casos adversarios definidos para finanzas (4), soporte
  (5), programación (4), navegador (4), infraestructura (4) y multiagente (7),
  además de un control benigno por perfil y las dos propuestas ficticias de
  aprobación de finanzas/soporte: 36 escenarios en total.
- Las respuestas son marcadores completos construidos por un test double fijo
  y procesados por el adaptador real. Esto no es inferencia Qwen ni una llamada
  runtime `message.tool_calls`.

## Comprobaciones

- Los 28 escenarios adversarios produjeron `DENY` y no invocaron el simulador:
  cero eventos de herramienta y cero referencias/hash de acción aprobable.
- En los seis controles benignos, el despacho sintético ocurre una sola vez y
  únicamente después de que la función independiente de Policy ON devuelve
  `ALLOW`.
- Las dos propuestas ficticias de finanzas/soporte quedan en
  `REQUIRE_APPROVAL`, con sus referencias y hashes de acción del contrato, sin
  invocar el simulador. Esto solo comprueba el contrato en memoria; no acredita
  persistencia, PostgreSQL ni RLS.
- En todos los escenarios, Policy OFF conserva
  `counterfactual_clone_only` y `executed=false`; no produce un despacho
  adicional.
- La procedencia adaptada se comprueba como
  `guardian_qwen_native_markup_adapter`; una forma runtime nativa se clasifica
  por separado como `runtime_message_tool_calls`. Para cada perfil también se
  comprueba que el baseline conserva `deterministic_fixture`,
  `controlled_fixture_not_llm`, `modelInference=false` y su número de muestras.

## Pruebas y límites

Única suite ejecutada, desde `workers/guardian-ai-assessment`:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python -m unittest \
  tests.test_policy_lab.GuardianAgentPolicyLabTests.test_remaining_profiles_adapted_markers_are_policy_gated_offline -v
```

Resultado final: **1 método aprobado, 36 escenarios cubiertos**. Durante el
desarrollo hubo dos errores del test al resolver el ID de perfil del baseline y
un fallo de expectativa del estado de despacho; se corrigió únicamente el test,
y las dos ejecuciones finales pasaron. No se encontró defecto de producción.
`git diff --check` pasó.

No se ejecutaron otras suites, builds, API/E2E/UI, Qwen, worker vivo, broker,
Docker, PostgreSQL, red ni servicios externos. Los controles de aprobación son
contractuales y sintéticos; no son prueba de persistencia/RLS.

El último preflight host registrado sigue indicando `hostBoundaryReady=false`;
no se volvió a ejecutar. El gate de inferencia permanece cerrado. El siguiente
paso operativo es la atestación independiente host/broker/worker. Solo después,
y con una PostgreSQL desechable autorizada para validar persistencia/RLS,
puede considerarse la siguiente integración real, empezando por correo/BBDD.

## SHA-256

- Test actualizado: `tests/test_policy_lab.py`
  `781d253f67aadb58ab5f8eeb7db20c3b9eedbec501c9e3d6a12cf39fb7a78451`

