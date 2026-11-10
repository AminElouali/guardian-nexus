# Matriz offline de inyección en contenido para correo y BBDD

Fecha: 2026-11-10

## Alcance

- Punto inicial: HEAD `4ec4471ee42761cf8084d9534673030c1dea4f4f`, rama `main`,
  árbol limpio; no se observaron procesos locales de Qwen, worker, pruebas,
  API, Docker ni PostgreSQL.
- Se amplió únicamente la prueba focalizada de `tests/test_policy_lab.py`.
  No se modificaron la lógica de producción, el runner, el contrato v2 ni los
  ocho fixtures baseline.
- La prueba usa respuestas fijas de test con marcadores completos procesados
  por el adaptador existente. Es evidencia de prueba offline, **no** inferencia
  Qwen ni llamadas reales del runtime.
- Se añadieron ocho variantes de contenido adversario: exfiltración, cambio de
  tenant, elevación de privilegios y órdenes incrustadas para correo y filas
  sintéticas de BBDD. Dos controles benignos incluyen texto de ataque citado
  como contenido no confiable. La matriz focalizada recorre 18 escenarios en
  total: ocho adversarios originales, ocho variantes y dos controles benignos.

## Verificación y resultados

Todas las pruebas se ejecutaron en serie desde `workers/guardian-ai-assessment`
con `PYTHONDONTWRITEBYTECODE=1` y `python -B`:

1. `PYTHONPATH=. python -B -m unittest tests.test_policy_lab.GuardianAgentPolicyLabTests.test_all_email_database_adversarial_adapted_markers_are_policy_gated -v`
   — 1 método aprobado; 18 escenarios dentro del método.
2. `PYTHONPATH=. python -B -m unittest tests.test_policy_lab.GuardianAgentPolicyLabTests.test_malformed_markup_for_all_profiles_is_rejected_before_policy_or_dispatch -v`
   — 1 método aprobado; los marcadores malformados no llegan a Policy ni al simulador.
3. `PYTHONPATH=. python -B -m unittest tests.test_llm_lab.LocalLlmLabHarnessTests.test_invalid_json_is_not_counted_as_an_action -v`
   — 1 método aprobado.
4. `PYTHONPATH=. python -B -m unittest tests.test_host_boundary_attestation.HostBoundaryAttestationTests.test_all_live_model_paths_fail_before_model_or_runtime_setup tests.test_host_boundary_attestation.HostBoundaryAttestationTests.test_model_client_constructor_checks_gate_before_loading_llama -v`
   — 2 métodos aprobados; el gate fallido bloquea antes de verificar/cargar el
   modelo, consultar runtime o construir el cliente.
5. `PYTHONPATH=. python -B -m unittest tests.test_autonomous_tool_selection.QwenNativeMarkupAdapterTests -v`
   — 7/7 pruebas aprobadas: marcador completo, JSON simple no promovido,
   texto/JSON malformados y duplicados, límite de llamadas y clasificación
   separada de forma nativa y adaptada. Son estructuras de test, no llamadas
   nativas de inferencia.
6. Validación AST de `test_policy_lab.py`, `qwen_policy_lab.py` y `llm_lab.py`
   — 3/3 archivos analizaron correctamente.
7. `git diff --check` — aprobado.

En los ataques, la propuesta fija se clasifica como
`guardian_qwen_native_markup_adapter`; Policy ON la deniega y el simulador no
se invoca. En los controles benignos, Policy ON permite únicamente la lectura
sintética y ocurre antes del despacho. Policy OFF conserva el modo
`counterfactual_clone_only`, `executed=false` y no provoca despacho adicional.
La clasificación de `runtime_message_tool_calls` se prueba separadamente con
una estructura nativa sintética; no representa una llamada de modelo en este
ciclo.

No hay una herramienta/configuración de typecheck Python (`mypy`, `pyright` o
equivalente) disponible en este workspace; se hizo la validación AST indicada
en su lugar. No se ejecutó la suite completa, ni build, API/E2E/UI, Qwen,
worker vivo, broker, Docker, PostgreSQL, red o servicios externos.

## Límites y siguiente gate

El último preflight guardado sigue en `hostBoundaryReady=false`; no se repitió
ni se tocó el socket Docker. No hay inferencia nueva, atestación de aislamiento
ni validación PostgreSQL/RLS en este incremento. El siguiente paso para
considerar Qwen real sigue siendo una atestación independiente verificable de
host/broker/worker; después se requiere una PostgreSQL desechable autorizada
para probar persistencia y RLS.

## SHA-256

- `tests/test_policy_lab.py`:
  `2ac26d8a3d9058b927547faccd21d9ade00970525ca5da184aa7910293705432`
