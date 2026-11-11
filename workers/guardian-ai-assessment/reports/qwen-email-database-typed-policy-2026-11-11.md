# Incremento offline de propuestas tipadas para Correo y Bases de datos — 2026-11-11

## Alcance y cambios

- Base inspeccionada: HEAD `377521899a7700562e58f81d353af101fbcc47dd`,
  rama `main`, árbol limpio antes de empezar.
- Commits de código y tests observados:
  - `a9957e61400ae560b5b523193e6d7e293ac61e7d` — refactor del recorrido
    compartido de propuestas Qwen.
  - `afecbbe` — alinea los tests sintéticos existentes con el requisito de
    pasar el catálogo completo del perfil.
- `qwen_policy_lab.py` introduce `ParsedQwenToolProposal`, que solo admite
  procedencia `guardian_qwen_native_markup_adapter` o
  `runtime_message_tool_calls`. Fixture y abstención no pueden convertirse en
  esta categoría.
- Antes de validar argumentos, el parser comprueba que la propuesta pertenece
  al catálogo completo, único y del perfil actual. Herramientas conocidas en
  otro perfil, catálogo incompleto y argumentos no representables como JSON
  se rechazan antes de Policy Engine.
- `llm_lab._native_call_arguments` ahora usa el parser JSON estricto existente
  para rechazar claves duplicadas y constantes no estándar como `NaN`.
- En `_one_case`, validación precede al Policy Engine. Argumentos inválidos,
  errores/excepciones o resultados mal formados del Policy Engine quedan en
  rechazo y nunca alcanzan el simulador. Solo `ALLOW` del Policy ON puede llamar
  al simulador ficticio. `REQUIRE_APPROVAL` y `DENY` no despachan. Policy OFF
  sigue limitado a clones contrafactuales (`executed: false`).
- `tool_choice="auto"` se conserva. Los ocho fixtures existentes no se
  modificaron.

## Pruebas realmente ejecutadas en esta iteración

Comando lógico:

```text
cd workers/guardian-ai-assessment/tests
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=.. python -m unittest -v [18 métodos focalizados de test_policy_lab]
```

Los 18 métodos seleccionados fueron:

1. `QwenPolicyLabDispatchSelfCheckTests.test_email_database_typed_proposals_validate_before_policy_and_simulator`
2. `QwenPolicyLabDispatchSelfCheckTests.test_email_database_cross_profile_tools_stop_before_validation_and_policy`
3. `QwenPolicyLabDispatchSelfCheckTests.test_email_database_policy_errors_fail_closed_before_simulator`
4. `QwenPolicyLabDispatchSelfCheckTests.test_email_database_incomplete_catalog_and_invalid_arguments_fail_closed`
5. `QwenPolicyLabDispatchSelfCheckTests.test_native_email_database_arguments_reject_ambiguous_json`
6. `QwenPolicyLabDispatchSelfCheckTests.test_email_synthetic_response_matrix_keeps_provenance_and_policy_separate`
7. `QwenPolicyLabDispatchSelfCheckTests.test_database_synthetic_response_matrix_keeps_provenance_and_policy_separate`
8. `QwenPolicyLabDispatchSelfCheckTests.test_email_synthetic_adapter_keeps_untrusted_content_out_of_system`
9. `QwenPolicyLabDispatchSelfCheckTests.test_email_and_database_abstention_never_runs_policy_or_dispatch`
10. `GuardianAgentPolicyLabTests.test_all_email_database_adversarial_adapted_markers_are_policy_gated`
11. `QwenPolicyLabDispatchSelfCheckTests.test_email_database_offline_subset_covers_header_body_and_row_cells`
12. `GuardianAgentPolicyLabTests.test_adapted_email_and_database_reads_require_policy_before_fixture_dispatch`
13. `GuardianAgentPolicyLabTests.test_shared_tool_adapter_runs_only_after_allow_and_never_in_policy_off`
14. `GuardianAgentPolicyLabTests.test_qwen_call_origin_requires_explicit_parser_provenance`
15. `GuardianAgentPolicyLabTests.test_native_adapted_and_absent_origins_stay_distinct_for_all_profiles`
16. `GuardianAgentPolicyLabTests.test_malformed_markup_for_all_profiles_is_rejected_before_policy_or_dispatch`
17. `GuardianAgentPolicyLabTests.test_adversarial_proposals_validate_before_policy_and_never_dispatch_across_origins`
18. `GuardianAgentPolicyLabTests.test_adversarial_no_proposal_stays_distinct_across_all_qwen_profiles`

Resultado final: **18 métodos pasaron, 0 fallaron** (0,062 s). La primera
selección tuvo errores de nombre de test; una corrida posterior mostró tests
preexistentes pasando catálogos vacíos. Se corrigieron únicamente esos harnesses
para pasar el catálogo de cada perfil y esperar rechazo antes de Policy cuando
la validación falla. La corrida final anterior es la que acredita el resultado.

`git diff --check` pasó. No se encontró configuración Python de mypy/pyright y
no se ejecutó un typecheck separado.

## Límites de evidencia

- Todas las respuestas de estos tests son fijas y sintéticas. El test que usa
  una estructura `message.tool_calls` solo comprueba clasificación de formato;
  no demuestra llamadas nativas emitidas por Qwen. No hubo inferencia viva,
  propuestas reales del modelo, ni carga del GGUF.
- No se ejecutaron el runner coordinador, subprocess hijos, workers, API,
  broker, servidores, Docker/socket, PostgreSQL, migraciones, red o servicios
  externos. No se leyó ni modificó `.replit`, variables o secretos.
- No se modificaron Policy Engine, fixtures, RLS ni gates. `hostBoundaryReady`
  e `integratedAssessmentReady` no fueron comprobados en runtime ni cambiados;
  esta regresión offline no acredita aislamiento, persistencia ni E2E.
- El artefacto Qwen histórico sigue separado y no se actualizó ni contabilizó
  como resultado de este cambio.

## Siguiente incremento seguro

Para Finanzas y Soporte, el siguiente test offline puede enviar respuestas
fijas por la misma ruta tipada y confirmar `REQUIRE_APPROVAL`, vínculo a la
propuesta exacta y cero despacho para `request_bank_account_change` y
`propose_synthetic_refund`. La función `_allowlisted_approval_action` ya limita
esas acciones sintéticas a casos y argumentos exactos. Esa prueba no debe
presentarse como persistencia: aprobación durable, RLS y concurrencia siguen
pendientes de una base de laboratorio desechable autorizada.
