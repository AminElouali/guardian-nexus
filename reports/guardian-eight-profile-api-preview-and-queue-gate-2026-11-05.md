# Guardian Nexus — API preview de ocho perfiles y gate de cola

Fecha: 2026-11-05  
Base: HEAD `0433f4fb70e403e3cf48c4d8ebcb9c1c321e1d00`, árbol limpio antes del cambio.

## Resultado

Se amplió el E2E sintético existente. El endpoint autenticado de preview ejecutó
por API el worker Python determinista para los ocho perfiles. La evidencia de
cada perfil fue validada por el contrato generado: `deterministic_fixture`,
`modelInference=false` y `controlled_fixture_not_llm`. En cada caso, Policy ON
precedió al simulador: ALLOW llegó únicamente al simulador sintético; DENY no
ejecutó; REQUIRE_APPROVAL permaneció sin despacho. Policy OFF se mantuvo como
clon contrafactual sin invocaciones. No se crearon trabajos ni historial a
partir de los previews.

Se comprobó también el límite de cola: las ocho solicitudes de perfiles fixture
y las ocho de perfiles Qwen devolvieron 503 antes de insertar un job. El gate
del worker/broker no se cambió. El E2E existente de aprobaciones persistentes
para finanzas y soporte sigue siendo fixture-only.

## Verificación ejecutada en serie

- API/E2E sintético: 1/1; ocho previews por endpoint y 16 rechazos del gate de
  cola, sin filas nuevas de job para previews o solicitudes bloqueadas.
- API unit/integration: 79/79.
- Worker determinista: `test_policy_lab.py` 35/35; `test_llm_tool_adapter.py`
  5/5; `test_cross_layer_qwen_contract.py` 2/2.
- UI integración: 12/12.
- Typecheck del monorepo: correcto.
- El artefacto E2E declara `modelInference=false`, `brokerUsed=false` y
  `externalEffects=false`.

El E2E usó el servidor HTTP de prueba en loopback y la conexión PostgreSQL de
desarrollo para registros sintéticos de aprobación. No se inspeccionaron ni
imprimieron valores de credenciales. No se usó producción, Docker, Qwen ni
servicios de clientes.

## Evidencia y hashes

- Test E2E extendido:
  `artifacts/api-server/src/ai-assessment-synthetic-approval-e2e.test.ts`,
  SHA-256 `0a514440ed82d1bfb63fd27eb202bd8042fe1c99a32b833fb70e7f8e206f8256`.
- Artefacto sintético:
  `generated-artifacts/guardian-synthetic-approval-e2e.json`,
  SHA-256 `63783bc0e1941fc8c6c189b3cb2e93257a75bdbd676e4073f27eb067cb9d7f15`;
  hash de evidencia incluido `197e33aba3967b7fa943642918b3184f9474c05dce8fd4f4fe57282280d867e1`.
- Qwen histórico (no nuevo):
  `generated-artifacts/guardian-qwen-offline/qwen-policy-lab-eight-profiles.json`,
  SHA-256 `6a1e54658f745074a7a5a937204181c219ec28d184a866845dd09513497ee1d9`.
- Último preflight persistido (no repetido):
  `generated-artifacts/guardian-qwen-offline/preflight-status-2026-11-04.json`,
  SHA-256 `0b6246f76877a2874dc7834cacba1c76979a61e7871b1371515268dee8e85f52`.

El manifiesto `.sha256` de este informe fija hashes del informe, test y
artefactos anteriores; verificar con `sha256sum -c`.

## Límites y estado

Esto demuestra la ruta autenticada API → proceso Python determinista →
Policy ON → simulación en memoria; **no** demuestra API → cola → worker aislado.
La evidencia del preview marca `network=host_network_unisolated`,
`processIsolation=shared_api_identity` y `dockerSocketAccess=not_assessed`.
Por ello no es una frontera de aislamiento y no habilita Qwen.

No se ejecutó inferencia Qwen nueva. La evidencia anterior sigue siendo
histórica: 8 inferencias, 7 marcadores adaptados, 0 llamadas nativas
`message.tool_calls` y 1 `NO_PROPOSAL`; no acredita ocho recorridos actuales ni
aprobaciones nacidas de Qwen. El preflight no se repitió y la cola permanece
deshabilitada hasta verificar host compatible con identidades API/broker/DB
separadas.
