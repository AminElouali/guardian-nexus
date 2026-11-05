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
  SHA-256 `6986071bdc922c829bcb9c51fd40f48287b80482ac0c51b6bb646a00bf8f42d3`.
- Ruta API:
  `artifacts/api-server/src/routes/ai-assessment-lab.ts`,
  SHA-256 `b0ae9ca290d5e6cf3d00f33b026d0d37f1578da48b55dc7e32dc25780e7bdd94`.
- Artefacto sintético:
  `generated-artifacts/guardian-synthetic-approval-e2e.json`,
  SHA-256 `d722501129e9c74f3b9c1f1101f9d8914f2f2116db2c6a91bbec1cdd2b07421c`;
  hash de evidencia incluido
  `f9facb43cdcc72d7e3f5050b33e75f44874818ac05df01ddcc20b19d39069f34`.
- Qwen histórico (no nuevo):
  `generated-artifacts/guardian-qwen-offline/qwen-policy-lab-eight-profiles.json`,
  SHA-256 `6a1e54658f745074a7a5a937204181c219ec28d184a866845dd09513497ee1d9`.
- Último preflight persistido (no repetido):
  `generated-artifacts/guardian-qwen-offline/preflight-status-2026-11-04.json`,
  SHA-256 `0b6246f76877a2874dc7834cacba1c76979a61e7871b1371515268dee8e85f52`.

El manifiesto `.sha256` de este informe fija hashes del informe, fuentes y
artefactos; verificar con `sha256sum -c`.

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

## Addendum — autorización antes de reportar disponibilidad de cola

En la revisión posterior se encontró que la ruta POST de cola contestaba
`503` por el gate del worker antes de comprobar membresía y rol. No insertaba
jobs, pero revelaba disponibilidad del worker a solicitudes no autorizadas.
La comprobación del gate ahora ocurre dentro de la transacción tenant-scoped,
después de validar membresía y rol, y antes de consultar idempotencia o tocar
la cola. No cambió el gate: owners/admins siguen recibiendo 503 cuando el
broker no está verificado.

El E2E comprueba el comportamiento para un perfil fixture y uno Qwen:
solicitud anónima → 401, tenant ajeno → 403 y viewer → 403. Owners reciben 503
para los 16 perfiles; el conteo de jobs no cambia. El artefacto actualizado
registra dos rechazos en cada categoría de autorización y 16 rechazos previos
a inserción.

Validación del cambio: E2E 1/1, API 79/79, worker 35/35 + 5/5 + 2/2, UI
integration 12/12, typecheck monorepo correcto y build API correcto. La UI se
verificó con pruebas de integración, no mediante una sesión Clerk real en
navegador. El workflow local de API se reinició y sus logs muestran el servidor
escuchando en el puerto 8080; no se inició el worker. No hubo inferencia Qwen
ni ejecución Docker.
