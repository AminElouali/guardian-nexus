# SDK Guardian Nexus con los ocho perfiles Qwen

**Fecha:** 3 de noviembre de 2026  
**Base inspeccionada:** `1a9940c2b480abb55494e64b3a77eced73a3f423`  
**Alcance:** desarrollo local, evaluación sintética; no se publicó el SDK ni se desplegó la aplicación.

## Resultado

`@workspace/guardian-agent-sdk` se actualizó a `0.2.0`. El cliente ahora puede
solicitar y consultar una evaluación local Qwen para los ocho `profileId`
fijados, además de usar el flujo de intención/aprobación sintética existente.
No acepta prompts, herramientas, argumentos, decisión de política, identidad,
rol ni destino escogidos por el consumidor. La solicitud contiene únicamente
el perfil permitido y una clave de idempotencia. El host proporciona un
callback de token de sesión; la API valida autorización y pertenencia al
workspace. El SDK no almacena ni registra el token.

El contrato devuelve `not_yet_verified` al encolar. Solo entrega el informe
después de que el job termine correctamente y verifica el perfil, origen de
inferencia, `tool_choice`, límites, procedencia de la propuesta, coherencia de
conteos, dispatch simulado y ausencia de efectos externos. El tipo del perfil
en la respuesta se estrechó a la unión de ocho perfiles solo después de
comprobar la coincidencia con la solicitud.

## Inferencia real local: 8 perfiles, 28 casos

El E2E solicitó cada perfil desde el SDK mediante la cola/API existente y leyó
el resultado persistido por workspace. Todos los casos usaron
`tool_choice=auto`; el runner no forzó una herramienta. Los marcadores Qwen
completos se cuentan como propuestas adaptadas, nunca como `message.tool_calls`
nativas.

| Perfil | Casos | Marcadores adaptados | Llamadas nativas | Sin propuesta | ALLOW | DENY | Requiere aprobación | Simulaciones | SHA-256 evidencia |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| Correo | 3 | 2 | 0 | 1 | 2 | 0 | 0 | 2 | `1bfd996d46499f50bca46f67da4ce1c7d97dbb307507e3bc0b652a05949c8477` |
| Bases de datos | 3 | 2 | 0 | 1 | 2 | 0 | 0 | 2 | `e9aef3d894a28d9b393d7a546a5b901bba997820b2b24e21174380edb2c07a88` |
| Finanzas | 3 | 2 | 0 | 1 | 1 | 0 | 1 | 1 | `27b1f00c4ca9f623f9a08707830d6d1edc1afc28e161b08d94c636285af99cc1` |
| Atención al cliente | 7 | 3 | 0 | 4 | 1 | 1 | 1 | 1 | `945dbde0d0fede8646f4c8c4da68e2e4f473bb25a14f59e0d746f5bcff8d385d` |
| Programación | 3 | 3 | 0 | 0 | 1 | 2 | 0 | 1 | `c3f3518474e42f5b226875cc3acbcf3f7043ccd1b6784a5435cf43d90d92ea15` |
| Navegador | 3 | 2 | 0 | 1 | 1 | 1 | 0 | 1 | `a7c5bd3d55cf97540d506577521b2f143d84eb81cc47eaba863df63662d774df` |
| Infraestructura | 3 | 2 | 0 | 1 | 1 | 1 | 0 | 1 | `b85e7b284d5fd832465dbf267e2d5a738a08aca56cf5e1209c85a198a53d94bb` |
| Multiagente | 3 | 3 | 0 | 0 | 1 | 2 | 0 | 1 | `e22980ff9c739b970c960695b7c44e1adc2f49214891d96e197c451f16aae65a` |
| **Total** | **28** | **19** | **0** | **9** | **10** | **7** | **2** | **10** | — |

No hubo marcadores sin interpretar. Los 9 casos sin propuesta no se cuentan
como denegaciones. La evidencia agregada declara `externalCalls=0`,
`unauthorizedExecutions=0`, `policyOffExecutions=0` y
`rawPromptsResponsesArgumentsPersisted=false`.

Guardian Policy se evaluó antes de cualquier dispatch al simulador. Dos
propuestas Qwen requirieron aprobación: una se aprobó con rol administrador,
vínculo de propuesta y hash de replay, y produjo
`synthetic_action_simulated_once` en un clon ficticio; la otra se expiró, una
aprobación/repetición devolvió conflicto y la persistencia confirmó
`execution=not_performed` y `simulated_at=null`. La salida de esta batería no
es un benchmark comparativo Policy ON/OFF. El contador de ejecución Policy OFF
fue cero.

## SDK empaquetado y compatibilidad

- Build y tests unitarios SDK: **11/11**.
- Ejemplo TypeScript `examples/lab-client.ts`: typecheck correcto. Se estrechó
  el tipo `profileId` del job a la unión allow-listed después de verificarlo
  contra la solicitud.
- Se creó un tarball local v0.2.0, se extrajo en un consumidor temporal bajo
  `node_modules/@workspace/guardian-agent-sdk` y se importaron los exports
  públicos `GuardianNexusClient`, `QWEN_AGENT_PROFILE_IDS` y
  `GUARDIAN_NEXUS_SDK_VERSION`; comprobado que contiene los ocho perfiles.
  SHA-256 del tarball:
  `141dc330830f04d7c4a29d5c55071d0fec26d21e45c5dfc8d1afa7b8b0b02304`.
  No se contactó un registry; el tarball no se publicó.
- El paquete sigue siendo local al workspace; un consumidor externo necesitará
  instalarlo desde un artefacto aprobado o registry futuro antes de usarlo.

## Validación ejecutada

- `pnpm --filter @workspace/api-server run test:ai-assessment-e2e`: API/worker
  **8/8**, exit 0, duración `686466.9 ms`. Incluyó los ocho perfiles Qwen,
  baseline determinista, E2E del SDK y aprobación persistente.
- Integración de componentes del dashboard: **8/8**, exit 0. La UI muestra
  evidencia Qwen diferenciada, aprobaciones y exportación JSON allow-listed.
- `sh workers/guardian-ai-assessment/scripts/run-local.sh --unit-tests`:
  **87/87** en la imagen Garak fijada, con `--network=none` y `--pull=never`.
  Una primera ejecución de `unittest` directamente en el host obtuvo 115
  éxitos y un error de importación porque el host no tiene `garak`; la suite se
  repitió en el perfil de contenedor que sí contiene esa dependencia y pasó.
- `pnpm --filter @workspace/api-server run test`: **60/60**.
- SDK build/tests: **11/11**; API typecheck y build: correctos.
- Web typecheck y build: correctos con `PORT=5000` y
  `BASE_PATH=/eu-security-platform/`. Vite mantiene avisos existentes de
  sourcemap para `tooltip.tsx` y chunk minificado mayor de 500 kB.
- `git diff --check`: correcto.
- El E2E completo precedió al ajuste final de tipo de `profileId`; después de
  ese ajuste se repitieron SDK build/tests, compilación del ejemplo TypeScript,
  typecheck API y la importación del tarball. La API ya comprueba igualdad del
  perfil antes de devolverlo; no se repitieron los 11 minutos del E2E completo
  para ese estrechamiento de tipo.
- La importación del tarball local probó los exports del paquete, no una sesión
  Clerk real ni una integración con una aplicación empresarial conectada.

En el mismo E2E se ejecutaron suites separadas: la suite nativa registró
`QWEN_NATIVE_TOOL_TRACE_COUNT=24/288` y la suite autónoma existente
`QWEN_AUTONOMOUS_TOOL_TRACE_COUNT=39/42`. Esos denominadores pertenecen a
pruebas distintas; no se suman ni sustituyen los 28 casos de esta integración.
La suite nativa incluye controles con herramienta forzada según su manifiesto,
por lo que no demuestra selección autónoma.

## Evidencia y límites

- Resumen redactado por perfil:
  `generated-artifacts/guardian-agent-sdk-qwen-eight-profiles-e2e.json`
- SHA-256 del resumen:
  `ad0f0bdd427a1a37822e385488edf650c5e4bd77318c6f1e438b3aa93a827113`
- SHA-256 interno del resumen:
  `06f729655d43374da089b677224f7be651c4057a1e11333d52552708a9e5401a`
- Tarball local, ignorado por Git:
  `generated-artifacts/guardian-agent-sdk/guardian-agent-sdk-0.2.0.tgz`

El modelo fue `Qwen/Qwen3-0.6B-GGUF`, revisión
`23749fefcc72300e3a2ad315e1317431b06b590a`, Q8_0, archivo SHA-256
`9465e63a22add5354d9bb4b99e90117043c7124007664907259bd16d043bb031`;
runtime `llama-cpp-python` 0.3.36. El perfil Qwen usó la imagen local fijada
`sha256:884d4f7bc6c11e03f6ced5cfcc9e88e7a8043d85923429f1a3a181953f07830f`,
sin pull y con `--network=none`. La prueba autentica con el harness local de
integración, no con una sesión Clerk real en navegador.

Esto acredita un flujo de laboratorio reproducible con propuestas adaptadas,
no ocho conectores empresariales ni protección general de sistemas reales. La
muestra es pequeña y no demuestra tasas generales de detección o eficacia.
Siguen pendientes antes de clientes: resolución de advisories de supply chain,
procedencia/licencias pendientes, verificación IPv6 en dual-stack, separación
real del broker Docker respecto del API y prueba de sesión Clerk real. No se
publicó, desplegó ni conectó ningún servicio externo.
