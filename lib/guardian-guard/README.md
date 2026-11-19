# Guardian Guard — demo SMTP local

## Estado

**IMPLEMENTADO:** `index.mjs` verifica recibos individuales v1 sin llamar al
servidor para la firma, compara workspace/aprobación/acción/argumentos, exige
clave pública confiable y vigencia, y reclama el recibo al endpoint de consumo
antes de entregar el mensaje al capturador SMTP local. El capturador requiere
`AUTH PLAIN` con una credencial aleatoria que solo reciben el guard y el
capturador de la prueba; un cliente directo sin esa credencial recibe `530`.
El destino está limitado a loopback y el buzón a dominios de prueba
(`example.test` o `guardian.invalid`). Las pruebas usan claves y credenciales
efímeras, HTTP simulado y un servidor SMTP TCP local.

**PROYECTADO:** despliegue como guard obligatorio delante de una herramienta
empresarial, identidad de workload del agente, aislamiento de red/credenciales,
integración MCP/framework y conector de producción. El módulo de demo no
constituye un límite de seguridad si el agente puede alcanzar otra ruta o usar
las credenciales directamente.

## Base común de conectores

**IMPLEMENTADO en código, sin proveedores reales:** la API puede guardar una
credencial cifrada por workspace, devolver únicamente su estado y los últimos
cuatro caracteres, y desconectarla. La ejecución exige una acción del catálogo,
argumentos válidos, una aprobación y un recibo v1 válido y vigente. El recibo
se consume antes del despacho; una clave idempotente evita repetir la ejecución.
La app no registra adaptadores externos, por lo que no ejecuta acciones reales.
El laboratorio solo inyecta un adaptador falso sin red.

La bóveda usa AES-256-GCM y toma un keyring versionado por `keyId` desde la
configuración del proceso. En laboratorio se genera una clave efímera que se
descarta al cerrar la ejecución. Para una rotación operativa, se conserva
temporalmente la clave anterior para descifrar credenciales existentes y se
vuelven a introducir/reemplazar las credenciales; no se expone el secreto
descifrado mediante una ruta de lectura. Custodia y rotación de claves en
producción, integraciones reales y enforcement que no pueda evitarse siguen
**PROYECTADOS**.

La migración `0005` crea las tablas de credenciales y ejecuciones, con RLS
forzada, policies de workspace y grants por columna. Solo se prueba en
PostgreSQL desechable; no se aplica a desarrollo ni producción en esta etapa.

## Pruebas locales

Desde la raíz del monorepo:

```sh
node --test lib/guardian-guard/index.test.mjs
```

Las pruebas no acceden a una base, no usan Secrets ni se conectan a internet.
El E2E de aprobación del laboratorio también ejecuta este guard frente a una
instancia PostgreSQL desechable, con la clave efímera de ese laboratorio y un
capturador SMTP local.

## Flujo de `executeGuardedSandboxAction`

El llamador entrega el recibo completo, la clave pública de confianza, el
contexto esperado, la acción exacta y el puerto del servidor SMTP de captura.
El guard:

1. valida la firma Ed25519 v1, el hash del payload, dominio, vigencia y
   coincidencia de workspace/aprobación/acción;
2. recalcula el hash de acción y argumentos con la canonicalización v1;
3. llama al endpoint autenticado de consumo de Guardian;
4. si el consumo falla, caduca, ya se usó o el ledger no responde, no envía;
5. solo tras el consumo exitoso abre una conexión TCP a `127.0.0.1` y manda el
   contenido fijo de demostración a un destinatario de prueba.

El índice único parcial del ledger es la autoridad final contra replay.
Verificar una firma offline no impide por sí solo el replay. El guard no acepta
un comando arbitrario ni devuelve credenciales.

## Credencial del capturador local

`sandboxSmtp.credential` es un valor aleatorio del guard, de al menos 32 bytes
en base64url. El capturador compara la autenticación y no revela el valor. No
uses una credencial de prueba en otro entorno ni la entregues al agente. Esta
demostración corre dentro de un entorno de prueba común: no evita que un
proceso comprometido o con acceso al valor se haga pasar por el guard.

## Límites

El consumo y el envío SMTP no comparten una transacción. Si Guardian confirma
el consumo y el capturador no está disponible, el recibo queda consumido y el
mensaje no se entrega; no hay reintento automático. Este flujo prueba
**captura local**, no envío de correo a una persona. La autenticación del
capturador prueba el rechazo de una conexión directa sin credencial, pero no
constituye aislamiento de red/proceso ni enforcement de producción. Véase
`docs/guard-enforcement-threat-model.md` y
`docs/guard-production-isolation-plan.md`.
