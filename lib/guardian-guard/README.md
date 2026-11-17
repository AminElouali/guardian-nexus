# Guardian Guard — demo SMTP local

## Estado

**IMPLEMENTADO:** `index.mjs` verifica recibos individuales v1 sin llamar al
servidor para la firma, compara workspace/aprobación/acción/argumentos, exige
clave pública confiable y vigencia, y reclama el recibo al endpoint de consumo
antes de entregar el mensaje al capturador SMTP local. El destino está limitado
a loopback y el buzón a dominios de prueba (`example.test` o
`guardian.invalid`). Las pruebas usan claves efímeras, HTTP simulado y un
servidor SMTP TCP local.

**PROYECTADO:** despliegue como guard obligatorio delante de una herramienta
empresarial, identidad de workload del agente, aislamiento de red/credenciales,
integración MCP/framework y conector de producción. El módulo de demo no
constituye un límite de seguridad si el agente puede alcanzar otra ruta o usar
las credenciales directamente.

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

## Límites

El consumo y el envío SMTP no comparten una transacción. Si Guardian confirma
el consumo y el capturador no está disponible, el recibo queda consumido y el
mensaje no se entrega; no hay reintento automático. Este flujo prueba
**captura local**, no envío de correo a una persona. Un proceso comprometido
con acceso alternativo a una herramienta puede saltarse el módulo.
