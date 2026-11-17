# Plan de aislamiento del guard para producción

**Estado: PROYECTADO.** Este documento no cambia configuración, red, base de
datos ni credenciales y no demuestra que un despliegue real esté aislado. El
único envío probado actualmente es a un capturador SMTP autenticado en
`127.0.0.1` dentro del laboratorio desechable.

## Objetivo

Un agente no debe poder ejecutar una herramienta protegida por una ruta
alternativa. La herramienta debe aceptar únicamente una identidad de guard
autorizada. La validación de firma offline es necesaria, pero no crea por sí
sola esa frontera: un agente que alcanza directamente las credenciales o la
herramienta puede evitar el guard.

## Diseño y orden de trabajo

1. **Separar identidades y procesos.** Ejecutar agente, guard y herramienta en
   identidades de sistema distintas. El agente no debe poder leer el entorno,
   archivos, memoria, socket ni credenciales del guard. Cada agente obtiene una
   identidad autenticada de workload, no una identidad declarada en su propio
   JSON.
2. **Cerrar rutas de red directas.** Aplicar namespaces/firewall y política de
   salida: el agente solo llega al guard y a destinos expresamente permitidos;
   la herramienta solo acepta conexiones del guard; el guard llega al ledger y
   a la herramienta autorizada. Denegar por defecto y probar desde el espacio
   de red del agente que la conexión directa falla.
3. **Autenticar al guard ante la herramienta.** Usar mTLS o una credencial
   corta y rotatoria suministrada solo al guard. No ponerla en configuración,
   SDK, prompt ni proceso del agente. La herramienta debe validar la identidad,
   no solo una cabecera enviada por el cliente.
4. **Validar una acción exacta.** El guard valida el recibo v1 con una clave
   pública fuera del bundle, comprueba workspace, aprobación, caducidad y hash
   canónico de acción/argumentos. Toda modificación exige otro recibo. Claves
   desconocidas, revocadas o fuera de vigencia se rechazan.
5. **Consumir antes de ejecutar.** Reclamar el recibo al endpoint autenticado
   de Guardian; solo el ganador del índice único parcial puede continuar.
   Ledger no disponible, conflicto o respuesta incompleta significa no
   ejecutar. El guard conserva una clave de idempotencia para poder reconciliar
   intentos, sin reutilizar el recibo para otra acción.
6. **Resolver la ventana consumo/efecto.** El consumo y la llamada a una
   herramienta externa no son atómicos. Antes de producción se requiere una
   decisión de producto y pruebas de recuperación: herramienta idempotente,
   operación con clave de idempotencia, o un protocolo de intención y
   reconciliación. No se debe reintentar automáticamente una operación cuyo
   resultado sea incierto.
7. **Desplegar gradualmente.** Primero modo de observación que no afirma
   enforcement; luego un entorno de prueba con credenciales no productivas;
   después un piloto de una sola acción con canary, alertas y procedimiento de
   desactivación. El modo de observación no debe llamar a la herramienta.
8. **Validar bypasses.** Desde el agente, probar conexión directa, acceso a
   credenciales, API alternativa, reuso, carreras, workspace distinto,
   argumentos modificados, reloj desviado, guard detenido y fallo del ledger.
   Exigir evidencia de red y de la herramienta además de respuestas del API.

## agentgateway y conectores

**PROYECTADO / no probado:** agentgateway podría servir como proxy si la versión
concreta ofrece external authorization y puede pasar al autorizador la
identidad autenticada, operación y cuerpo exactos. Antes de adoptarlo habría
que probar que un fallo del autorizador siempre deniega, que no existe ruta
directa hacia la herramienta y que el valor validado es exactamente el que se
ejecuta. No se añade ni configura agentgateway en este proyecto.

Los adaptadores de MCP o frameworks deben llamar al mismo guard; no son un
límite de seguridad si el agente conserva una ruta directa. Cada conector
necesita una identidad de herramienta propia, allow-list de destinos y
pruebas negativas de bypass. No se ha verificado un conector de producción.

## Decisiones y prerrequisitos

- Elegir el modelo de identidad de agente, autenticación y revocación.
- Elegir custodia y rotación de credenciales de herramienta y del firmante.
- Definir cómo se distribuye el checkpoint más reciente por un canal confiable
  independiente del bundle.
- Definir límites de tiempo, reintento e idempotencia de cada herramienta.
- Aprobar una revisión de seguridad y una prueba de penetración del entorno
  aislado antes de conectar datos o efectos reales.

## Implementado frente a proyectado

**IMPLEMENTADO:** guard de demostración que verifica recibos v1, consume el
recibo antes de actuar y conecta únicamente a un capturador SMTP loopback. El
capturador exige `AUTH PLAIN` con una credencial efímera del guard; conexiones
directas sin ella se rechazan. El E2E comprueba esa denegación, replay,
argumentos alterados y consumo concurrente contra PostgreSQL desechable.

**PROYECTADO:** aislamiento de procesos, red de salida restringida, identidad
de workload, credenciales inaccesibles al agente, enforcement global y
conectores reales. El token efímero del laboratorio no ofrece aislamiento
contra un proceso comprometido ni acredita la seguridad de una herramienta en
producción.
