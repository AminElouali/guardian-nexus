# Threat model: enforcement obligatorio del guard

## Alcance y activos

Este modelo cubre el flujo sintético de `guardian.email.send.external.v1`, el
recibo Ed25519 v1, el consumo de un solo uso en el ledger y el capturador SMTP
de loopback del laboratorio. El receptor de correo de prueba no es un proveedor
externo. Ningún resultado de este documento demuestra aislamiento de procesos
ni protección de una herramienta de producción.

Activos: la autorización firmada, la integridad de los argumentos aprobados, la
pertenencia al workspace, el estado de consumo del recibo y la credencial local
que permite al guard hablar con el capturador. La clave privada de firma no se
usa ni se carga en estas pruebas; el guard solo recibe una clave pública de
confianza.

## Límites de confianza

- **Agente → API:** la propuesta es entrada no confiable; el servidor valida el
  catálogo, los argumentos, el workspace y el rol.
- **Aprobador → API/ledger:** solo otra persona autorizada decide; la firma
  v1 queda ligada a workspace, aprobación, binding y hash de acción.
- **Agente/proceso directo → capturador:** el servidor SMTP de laboratorio
  requiere autenticación propia del guard y rechaza comandos de envío sin ella.
- **Guard → ledger y capturador:** el guard verifica localmente el recibo,
  consume en Guardian y solo entonces conecta a `127.0.0.1`.
- **Laboratorio → herramienta real:** no existe una frontera de aislamiento
  entre procesos que impida al agente alcanzar otra herramienta. Esa garantía
  sigue proyectada.

## Amenazas

| Amenaza | Qué la detiene hoy — IMPLEMENTADO | Qué falta — PROYECTADO |
|---|---|---|
| El agente llama directamente a la herramienta | El capturador SMTP del laboratorio responde `530` a `MAIL FROM` sin `AUTH PLAIN`. El E2E intenta esa ruta directa y comprueba que no se captura ningún mensaje. | Firewall/namespace que haga inaccesible la herramienta al agente y permita acceso solo desde el guard. La credencial de laboratorio no es una frontera entre procesos. |
| Recibo reutilizado o dos consumos simultáneos | Guardian consume el recibo en una transacción; el índice único parcial y el tratamiento de conflictos dejan un ganador. Hay pruebas secuenciales y una carrera contra PostgreSQL desechable. | Pruebas de carga y recuperación ante fallos en la infraestructura aislada de producción. |
| Recibo falso, firma alterada o clave no confiable | El guard valida Ed25519, separación de dominio, digest, caducidad y key id contra claves públicas de confianza. Las pruebas generan claves efímeras. | Custodia y rotación operativa de claves; separar al firmante del servidor de la aplicación. |
| Argumentos cambiados después de aprobar | El guard recalcula el hash canónico de tipo y argumentos y lo compara con el recibo antes de consumirlo. El E2E cambia el destinatario y exige rechazo. | Una API de herramientas que acepte únicamente la acción ya validada y no permita mutaciones posteriores. |
| Recibo de otro workspace o aprobación | La verificación del guard exige workspace, aprobación, binding, actor y acción esperados; la API valida membership y RLS. Hay prueba negativa de workspace distinto. | Identidad de workload autenticada y vinculada a un agente concreto, además de la identidad de usuario actual. |
| Reloj local manipulado | El guard rechaza recibos fuera de su ventana usando el reloj del proceso; la verificación criptográfica no altera el timestamp. | Tiempo confiable, alertas de desviación y política operativa para hosts con reloj incorrecto. Un host comprometido puede mentir sobre su hora. |
| Guard apagado o bypass por configuración | El guard exige recibo válido, configuración SMTP válida y credencial; el capturador no acepta envíos sin autenticación. | Política de arranque que impida habilitar herramientas protegidas sin guard, y control de configuración firmado/auditado. No hay un supervisor de producción implementado. |
| La herramienta tiene otra ruta alcanzable | En el laboratorio el listener se enlaza a loopback y exige credencial. | Aislamiento de red y credenciales; no hay prueba de que una herramienta real carezca de rutas alternativas. |
| Ledger inaccesible después de verificar firma | El guard falla cerrado: si el endpoint de consumo no responde o rechaza, no conecta al capturador. Hay prueba de indisponibilidad. | Alta disponibilidad y reconciliación operativa sin permitir bypass. |
| Roban la credencial del guard | El capturador valida el token en el ensayo; el E2E no lo imprime y usa un valor efímero. | Credencial de corta duración en un almacén no accesible al agente, rotación y revocación. La implementación local no protege memoria compartida ni un host comprometido. |

## Garantías requeridas antes de una herramienta real

1. El agente no debe tener ruta de red ni credenciales para llamar a la
   herramienta protegida directamente.
2. El guard debe autenticar una identidad de agente y verificar el recibo y el
   hash exacto de la acción antes de pedir el consumo.
3. El consumo debe fallar cerrado y ser atómico frente a replay. Una caída del
   ledger nunca debe permitir la operación.
4. La herramienta debe autenticar al guard, no al agente, y rechazar cualquier
   otra identidad.
5. Las claves públicas confiables y el punto de control deben distribuirse por
   canales separados del bundle. La firma v1 no prueba por sí sola que el
   historial exportado sea el más reciente.
6. Debe declararse la ventana entre consumir el recibo y completar la
   operación: hoy el consumo y el envío no comparten una transacción. Si el
   capturador cae después del consumo, el recibo queda gastado y no se reintenta.

## Estado

**IMPLEMENTADO:** enforcement de credencial en el capturador SMTP desechable,
guard local con verificación v1 y consumo previo, rechazo de acceso directo y
pruebas de replay, cambios de argumentos, caducidad, workspace, firma y carrera
de doble uso.

**PROYECTADO:** aislamiento de procesos/red, identidad de agentes, credenciales
de herramienta protegidas del agente, bloqueo global de bypass, conectores
productivos y operación atómica/reconciliable. La prueba SMTP local no equivale
a seguridad de producción.
