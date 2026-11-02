# Verificación de aislamiento de red del worker

Esta verificación se ejecuta únicamente dentro del worker Docker con
`--network=none`. No se ejecuta desde el host con conectividad pública y no
habilita egress para el evaluador.

## Ejecución local reproducible

1. Construir la imagen desde el wheelhouse verificado:

   ```sh
   bash workers/guardian-ai-assessment/scripts/build-offline-image.sh
   ```

   El script exige que el digest base ya exista localmente, comprueba los hashes
   de los locks y construye con `--no-cache --pull=false --network=none`.
   No descarga paquetes. La imagen candidata no reemplaza automáticamente la
   imagen `guardian-ai-assessment:local` usada por la API.

2. Ejecutar el test unitario y la comprobación real del contenedor:

   ```sh
   docker run --rm --pull=never --network=none --read-only \
     --cpus=0.5 --memory=256m --memory-swap=256m --pids-limit=32 \
     --cap-drop=ALL --security-opt=no-new-privileges --user=65532:65532 \
     --entrypoint=python guardian-ai-assessment:offline-rebuilt \
     -m unittest discover -s tests -p 'test_network_audit.py' -v

   sh workers/guardian-ai-assessment/scripts/verify-egress-isolation.sh \
     guardian-ai-assessment:offline-rebuilt
   ```

Los probes UDP directos apuntan solo a direcciones reservadas para
documentación: `192.0.2.53` (IPv4 TEST-NET-1) y `2001:db8::53`
(`2001:db8::/32`). El test DNS IPv6 usa el segundo destino con un nombre
`.invalid`. El preflight exige `network=none`, ausencia de interfaces no-loopback
activas y ausencia de rutas por defecto antes de los probes.

## Interpretación fail-closed

- `blocked`: `sendto` falló con una condición de ruta/interfaz no disponible.
- `reachable`: se recibió una respuesta; la comprobación falla.
- `timeout_no_response`: el datagrama pudo enviarse pero no llegó respuesta;
  **no** demuestra bloqueo y la comprobación falla.
- `timeout_on_send` o `error:<errno>`: resultado inconcluso/fallido, nunca se
  convierte en “blocked”.
- `unavailable`: el kernel no ofrece el protocolo. Para IPv6, conservar
  literalmente `kernel_protocol_unavailable`; IPv6 queda **NO VERIFICADO**.

El resultado general solo puede ser `verified` cuando IPv4 TCP, IPv4 UDP, DNS
IPv4/UDP, IPv6 TCP, IPv6 UDP, DNS IPv6/UDP están bloqueados, y IPv4 e IPv6
loopback funcionan. Un resultado de IPv6 no disponible es incompleto.

## Repetición en un host de desarrollo dual-stack autorizado

No hace falta provisionar nube. Utilizar solo un host de desarrollo autorizado
que ya tenga habilitado IPv6 en el kernel; no habilitar egress, cambiar reglas de
red ni probar destinos desde el host. Los probes se ejecutan dentro del mismo
contenedor `--network=none` y usan únicamente las direcciones reservadas y el
dominio `.invalid` descritos arriba.

1. Registrar `date -u`, `uname -a`, `docker version` y el ID de imagen local:

   ```sh
   date -u
   uname -a
   docker version
   docker image inspect guardian-ai-assessment:offline-rebuilt \
     --format '{{.Id}}'
   ```

2. Comprobar que IPv6 está disponible dentro del contenedor, sin enviar tráfico
   de salida. Si la creación/enlace del socket falla, registrar el error y
   detener la evaluación IPv6:

   ```sh
   docker run --rm --pull=never --network=none --read-only \
     --cpus=0.5 --memory=256m --memory-swap=256m --pids-limit=32 \
     --cap-drop=ALL --security-opt=no-new-privileges --user=65532:65532 \
     --entrypoint=python guardian-ai-assessment:offline-rebuilt \
     -c 'import socket; s=socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); s.bind(("::1", 0)); print("ipv6_loopback_available"); s.close()'
   ```

3. Ejecutar el test unitario y el auditor ya descritos. Guardar el stdout,
   stderr, exit code, JSON, hora UTC y SHA-256 de cada artefacto. No ejecutar los
   probes fuera del contenedor ni sustituir `--network=none` por una red
   conectada.

La aceptación requiere, en una misma ejecución: preflight correcto; `network=none`;
solo loopback activo y sin ruta por defecto; loopback IPv4 e IPv6 alcanzables;
IPv4 TCP, IPv4 UDP, DNS IPv4/UDP, IPv6 TCP, IPv6 UDP y DNS IPv6/UDP clasificados
`blocked` por los criterios estrictos del script; cero respuestas y cero
timeouts clasificados como bloqueo; y un JSON cuya suma de verificación pueda
recalcularse. Un timeout, error de envío, ruta ausente no atribuible al modo
aislado o cualquier inconsistencia deja el resultado **INCONCLUSO**, nunca
`verified`.

Registrar el ID de imagen, versión de Docker, kernel, comandos, fechas, códigos
de salida, JSON de evidencia y sus hashes. Si el worker informa literalmente
`kernel_protocol_unavailable`, IPv6 permanece **NO VERIFICADO**; no se debe
presentar como egress bloqueado ni habilitar un servicio remoto.
