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

No hace falta provisionar nube. En un host local autorizado que ya tenga soporte
IPv6 del kernel, ejecutar los mismos dos comandos anteriores contra la imagen
local `offline-rebuilt`. Confirmar primero que la creación de un socket IPv6
funciona dentro de ese host; ejecutar los probes siempre dentro del contenedor
`--network=none`, nunca contra endpoints públicos desde el host. Guardar el JSON
de salida y el hash junto con la versión de Docker y el ID de imagen. Si el
worker informa `kernel_protocol_unavailable`, no se puede acreditar IPv6 y no
debe habilitarse el servicio remoto.
