# Resumen ejecutivo — cadena de suministro del evaluador

**Fecha de evidencia:** 2 de noviembre de 2026  
**Alcance:** imagen local `guardian-ai-assessment:offline-rebuilt`, no servicio
remoto ni evaluación de clientes. Este documento es independiente del informe
de evaluación de agentes IA.

## Conclusión

La imagen candidata se reconstruyó en este workspace usando una imagen base
fijada ya presente y artefactos locales con hashes verificados. La ejecución del
worker continúa sin red (`network=none`), con usuario no privilegiado y límites
de recursos. La auditoría **no acredita que la imagen esté libre de
vulnerabilidades ni lista para clientes**.

El escaneo completo más reciente de OSV Scanner registró **177 coincidencias
paquete/advisory**, **81 IDs únicos** (1 crítico, 25 altos, 43 moderados, 9 bajos
y 3 sin puntuación) y **cero coincidencias PyPI** en esta imagen. El escaneo
completo previo, con otra base Debian local, encontró 186 coincidencias/84 IDs.
Solo dejaron de aparecer tres IDs moderados y no cambió ningún paquete; esto no
es una remediación. Son coincidencias de inventario, no prueba de explotación ni
de que cada ruta sea alcanzable. No se aplicaron actualizaciones. La simulación
local de paquetes no encontró candidatos Trixie para los paquetes afectados.

## Riesgos principales y controles actuales

- Las coincidencias incluyen `glibc`, SQLite, `util-linux`, ACL/attr, zlib,
  ncurses, PAM, Perl y `libstdc++`. La revisión estática no encontró llamadas
  del worker a varias operaciones de línea de comandos afectadas. Algunas
  bibliotecas sí están presentes y pueden formar parte del runtime; sus rutas
  exactas permanecen parcialmente desconocidas.
- Los controles actuales son usuario UID 65532, filesystem raíz de solo
  lectura, capabilities descartadas, `no-new-privileges`, red deshabilitada y
  límites de CPU, memoria y procesos. Reducen ciertas precondiciones, pero no
  parchean los paquetes.
- La evidencia de egress demuestra bloqueo de IPv4 TCP/UDP y DNS/UDP dentro de
  `network=none`. IPv6 no se pudo probar porque el kernel devuelve
  `kernel_protocol_unavailable`; por tanto, **IPv6 no está verificado**.
- `langdetect 1.0.9` tiene metadatos contradictorios (MIT frente a Apache-2.0).
  La licencia y las obligaciones de los componentes nativos necesitan revisión
  legal; este informe no concede aprobación legal.

## Evidencia trazable

- Imagen candidata: `sha256:e2d13fb48471dbcdc169e421598d5830303717266baf9892a3f11e86eb48e476`.
- SBOM CycloneDX 1.6: 124 componentes,
  `8eb49149a21afac04818f94ac0183eb799ed740b8f2254a9f63c453c279c5d97`.
- Wheelhouse: 38/38 archivos coinciden con los locks locales; inventario de
  licencias y archivos de licencia:
  `168e1534da55376e403b5587c6d702810f356c0517c6d8a3d64aa5aca4b36ff0`.
- Runtime local montado: inventario de hashes de los binarios `.so` y de
  licencias disponibles de MarkupSafe y llama-cpp-python:
  `2fafa80a397f89ccae66fcab113b94cd6475db627e4dc3f6f58f5ca528197873`.
  No demuestra cobertura transitiva completa ni aprobación legal.
- Escaneo OSV offline completo más reciente con OSV Scanner 2.7.0 / SCALIBR 0.5.3:
  Debian DB `4816191fe3b9edc162646d56b0f26ee417c26bacdd02d1c39a5bcfa957c53582`,
  PyPI DB `8fd7138ad08c733316d229a05ac5a8a9fdcba4f6439d80cdab97fe4e18445dde`,
  JSON `292c48b7a65092730f080cb737e72e8e29a1610cbd3e304e1d9b6a87d18c59ca`.
  El ejecutable local tiene SHA-256
  `73cc8c323f04d4dbc39a861033819624524f3a7908be730f92d3f076fda0f087`;
  en esta ejecución no se comprobó su firma upstream. El escaneo devolvió
  código 1 por hallazgos. El resultado anterior contra la base
  `95c71e88…` es idéntico byte a byte a su JSON previo, también con código 1;
  el checkpoint que decía 2 era incorrecto. Un intento separado con
  `XDG_CACHE_HOME` mal dispuesto dio 127 y no cuenta como escaneo válido.
- Suite worker en la imagen candidata, con red deshabilitada y `/tmp` efímero:
  64/64 pruebas pasaron. Esto no sustituye un rescan posterior a cualquier
  actualización de paquetes.

## Recomendaciones y límites

1. Mantener la imagen sin promocionar hasta que se revise cada advisory crítico
   y alto frente a una base Debian autorizada más reciente, se identifique una
   corrección disponible y se reconstruya y vuelva a escanear la imagen.
2. Mantener fuera del runtime las dependencias opcionales no necesarias y
   conservar las restricciones de contenedor; no tratar mitigaciones como
   correcciones.
3. Resolver `langdetect` y el inventario legal nativo con revisión jurídica.
4. No habilitar worker remoto hasta verificar egress IPv6 en un host dual-stack
   autorizado.

El detalle por advisory, comandos, hashes y límites de alcance está en
`../DEPENDENCY_AUDIT.md`. El dashboard de evaluaciones continúa mostrando
evidencia de agentes IA por tenant; este resumen global de la imagen worker no
se mezcla con esos informes.
