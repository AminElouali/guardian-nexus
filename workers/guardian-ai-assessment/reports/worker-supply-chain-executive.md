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

## Verificación automatizada de procedencia y runtime Qwen — 2 de noviembre

Se añadió un ejecutor offline que exige explícitamente `XDG_CACHE_HOME`, la
versión del scanner y los SHA-256 de las bases Debian/PyPI. Comprueba también
que OSV informe de las rutas exactas cargadas, recalcula sus hashes y conserva
los comandos, salidas, códigos y un hash lateral del manifiesto. Un test con
hash incorrecto se detuvo antes de escanear como `provenance_error`; un escaneo
con hallazgos conserva el exit code 1 del scanner sin confundirlo con error de
ejecución.

La nueva repetición del worker devolvió 177 coincidencias, 81 IDs únicos,
38 registros de paquete con hallazgos y 0 coincidencias PyPI. Los hashes de
las bases OSV coinciden con el manifiesto y el JSON es byte-idéntico al escaneo
corregido anterior. Los 81 IDs, incluido 1 crítico y 25 altos, siguen presentes:
esto no es una remediación.

El runtime Qwen montado tiene ahora un inventario CycloneDX separado con 13
componentes, pesos y wheels hash-verificados, seis ELF de llama.cpp/ggml y la
extensión nativa de MarkupSafe. El inventario confirma hashes y metadatos
disponibles; no acredita firma, build bit-a-bit, revisión legal completa ni
escaneo de vulnerabilidades. `numpy` y `typing-extensions` siguen sin wheels
separados en este inventario; `langdetect` continúa con licencia ambigua.

El escaneo completo más reciente de OSV Scanner registró **177 coincidencias
paquete/advisory**, **81 IDs únicos** (1 crítico, 25 altos, 43 moderados, 9 bajos
y 3 sin puntuación) y **cero coincidencias PyPI** en esta imagen. El escaneo
completo previo, con otra base Debian local, encontró 186 coincidencias/84 IDs.
Solo dejaron de aparecer tres IDs moderados y no cambió ningún paquete; esto no
es una remediación. Son coincidencias de inventario, no prueba de explotación ni
de que cada ruta sea alcanzable. No se aplicaron actualizaciones. La simulación
local de paquetes no encontró candidatos Trixie para los paquetes afectados.

## Comparación de base Trixie slim — 2 de noviembre de 2026

Se comprobó una imagen temporal basada en Debian 13 Trixie slim, copiando el
runtime CPython 3.13.18 desde la imagen Python oficial ya almacenada localmente.
El build no usó red, no instaló paquetes y no sustituyó la imagen existente.
La comparación corregida, con las mismas bases OSV locales y opciones completas,
encontró 177 coincidencias/81 IDs en la imagen worker actual y 175/81 en la
temporal. Los 81 IDs son iguales, incluidos los 1 críticos y 25 altos: la
diferencia de dos registros no elimina avisos ni es una remediación. La temporal
quita nueve componentes Debian del SBOM y reduce el tamaño de imagen en unos
7,1 MB, pero no ofrece una reducción material de riesgo.

La prueba de 64/64 tests del worker y el self-test aislado pasaron. Sin embargo,
la imagen temporal no conserva toda la funcionalidad estándar de Python:
`ctypes` falla por ausencia de `libffi.so.8` y `readline` por ausencia de
`libreadline.so.8`. No se copiaron bibliotecas ni se instalaron paquetes para
sortearlo. La imagen no está promovida y no debe sustituir al worker actual.

Corrección de procedencia de escaneo: dos resultados preliminares 186/84 y
184/84 se habían etiquetado como si usaran la base Debian OSV más reciente
(`481619…`). Los stderr muestran que heredaron `XDG_CACHE_HOME` y cargaron la
base anterior `95c71e…`. Los recuentos son válidos para esa base antigua; sus
contextos estaban mal etiquetados. Con `XDG_CACHE_HOME` fijado explícitamente,
la imagen Python/Trixie base devuelve 177/81 y Debian Trixie slim 175/81. La
corrección completa, comandos y hashes están en `DEPENDENCY_AUDIT.md` y en el
artefacto local de corrección; no se presentan los 186/84 como una nueva
medición de la imagen candidata.

Una segunda reconstrucción local generó las mismas cinco capas del sistema de
archivos, pero otro ID de imagen porque cambió la metadata de creación. Esto
apoya la repetibilidad local de esas capas, no una reproducibilidad completa
entre equipos. El intento de fijar la imagen de entrada por su ID falló en la
resolución de origen de BuildKit; no se hizo una alternativa con red.

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

## Revisión oficial de Debian y procedencia — 2 de noviembre de 2026

- Consultamos las páginas oficiales del Debian Security Tracker para los 26
  avisos críticos/altos y sus paquetes fuente. En Debian 13/Trixie, 25 aparecen
  como `vulnerable` y PAM como `undetermined`; no hay una versión corregida de
  Trixie listada para ninguno. Varias correcciones existen en unstable/forky/sid,
  pero no se incorporaron: mezclar paquetes de esas suites no es una
  actualización segura de esta imagen Trixie. Las etiquetas Debian (`unimportant`,
  `no-DSA`) son priorización de Debian y no sustituyen los CVSS ni eliminan los
  resultados OSV.
- Excepción de alcance documentada, no de escaneo: Debian indica que la extensión
  SQLite `zipfile` no se construye en sus binarios. En una ejecución efímera,
  aislada y de solo lectura de la imagen candidata, SQLite 3.46.1 informó
  `ENABLE_ZIPFILE=False` y no había ejecutable `sqlite3`. La coincidencia OSV se
  mantiene visible; esta evidencia solo descarta esa ruta concreta en el binario
  probado.
- Los 38 artefactos locales bloqueados coinciden en SHA-256 con los digest
  publicados en la API oficial de PyPI. La respuesta capturada no incluye
  attestations para esos archivos. Esto verifica igualdad de archivos con los
  metadatos de PyPI, no una firma independiente del publicador ni una build
  reproducible.
- `langdetect 1.0.9` sigue sin resolución legal: sus metadatos dicen MIT, pero
  su clasificador y archivo `LICENSE` dicen Apache-2.0. `llama-cpp-python`
  declara MIT; la sdist coincide con el digest de PyPI, y los archivos MIT de
  su release y del commit vendorizado de llama.cpp coinciden con los hashes
  locales. La rueda nativa activa se construyó localmente y no es un artefacto
  de PyPI; su procedencia de build y la revisión jurídica completa siguen
  pendientes.
- No se cambió paquete ni imagen: por ello no hay rebuild, nuevo SBOM ni rescan
  que puedan presentarse como remediación. Los avisos continúan abiertos salvo
  la ruta `zipfile` concreta no incluida en el binario.

## Evidencia trazable

- Imagen candidata: `sha256:e2d13fb48471dbcdc169e421598d5830303717266baf9892a3f11e86eb48e476`.
- SBOM CycloneDX 1.6: 124 componentes,
  `8eb49149a21afac04818f94ac0183eb799ed740b8f2254a9f63c453c279c5d97`.
- Wheelhouse: 38/38 archivos coinciden con los locks locales; inventario de
  licencias y archivos de licencia:
  `168e1534da55376e403b5587c6d702810f356c0517c6d8a3d64aa5aca4b36ff0`.
- Comparación con digests de la API oficial de PyPI (38/38 iguales; cero
  attestations declaradas en la captura): JSON SHA-256
  `0765397da2d2c663d16fa69f6cf8798fec5f364bc17c9f8a58301d157ddf665f`.
- Captura de páginas oficiales de Debian, 26 CVE:
  `b7ec922e37a5951387f2986cfbf3632f09727f2b5db92f98e6a53f8e4696f7ec`;
  páginas de paquetes fuente:
  `10d28ad109a83f9d7022a8491e2da875a754f3f40a59b144039fb1e3d176609f`.
  Evidencia de la prueba efímera `ENABLE_ZIPFILE=False` y su comando:
  `debian-official-review-20261102/SHA256SUMS.txt`, SHA-256
  `24a258a49d2bd21e1756ceef796a3f9d3203ae7ab4eb1d704782fc7762410a8c`.
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

## Qué contiene realmente el runtime local de Qwen

El runner de laboratorio valida antes de cargar el wheel local de
`llama-cpp-python 0.3.36` por SHA-256
`5e50c8f09c0ed78512bfb16adb32be9e0c65b8ced7c1efcfc200c38782141e96`.
Se construyó desde la sdist de PyPI con hash fijado, un parche local para retirar
`diskcache` y un constructor sin red. La rueda requiere Jinja2, NumPy y
typing-extensions; los binarios ELF incluidos enlazan con bibliotecas del propio
`llama.cpp` y con componentes del sistema Debian. El inventario estático de
binarios y sus hashes está en
`../local-llm-build/native-runtime-inspection.json`.

Esto aporta trazabilidad, pero no convierte la rueda en una build firmada o
bit-a-bit reproducible. Tampoco es una SBOM completa de todas las dependencias
nativas del runtime montado. Las licencias observadas y los textos disponibles
están documentados para revisión; no hay aprobación legal. La auditoría de
`langdetect` sigue sin resolverse y el resultado de IPv6 sigue **NO VERIFICADO**
hasta que se ejecute el procedimiento en un host compatible, dentro de un
contenedor sin red. Los findings globales del worker permanecen en este informe
interno, separados del informe de evaluación por tenant.
