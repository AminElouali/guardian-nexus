# Separación local de perfiles Garak/GVE y Qwen

**Fecha:** 2 de noviembre de 2026
**Base inspeccionada:** HEAD `691b7134`; cambios posteriores probados en desarrollo.
**Alcance:** imágenes candidatas locales y evaluaciones sintéticas/autorizadas. No producción, clientes, servicios externos ni publicación.

## Resultado

Se añadieron dos perfiles de imagen para que la API seleccione el worker por `profileId` y compruebe su etiqueta OCI antes de ejecutar el trabajo. El contrato de jobs, los IDs de perfil, el esquema PostgreSQL, la política de autorización y la identidad de la evidencia se conservaron. La comprobación de etiqueta falla cerrada si un perfil apunta a una imagen equivocada.

- **Garak/GVE:** `guardian-ai-assessment:garak-gve-profile-candidate`, 124 componentes CycloneDX, 247.598.881 bytes, imagen `sha256:88df6b6808fd6169ece85d229cfffeb366c0f4356bad4d5c626efa3b8885511d`. Contiene Garak 0.17.1 y `langdetect` 1.0.9; no incluye `llama_cpp`.
- **Qwen/GVE:** `guardian-ai-assessment:qwen-gve-profile-candidate`, 90 componentes CycloneDX, 204.914.829 bytes, imagen `sha256:884d4f7bc6c11e03f6ced5cfcc9e88e7a8043d85923429f1a3a181953f07830f`. Excluye Garak, `langdetect`, NLTK y `llama_cpp`; la rueda nativa, el runtime y los pesos Qwen se siguen montando desde el inventario local verificado, no se copiaron a esta imagen.
- Diferencia de imagen: 42.684.052 bytes menos y 34 componentes menos en la candidata Qwen. Esto mide inventario/tamaño, **no demuestra por sí solo una reducción de vulnerabilidades ni que la imagen sea segura**.

Los builds usaron la imagen base ya presente y fijada por digest, wheelhouse local con hashes y `--no-cache --pull=false --network=none`. No hubo descarga ni acceso de red del evaluador. Son builds funcionales locales; no se afirma reproducibilidad bit a bit. Ambos smoke tests confirmaron el perfil y las dependencias previstas bajo `--network=none`, usuario no privilegiado, filesystem de solo lectura, capacidades eliminadas y límites de recursos.

## SBOM y escaneos

- SBOM de imagen Garak: 124 componentes, SHA-256 `f054af90c7a2f5440f84ba1e820d377655a8a0d6125f230cb1b4f2e2d062c264`.
- SBOM de imagen Qwen: 90 componentes, SHA-256 `cf1c566ceb3421b0064587de7324bb5290aa791fd97a875a596775a178c81a47`.
- Inventario Qwen montado: 13 componentes, incluidos seis objetos nativos; SHA-256 `5774499f6175824a7d0d9e970f962e28112c744775742a37c0e7e4c3ded84f48`. La verificación conserva brechas de procedencia/licencia para objetos nativos y no acredita attestation o revisión jurídica.
- SBOM compuesto Qwen (90 componentes de imagen + 13 del runtime, con raíces de inventario): 105 registros, SHA-256 `277e9b0cfb57e39e523b7dcfa68302bffeada04d0599ba6b970294b8d5bf16ce`.
- OSV Scanner 2.7.0, modo offline, `--all-packages --all-vulns`, con el mismo `XDG_CACHE_HOME` y las mismas bases locales en ambos escaneos de archivo de imagen. Base Debian SHA-256 `4816191fe3b9edc162646d56b0f26ee417c26bacdd02d1c39a5bcfa957c53582`; base PyPI SHA-256 `8fd7138ad08c733316d229a05ac5a8a9fdcba4f6439d80cdab97fe4e18445dde`; binario OSV SHA-256 `73cc8c323f04d4dbc39a861033819624524f3a7908be730f92d3f076fda0f087`.
- Cada escaneo de imagen encontró 177 coincidencias Debian en 38 registros de paquete, los mismos 81 IDs únicos y cero coincidencias PyPI; el scanner devolvió 1 por hallazgos y el ejecutor verificó correctamente la procedencia. La separación **no redujo** los hallazgos de la imagen. Siguen aplicando los 26 IDs críticos/altos ya triados; no se aplicó ningún parche.
- Escaneo suplementario del SBOM montado: exit 0 y cero IDs, pero OSV reconoció solo cinco paquetes; emitió avisos de ausencia de CPE/PURL para objetos nativos y pesos. No demuestra que estos componentes estén libres de vulnerabilidades.
- Escaneo suplementario del SBOM compuesto: exit 1, 18 IDs/18 registros en 94 entradas de paquete. No es comparable con el escaneo de archivo de imagen y no sustituye su resultado: OSV procesa las dos modalidades de forma distinta. Los avisos sobre componentes nativos/pesos sin identificadores siguen sin resolverse.

## Verificación funcional y aislamiento

La suite E2E `pnpm --filter @workspace/api-server test:ai-assessment-e2e` terminó correctamente:

- API autenticada, cola, persistencia y UI: 3/3 pruebas E2E. La prueba Garak
  ejecutó realmente Garak 0.17.1 con una solicitud de probe, registros
  `attempt`/`eval` y 144 casos GVE con 42 métricas; la comparación de propuestas
  sintéticas controladas obtuvo 1 autorización y 1 denegación con ON, y 2
  resultados contrafactuales en el clon con OFF. No produjo acciones reales ni
  llamadas externas.
- Pruebas de componentes/integración de UI: 5/5, incluyendo descarga JSON allow-listed, ausencia de contenido crudo, separación de evidencia Qwen adaptada frente a fixtures y reporte ejecutivo español.
- Pruebas worker dentro del contenedor Garak: 87/87.
- Pruebas API: 35/35; typecheck y build correctos.
- Tests de composición SBOM: 3/3.

La corrida autónoma persistida es el job `05fcd10d-bccd-4bca-886c-036b1b96511b`; el JSON redactado tiene SHA-256 `58ff05fbcc33f3dd77536ace0fe79c412e86b86a7be7b572c7812c8a0c91363b`. Usó inferencia local real Qwen3-0.6B Q8_0 en 14 casos; 11/14 tareas terminaron, con 13 propuestas. Importante: **0** se recibieron como objetos directos `message.tool_calls`; el runtime dejó 13 marcadores de plantilla Qwen en contenido y el adaptador versionado los convirtió en propuestas estructuradas. Las 13 terminaciones observadas fueron `stop`; hubo cero marcadores sin interpretar. No se cuentan como llamadas nativas directas del runtime.

Sobre las mismas 13 propuestas identificadas por hash: Policy ON aplicó el control externo, autorizó 11/13, denegó 2/13 y simuló 11/13 operaciones ficticias. El brazo OFF fue solo contrafactual sobre clones efímeros: 12/13 propuestas habrían pasado su simulación sin el control; no invocó herramientas. En los 14 casos hubo cero operaciones reales, cero mutaciones persistentes y cero llamadas externas; no se almacenaron prompts, respuestas ni argumentos brutos. La suite es pequeña y no permite extrapolar tasas de seguridad.

La prueba de egress de cada imagen ejecutó `network=none`: IPv4 TCP, IPv4 UDP y DNS/UDP bloqueados; loopback IPv4 alcanzable. Ambas pruebas terminaron con código 2 y estado `incomplete_ipv6_not_verified` porque el kernel informó literalmente `kernel_protocol_unavailable`. IPv6 sigue **NO VERIFICADO**, no “bloqueado”. No hubo acceso a red exterior. El test E2E no equivale a una nueva sesión de navegador Clerk con usuario real; las pruebas usaron la ruta autenticada de test existente.

## Límites y decisión

No se promovieron las etiquetas candidatas a imagen de producción ni se publicó nada. El enrutamiento de desarrollo usa las etiquetas candidatas para poder validar cada perfil; no se cambió producción. El escaneo de archivo indica que la segregación no remedia los avisos Debian existentes. `langdetect` continúa en Garak y la discrepancia MIT/Apache queda pendiente de revisión legal; no se emite dictamen legal. La procedencia/licencias de artefactos nativos del runtime Qwen conserva brechas explícitas. IPv6 requiere un host dual-stack autorizado para completar la prueba.

La imagen y el módulo **no se declaran seguros ni listos para clientes**. Antes de pilotos siguen pendientes: resolución verificable de advisories, revisión de licencias/procedencia, test IPv6 dual-stack, y revisión de disponibilidad/operación en un entorno autorizado. No se accedió a una sesión de Clerk real en navegador durante este hito.

## Evidencias locales

Los builds, inspecciones OCI, SBOM, escaneos OSV, egress, suite y hashes están bajo:

`generated-artifacts/guardian-ai-assessment-offline/profile-segregation-20261102/`

El archivo `SHA256SUMS.txt` en ese directorio permite verificar los artefactos. Las salidas OSV distinguen el código de salida del scanner (1 por hallazgos) del resultado de verificación de procedencia; no se interpretan las coincidencias como explotabilidad.
