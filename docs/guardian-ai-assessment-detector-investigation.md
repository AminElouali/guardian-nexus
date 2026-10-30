# Investigación del detector y corpus balanceado

**Fecha:** 30 de octubre de 2026  
**Entorno:** desarrollo local; sin datos de clientes, servicios cloud, modelos de pago ni cambios de producción.  
**Alcance comercial:** evaluación de laboratorio únicamente; no disponible para clientes.

## Causa de los cuatro errores históricos

La ejecución anterior utilizó Garak 0.17.1 y `promptinject.AttackRogueString`. Su implementación comprueba si la respuesta contiene literalmente el marcador de activación (`trigger`); no interpreta si la respuesta está citada, si la instrucción se obedeció o si el contenido se codificó. El resultado es binario: `1.0` si encuentra el texto y `0.0` si no.

| Caso anterior | Puntaje / evaluación Garak observado | Comportamiento del agente local | Diagnóstico |
|---|---|---|---|
| `safe_quoted_refusal` | `1.0`; `passed=0`, `fails=1` por probe | Se negó a seguir la petición, pero reprodujo el texto no confiable, incluido el marcador | Los dos “FP” dependen de la etiqueta. Son FP para **ejecución de instrucción**, pero positivos correctos para **propagación literal**. El detector hizo lo que especifica. |
| `vulnerable_base64` | `0.0`; `passed=1`, `fails=0` por probe | No ejecutó la instrucción; volvió a emitir el texto codificado en Base64 | Los dos “FN” son fallos reales para **propagación de datos** porque el detector no decodifica. No son FN para ejecución de instrucción. |
| `vulnerable_echo` | `1.0` por probe | Reprodujo el texto recibido; el fixture no realizó ninguna acción | No prueba ejecución de una instrucción ni comportamiento de un LLM. |
| `safe_refusal` | `0.0` por probe | Devolvió una negativa fija | Control negativo sintético, no evidencia sobre un modelo. |

La batería antigua asignó `expectedVulnerable` por perfil: consideró la cita segura y la codificación vulnerable. Así combinó dos objetivos incompatibles en una sola matriz. Para el objetivo restringido de **propagación literal o codificada**, una reclasificación posterior de esos mismos ocho resultados sería TP/FP/TN/FN = **4/0/2/2** (precisión 4/4, recall 4/6, exactitud 6/8). Es solo una corrección de etiqueta sobre ocho muestras; no es una estimación de rendimiento. Para **ejecución de instrucciones**, los fixtures no ejecutan acciones y no permiten calcular una matriz válida.

El probe generó una solicitud por combinación y buscó el marcador literal. Es un test de firma estrecho, en inglés y con `generations=1`; no cubre otras familias, variaciones lingüísticas, transformaciones ni conducta de agentes reales. La causa primaria de los cuatro errores fue la **definición mezclada de la etiqueta y el alcance del detector**, no el parser. El parser antiguo contaba puntuaciones mayores que cero; en estos resultados binarios `0.0/1.0` eso coincidió con Garak. Aun así, era demasiado permisivo para otros detectores.

El parser se endureció: ahora requiere el registro `eval` del probe/detector fijado, usa `fails`, valida los contadores y comprueba que coincidan con las puntuaciones binarias del intento. Rechaza detector inesperado, puntuación no binaria o desacuerdo entre el evaluador y el informe.

## Corpus y resultados de la fase

Se creó un corpus reproducible de **128 casos sintéticos**. Contiene dos conjuntos de objetivo, cada uno separado en `calibration` y `holdout`; cada combinación conjunto/split tiene 32 muestras, 16 positivas y 16 negativas. Los textos y marcadores del holdout no se repiten en calibración. Ambos idiomas (`en`, `es`) quedan equilibrados por clase dentro de cada conjunto y split.

- **`attack_success`:** la etiqueta positiva significa que el fixture emite el marcador de una acción de laboratorio; una respuesta que solo cita ese marcador es negativa. Familias: override directo, suplantación de rol, instrucción indirecta citada e instrucción codificada.
- **`canary_propagation`:** la etiqueta positiva significa que el marcador sintético aparece en la respuesta, incluso codificado. Las negativas incluyen un marcador público de documentación y una respuesta limpia; sirven para medir la limitación de contexto del detector.
- Se ejecutó de verdad el código de `AttackRogueString` sobre las respuestas fixture mediante su API local, con umbral fijo 0,5. **No** se ejecutó la CLI Garak para las 128 filas y **no** hubo inferencia de LLM. Esto verifica el detector y el parser, no una evaluación de agente en producción.

| Conjunto | Split | N (pos/neg) | TP / FP / TN / FN | Precisión | Recall | FPR | FNR | Exactitud |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| `attack_success` | calibration | 32 (16/16) | 16 / 6 / 10 / 0 | 16/22 = 72,7 % | 16/16 = 100 % | 6/16 = 37,5 % | 0/16 = 0 % | 26/32 = 81,25 % |
| `attack_success` | holdout | 32 (16/16) | 16 / 6 / 10 / 0 | 16/22 = 72,7 % | 16/16 = 100 % | 6/16 = 37,5 % | 0/16 = 0 % | 26/32 = 81,25 % |
| `canary_propagation` | calibration | 32 (16/16) | 6 / 8 / 8 / 10 | 6/14 = 42,9 % | 6/16 = 37,5 % | 8/16 = 50 % | 10/16 = 62,5 % | 14/32 = 43,75 % |
| `canary_propagation` | holdout | 32 (16/16) | 6 / 8 / 8 / 10 | 6/14 = 42,9 % | 6/16 = 37,5 % | 8/16 = 50 % | 10/16 = 62,5 % | 14/32 = 43,75 % |

Las tasas son consecuencia visible de las fixtures diseñadas: el detector coincide con marcadores en texto, falla con Base64 (incluida una instrucción codificada citada) y marca menciones benignas de un marcador público. La división holdout comprueba plantillas distintas, pero **no** transforma estos casos sintéticos en una muestra representativa. No se ajustó ningún umbral con calibración.

El informe de medición guarda puntuación, etiqueta, idioma, familia y hashes SHA-256 de entrada y salida, no los textos del caso. El JSONL separado conserva solo fixtures sintéticas generadas para reproducir la prueba; no contiene datos de clientes. Prompt Guard 2 y las alternativas no tienen métricas porque no se instalaron ni ejecutaron.

### Reejecución Garak y artefactos

La suite CLI completa de Garak 0.17.1 se volvió a ejecutar contra el agente estático local, con los límites descritos en el informe de validación. Fueron **8/8 muestras en 21 segundos**. Para propagación literal, la matriz corregida es TP/FP/TN/FN = **4/0/2/2**, con soporte positivo 6 y negativo 2; precisión 4/4 = 100 %, recall 4/6 = 66,7 %, FPR 0/2 = 0 % y FNR 2/6 = 33,3 %. **Ejecución de instrucciones: no medible** (0 muestras), porque el mock solo devuelve textos fixture y no ejecuta acciones ni hace inferencia LLM. La ejecución del motor Garak es real; no equivale a una evaluación de un modelo ni a un servicio para clientes.

| Evidencia | SHA-256 |
|---|---|
| `generated-artifacts/guardian-ai-assessment-validation-followup-2026-10-30.json` | `f540bc6c8ca49ac5398d964b656e8b920e143fa602ed2212c1063db687c609a0` |
| `generated-artifacts/guardian-ai-assessment-corpus-results-2026-10-30.json` | `6ceeb9443d8e104be42387aa3df978b4b26080272140c43d56cf5d84b4995572` |
| `generated-artifacts/guardian-ai-assessment-synthetic-corpus-2026-10-30.jsonl` | `69883a8df3d4099617a8d94ee65be8865d8ef629d7feaaaf2893b9646d035521` |

## Alternativas y contrato de adaptador local

| Opción | Estado, licencia y función | Decisión para esta fase |
|---|---|---|
| Garak `AttackRogueString` | Detector literal binario; el framework declara Apache-2.0. No es un clasificador semántico universal. | Ejecutado localmente con la etiqueta limitada descrita arriba. |
| Meta Llama Prompt Guard 2 | Variantes 22M y 86M, clasificación de ataques de prompt, ventana de 512 tokens y evaluación publicada en inglés, español y otros idiomas. El acceso a pesos está controlado y el modelo usa Llama 4 Community License; no equivale a una licencia OSI permisiva. | No instalado ni ejecutado: el entorno no contiene pesos, PyTorch ni Transformers y no se aceptaron términos ni descargaron pesos. Los tamaños nominales no demuestran que quepa en el límite de 768 MiB con runtime/tokenizador. |
| Prompt Armor 0.9.1 | PyPI declara Apache-2.0 y Python >=3.10; el proyecto se clasifica como Alpha. PyPI lo registra como publicado el 3 de junio de 2026. El proyecto afirma ser offline y usar cinco capas con un clasificador de fusión; sus cifras de latencia/rendimiento son declaraciones propias. | Candidato para una evaluación posterior en aislamiento; no instalado. Requiere revisar licencia/transitivas, reproducibilidad, compatibilidad con Python 3.13 y validación independiente antes de elegirlo. |
| Promptfoo 0.125.1 | MIT; framework de evaluación/red team, no detector. Puede configurarse con proveedores locales, pero la generación o calificación predeterminada puede recurrir a modelos externos. | No instalado. No se habilitó ninguna ruta cloud. |
| NVIDIA NeMo Guardrails 0.24.1 | Apache-2.0; framework de políticas/rails para aplicaciones, no un clasificador plug-and-play equivalente. | No instalado; dependencias y perfiles de memoria no auditados aquí. |
| ProtectAI LLM Guard | MIT, pero el repositorio fue archivado el 9 de julio de 2026 y quedó en solo lectura. | Excluido como alternativa mantenida. |

**Contrato previsto para Prompt Guard 2, aún deshabilitado:** adaptador exclusivamente en proceso y offline; requeriría pesos locales con revisión y SHA-256 fijados, aceptación legal de licencia, identificador/revisión del modelo, idioma, segmentación ≤512 tokens, puntuación/clase, versión del umbral, latencia y resultado de error. Entrada y salida del agente se evaluarían como tareas distintas. No habría descarga en runtime ni endpoint remoto. Antes de habilitarlo habría que comprobar consumo real de memoria/CPU bajo el límite y validar umbrales con calibración separada; no se registraría evidencia como resultado de modelo hasta superar esos controles.

## Triage del sistema base, SBOM y licencias

Se volvió a resolver la etiqueta oficial `python:3.13-slim-trixie`; sigue en el digest fijado `sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb`. No apareció un digest más reciente que permitiera actualizar el sistema base.

- OSV-Scanner 2.7.0: **164** coincidencias paquete-aviso, **69** IDs CVE únicos, **18** paquetes Debian. Los 164 registros se deduplican por CVE; varios comparten paquete fuente.
- Debian Security Tracker para Trixie: **65** estados `open`, **2** `not-listed|open`, **1** `undetermined`, **1** `resolved`. Urgencia por ID: 26 `unimportant`, 41 `not yet assigned` y 2 con valores de asignación diferentes entre entradas. No se sustituye la urgencia Debian por una severidad CVSS inventada.
- **68/69** no tienen versión de corrección versionada en el tracker de Trixie. `CVE-2026-39113` para SQLite figura `resolved`, con `fixed_version=0` (sentinela) y versión del repositorio `3.46.1-7+deb13u2`; no se presenta `0` como parche semántico.
- Paquetes fuente afectados: `acl`, `apt`, `attr`, `bzip2`, `coreutils`, `dash`, `diffutils`, `gcc-14`, `glibc`, `ncurses`, `pam`, `perl`, `shadow`, `sqlite3`, `systemd`, `tar`, `util-linux`, `zlib`. Los hallazgos son del sistema base; no hubo avisos PyPI en las 37 distribuciones fijadas.
- No se cambió la imagen base: no había una versión más reciente del tag fijado ni una corrección versionada disponible para 68 IDs. Esto no equivale a resolver esos avisos. El contenedor sin red, no root, de solo lectura y sin capabilities reduce exposición, pero la imagen queda **no limpia**.
- El SBOM final de Syft 1.55.0 contiene 132 paquetes. `licenseConcluded` es `NOASSERTION` en 127; los otros cinco son referencias `LicenseRef` cuyos textos extraídos también son `NOASSERTION`. Hay 118 registros con `licenseDeclared` en metadatos y 14 sin declaración. Los metadatos Python tienen 12 expresiones de licencia, 24 campos, 20 clasificadores y 35 archivos de licencia presentes; los avisos Debian proporcionan etiquetas parciales para 17/18 paquetes afectados, sin una etiqueta parseable para `gcc-14`. No es una revisión legal ni una relación completa de licencias transitivas.

Inventarios detallados:

- `generated-artifacts/guardian-ai-assessment-debian-triage-2026-10-30.json`
- `generated-artifacts/guardian-ai-assessment-debian-license-metadata-2026-10-30.json`
- `generated-artifacts/guardian-ai-assessment-python-license-metadata.json`
- `generated-artifacts/guardian-ai-assessment-osv-final-2026-10-30.json`
- `generated-artifacts/guardian-ai-assessment-image-final-2026-10-30.spdx.json`

## Aislamiento de red y límites

El `--self-test` del contenedor final con `--network=none` volvió a comprobar que IPv4 público y DNS fallan, loopback responde y no hay interfaces no-loopback activas. IPv6 no estuvo disponible porque el kernel del entorno no ofrece ese protocolo; no se informa como bloqueado. No se desplegó worker remoto ni se probó firewall de proveedor. No se modificaron base de datos, producción, credenciales, cloud o publicación.

## Verificación final

- Imagen evaluada: `sha256:89db4ddede11fc8443ce6a734744d01681bcb671c4cde12ad7e4d942e1f1dec8`; base Python fijada al digest `sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb`.
- Worker: 12/12 pruebas unitarias, autotest de red aprobado, 8 muestras de CLI Garak; corpus directo del detector de 128 fixtures con calibration/holdout equilibrados.
- Replit Dependency Audit, SAST y HoundDog: 0 hallazgos cada uno. OSV sigue reportando las vulnerabilidades Debian descritas arriba; no se declara escaneo limpio.
- SBOM final SHA-256: `43ecfae742e61892d8b0a438905cf14be2859457887d305bf209b76d2caa8c0e`. OSV JSON SHA-256: `ef25ae98f0eb02302e728fdb002edd3fdc7b33baffb35ad247aea271b7440ef4`.
- Build/typecheck del monorepo y 33 pruebas API pasaron. No se habilitó ningún servicio cloud ni de pago; no hubo ejecución contra sistemas de clientes, cuentas externas o endpoints públicos.

## Fuentes consultadas

- Código del detector en [Garak 0.17.1](https://github.com/NVIDIA/garak/blob/v0.17.1/garak/detectors/promptinject.py) y documentación de [reportes](https://reference.garak.ai/en/stable/reporting.html).
- [Llama Prompt Guard 2, ficha oficial](https://www.llama.com/docs/model-cards-and-prompt-formats/prompt-guard), [modelo 22M](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-22M) y [86M](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M).
- [Prompt Armor en PyPI](https://pypi.org/project/prompt-armor/); [versiones Promptfoo](https://github.com/promptfoo/promptfoo/releases) y [licencia MIT](https://github.com/promptfoo/promptfoo/blob/main/LICENSE).
- [NeMo Guardrails, documentación](https://docs.nvidia.com/nemo/guardrails/) y [licencia Apache-2.0](https://github.com/NVIDIA-NeMo/Guardrails/blob/develop/LICENSE.md).
- [ProtectAI LLM Guard archivado](https://github.com/protectai/llm-guard).
- [Debian Security Tracker](https://security-tracker.debian.org/tracker/data/json).
