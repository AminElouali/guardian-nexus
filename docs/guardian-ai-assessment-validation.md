# Validación técnica — Evaluación de Seguridad de IA

**Fecha:** 30 de octubre de 2026  
**Entorno:** desarrollo local de Replit; sin datos de clientes, cuentas cloud ni modelos de pago.  
**Estado comercial:** evaluación real ejecutada solo en laboratorio. No está habilitada para clientes.

## Ejecución real y medición acotada

Se ejecutó NVIDIA Garak 0.17.1 en la imagen `guardian-ai-assessment:local` contra cuatro perfiles sintéticos del agente local autorizado. Se usaron dos probes fijos (`HijackLongPrompt` y `HijackHateHumans`), una solicitud por probe y perfil, semilla `20261030` y ocho muestras totales. Cada muestra conserva solo metadatos, tamaño y SHA-256 del informe; no se guardaron prompts ni respuestas brutas.

**Límites observados:** contenedor Docker `--network=none`, 0,5 CPU, 768 MiB, 64 procesos, concurrencia 1, máximo 240 segundos para la suite y almacenamiento temporal efímero. La primera ejecución tardó 25,27 segundos; la repetición tras endurecer el parser tardó 21 segundos. No hubo llamadas externas ni datos de clientes.

**Aislamiento observado:** `publicIpv4=blocked`, `publicDns=blocked`, `loopbackOnly=true`, sin interfaces no-loopback activas. `publicIpv6=unavailable` porque el kernel del host no ofrece el protocolo IPv6. Por tanto, IPv6 no está probado como bloqueado; tampoco se acredita aislamiento remoto.

### Resultado del clasificador de laboratorio

| Métrica | Resultado |
|---|---:|
| Muestras | 8 |
| Positivas esperadas | 4 |
| Negativas esperadas | 4 |
| TP / FP / TN / FN | 2 / 2 / 2 / 2 |
| Exactitud | 4/8 = 50 % |
| Precisión | 2/4 = 50 % |
| Recall | 2/4 = 50 % |
| Tasa de falsos positivos | 2/4 = 50 % |
| Tasa de falsos negativos | 2/4 = 50 % |

Por perfil, el informe histórico registró `vulnerable_echo` 2/2, `safe_refusal` 2/2, `safe_quoted_refusal` como 2/2 falsos positivos y `vulnerable_base64` como 2/2 falsos negativos. Una revisión posterior encontró que se mezclaron dos objetivos incompatibles —ejecución de instrucciones y propagación de texto— en una sola etiqueta. No deben usarse esos 50 % como medida de seguridad general; la causa y la reevaluación separada se documentan en [Investigación del detector y corpus balanceado](guardian-ai-assessment-detector-investigation.md).

Las huellas SHA-256 y tamaños por muestra están en `generated-artifacts/guardian-ai-assessment-validation-2026-10-30.json`. El artefacto no incluye contenido bruto.

## Dependencias, imagen, SBOM y licencias

- Imagen final evaluada: `sha256:89db4ddede11fc8443ce6a734744d01681bcb671c4cde12ad7e4d942e1f1dec8`.
- Base fijada en el manifiesto: `python:3.13-slim-trixie`, digest `sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb`.
- Garak 0.17.1; `aiohttp`, `nltk` y `requests` se actualizaron a versiones fijadas. Auditoría de dependencias de Replit: 0 hallazgos; SAST: 0; HoundDog: 0.
- OSV-Scanner 2.7.0 sobre la imagen final: 164 coincidencias paquete-aviso Debian, 69 CVE únicos, 18 paquetes afectados y 0 avisos PyPI en las 37 distribuciones Python. La verificación contra Debian Security Tracker agrupa los CVE como 65 `open`, 2 `not-listed|open`, 1 `undetermined` y 1 `resolved`; urgencia Debian: 26 `unimportant`, 41 `not yet assigned` y 2 con campos de asignación discrepantes. 68/69 no tienen versión corregida versionada en Trixie; el único resuelto es `CVE-2026-39113` con `fixed_version=0` (sentinela, no una versión de parche). La etiqueta oficial de la imagen continúa en el mismo digest fijado, por lo que no se encontró una actualización de base disponible para aplicar. OSV termina con código distinto de cero porque encontró esos avisos; el informe JSON se generó completo.
- Los avisos Debian permanecen abiertos como deuda de riesgo; no se declara la imagen limpia. La urgencia Debian es específica de la distribución, no una clasificación CVSS universal. La ejecución del worker no root, sin red, con filesystem de solo lectura y sin capabilities reduce exposición, pero no elimina los defectos del sistema base.
- SBOM final generado con Syft 1.55.0: 132 paquetes; 127 tienen `licenseConcluded=NOASSERTION` y los otros cinco usan `LicenseRef` cuyos textos extraídos también son `NOASSERTION`. Hay 118 registros con `licenseDeclared` en metadatos y 14 sin declaración; esto no sustituye una revisión legal. El inventario Python cubre 37 metadatos de paquetes (12 expresiones, 24 campos, 20 clasificadores y 35 archivos de licencia presentes), no es revisión legal. Para los 18 paquetes afectados, se extrajeron etiquetas `License:` parciales de 17 avisos Debian; `gcc-14` sigue sin licencia identificada en ese inventario. Garak declara Apache-2.0 y conserva atribución en `workers/guardian-ai-assessment/THIRD_PARTY_NOTICES.md`.
- SBOM final: `generated-artifacts/guardian-ai-assessment-image-final-2026-10-30.spdx.json`. Informe OSV: `generated-artifacts/guardian-ai-assessment-osv-final-2026-10-30.json`. Triages: `generated-artifacts/guardian-ai-assessment-debian-triage-2026-10-30.json` y `generated-artifacts/guardian-ai-assessment-debian-license-metadata-2026-10-30.json`. Inventario Python: `generated-artifacts/guardian-ai-assessment-python-license-metadata.json`. La cobertura de licencias sigue incompleta y requiere revisión antes de admitir cargas de clientes.

## Cola durable y límites de tenant

La API mantiene los trabajos en PostgreSQL; no hay cola en memoria. El claim usa `FOR UPDATE SKIP LOCKED`, lease de 45 s, heartbeat cada 10 s, recuperación por poll cada 2 s y máximo de dos intentos. El índice de slot limita la concurrencia local global a uno. Al caducar el lease se recupera el trabajo una vez; al agotar intentos pasa a fallido y libera el slot. El contenedor anterior se elimina al reclamar un lease vencido para reducir ejecuciones duplicadas.

El rol de cola es `NOLOGIN`, no propietario y sin `SUPERUSER`/`BYPASSRLS`; solo recibe columnas de metadatos necesarias para reclamar trabajos, no el resultado/evidencia. RLS está forzado; las consultas de usuario siguen limitadas al workspace. La preflight de la API verifica los roles y las cinco políticas antes de iniciar el poller. La configuración y las pruebas corresponden solo a la base de desarrollo, no producción.

Pruebas API: **33/33**. Incluyen dos claims concurrentes, lease, heartbeat, recuperación tras expiración, rechazo de un lease obsoleto, fallo al agotar intentos, aislamiento de resultados entre tenants y denegación de lectura/escritura cruzada. El rol interno de cola puede leer solo los metadatos necesarios de trabajos en varios tenants; no puede leer resultados ni modificar tenant/actor. Sigue siendo una única cola local, no alta disponibilidad distribuida.

## Opciones de worker remoto europeo

Consulta de documentación oficial: 30 de octubre de 2026. Ninguna opción se desplegó ni se probó desde una cuenta cloud. `network=none` en el contenedor hijo debe mantenerse; el proceso de control remoto necesitaría un canal de salida limitado al plano de control, separado de la evaluación offline.

| Opción | Lo verificado en documentación oficial | Coste orientativo | Decisión |
|---|---|---|---|
| Scaleway Serverless Jobs | La FAQ publica cuota mensual de 400.000 GB-s y 200.000 vCPU-s, pero confirma que actualmente no admite VPC ni Private Networks. No se encontró una garantía documentada de denegación total de egress público. | Con 100 ejecuciones de 25,27 s, 0,5 vCPU y asignación de 1 GiB: ~1.263,5 vCPU-s y 2.527 GB-s; con las tarifas publicadas equivale a ~€0,018 de cómputo antes de cuota gratuita. No incluye registry, logs ni otros recursos. | No apto hasta que el proveedor permita y se pruebe egress fail-closed. La cuota gratuita no resuelve el bloqueo de red. |
| Hetzner Cloud, Alemania/Finlandia | Las reglas de salida personalizadas hacen que el tráfico no coincidente se descarte. Se debe configurar una allowlist de salida; la documentación no sustituye el test dual-stack/DNS desde el worker. | Cloud compartido desde €5,99/mes sin IVA en la página consultada; sin cuota gratuita de cómputo. | Candidato económico para VM dedicada. Requiere firewall del proveedor más reglas host y aceptación técnica. |
| OVHcloud Public Cloud | Los Security Groups filtran conexiones entrantes y salientes. La guía advierte que el grupo predeterminado permite tráfico y no debe modificarse; crear un grupo propio y comprobar reglas efectivas. | B2-7 publicado a €25,17/mes; Gateway S ~€2,044/mes si la arquitectura lo necesita. Prueba inicial de €200 por un mes, sujeta a elegibilidad; no es gratuidad permanente. | Candidato, con coste superior y prueba obligatoria de denegación dual-stack. |
| IONOS Cloud | Los NSG admiten reglas EGRESS y selección IPv4/IPv6. La FAQ indica que el grupo preconfigurado permite todo el egress IPv4 e IPv6; hace falta un grupo personalizado y verificación de reglas efectivas. | No se determinó un precio mensual reproducible en documentación estática; requiere calculadora/cotización. | Candidato sujeto a un plan que permita denegación de salida y pruebas externas. |

### Criterio de aceptación remoto y kill switches

Antes de habilitar un worker remoto, el proceso de despliegue debe abortar si cualquiera de estas condiciones no se acredita:

1. Desde el contenedor de evaluación, comprobar que loopback funciona y que conexiones de prueba a destinos públicos IPv4, IPv6 y DNS por UDP/TCP fallan; `unavailable` en IPv6 cuenta como **no verificado**, no como bloqueado.
2. Confirmar en el firewall externo y en el host una política deny-by-default; repetir las pruebas tras reinicio. El ingreso privado no prueba la política de egress.
3. Mantener el contenedor Garak sin interfaz externa (`--network=none`). El proceso de control, si se implementa, solo puede hablar con un endpoint fijo autenticado del plano de control.
4. Concurrencia 1, límite de trabajos por periodo, timeout fijo, presupuesto mensual y alertas. Las alertas de facturación notifican pero no necesariamente detienen cargos; el kill switch operativo es desactivar el disparador, cancelar jobs y apagar/revocar el worker. No hay kill switch cloud configurado.

## Fuentes oficiales

- Scaleway [FAQ de Serverless Jobs](https://www.scaleway.com/en/docs/serverless-jobs/faq) y [limitaciones](https://www.scaleway.com/en/docs/serverless-jobs/reference-content/jobs-limitations/).
- Hetzner [reglas de Cloud Firewall](https://docs.hetzner.com/cloud/firewalls/faq), [ubicaciones](https://docs.hetzner.com/cloud/general/locations) y [precio Cloud](https://www.hetzner.com/cloud/).
- OVHcloud [Security Groups](https://docs.ovhcloud.com/en/guides/public-cloud/compute/setup-security-group), [precios Public Cloud](https://www.ovhcloud.com/en-ie/public-cloud/prices/) y [crédito de prueba](https://www.ovhcloud.com/en-ie/public-cloud/free-trial).
- IONOS [FAQ de NSG](https://docs.ionos.com/cloud/security/network-security-groups/nsg-faqs), [reglas EGRESS IPv4/IPv6](https://docs.ionos.com/cloud/security/network-security-groups/how-tos/create-rules) y [calculadora](https://price-calculator.cloud.ionos.com/).

## Comprobaciones ejecutadas y bloqueos

- Worker: **12/12 pruebas unitarias**; `--self-test` pasó. Suite Garak CLI real: 8/8 ejecuciones locales en 21 s; corpus sintético de detector: 128/128 casos, con calibración y holdout separados. Evidencia y límites en `docs/guardian-ai-assessment-detector-investigation.md`.
- API: **33/33** pruebas; typecheck y build del monorepo completados con `PORT=3000` y `BASE_PATH=/__mockup`, requeridos por la configuración del build. Vite muestra una advertencia no bloqueante de bundle superior a 500 kB en la plataforma.
- Seguridad: auditoría de dependencias de Replit, SAST y HoundDog sin hallazgos; OSV mantiene avisos del sistema base pendientes de triage.
- No se publicó, no se modificó producción, no se creó infraestructura cloud y no se conectaron sistemas de clientes.
- Bloqueos antes de piloto: IPv6 remoto no verificado; avisos Debian sin parche versionado y 41 CVE con urgencia aún no asignada; revisión completa de licencias pendiente; worker remoto y monitor externo no desplegados; corpus actual usa respuestas sintéticas y no valida modelos reales.
