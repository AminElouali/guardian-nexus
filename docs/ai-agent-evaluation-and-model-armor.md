# Evaluación experimental de agentes IA y Model Armor

Estado al 30 de octubre de 2026. Esto documenta una fase experimental; no acredita seguridad, cobertura ni cumplimiento de ningún agente o tenant.

## Estado que sí está implementado

- La vista **Seguridad IA** ofrece una simulación fija de tres casos sobre fixtures internos: inyección de instrucciones, canario sintético de datos y límite de herramientas. La función produce resúmenes deterministas; no recibe prompts libres ni se conecta a un agente.
- Solo `owner` y `admin` pueden iniciar la simulación. Se reserva una unidad de análisis y una solicitud API bajo la cuota del workspace.
- La ejecución se limita a una por proceso y tres fixtures. La evidencia se guarda en `workspace_audit_events`, con RLS forzado y acceso tenant-scoped. Solo almacena códigos de resultado y versión; no almacena prompts, respuestas o secretos.
- Las pruebas internas ejercitan resultados de fallo sin incluir el valor del canario sintético. Los resultados de la página están rotulados como simulados, no como hallazgos reales.
- El contrato del adaptador Model Armor requiere feature flag, consentimiento del tenant, proyecto, plantilla de prompt y plantilla de respuesta, credencial en memoria y ubicación UE admitida. La función de adaptación está desacoplada del transporte para permitir pruebas sin red; no se ha implementado una llamada REST real ni se ha configurado una credencial.

## Bloqueos de NVIDIA garak

- El proyecto no tiene instalado `garak` (`python -m garak --version` no está disponible); no se añadió una dependencia.
- La simulación Guardian Nexus no invoca garak, no equivale a sus probes y no debe describirse como evaluación garak.
- La documentación de garak presenta un generador REST configurable (`uri`, plantilla de solicitud y campo de respuesta). Un runner real debe construir el URI de un agente/mock controlado y rechazar toda dirección no loopback.
- No se ejecutará desde el proceso web hasta contar con un worker aislado, egress bloqueado salvo loopback, límites OS verificables de CPU/memoria/tiempo/salida, cuota/idempotencia distribuida y persistencia de la versión y el informe saneado bajo RLS. La concurrencia en memoria actual es solo un límite de proceso, no una cola distribuida.
- NVIDIA garak está publicado bajo Apache-2.0 según el repositorio oficial consultado. No se ha evaluado aún su árbol completo de dependencias/licencias para distribución comercial ni se ha ejecutado un audit tras instalarlo porque no se instaló.

## Model Armor: viabilidad revisada, integración todavía desactivada

- Model Armor es un servicio gestionado de Google Cloud, no una biblioteca open-source. La REST API tiene operaciones separadas para `sanitizeUserPrompt` y `sanitizeModelResponse`; exigen OAuth `cloud-platform` y los permisos IAM `modelarmor.templates.useToSanitizeUserPrompt` y `modelarmor.templates.useToSanitizeModelResponse`.
- La documentación oficial lista la multirregión `eu` y varias regiones de la UE. Para plantillas, Google declara controles de residencia at-rest, in-use y in-transit en las localizaciones UE con soporte completo; hay que seleccionar una ubicación y plantilla compatible y revisar los términos/DPA y el flujo completo de datos antes de habilitarla. La residencia configurada en ese servicio no demuestra por sí sola residencia extremo a extremo de Guardian Nexus.
- Google indica que prompts y respuestas son datos principales procesados y no almacenados en reposo por Model Armor; la configuración de plantillas sí se almacena en reposo. Esto requiere evaluación de privacidad y consentimiento explícito del cliente antes de enviar contenido.
- La página pública consultada indica hasta 2 millones de tokens/mes gratis y 0,10 USD por cada millón adicional. El coste esperado ahora es **0 USD**, ya que el feature flag está apagado y no se hizo ninguna llamada. Al activarlo, cualquier volumen superior al tramo gratuito puede generar facturación; las tarifas pueden cambiar.
- No hay credenciales, consentimiento del tenant, proyecto, plantillas ni autorización para enviar datos; no se realizaron llamadas cloud. La configuración y el transporte real permanecen bloqueados.

## Referencias oficiales

- NVIDIA garak CLI y parámetros: https://reference.garak.ai/en/stable/cliref.html
- NVIDIA garak REST generator: https://reference.garak.ai/en/latest/generators/rest.html
- NVIDIA garak LICENSE (Apache-2.0): https://github.com/NVIDIA/garak/blob/main/LICENSE
- Model Armor overview, manejo de datos y precios: https://docs.cloud.google.com/model-armor/overview
- Ubicaciones: https://docs.cloud.google.com/model-armor/locations
- Residencia y endpoints: https://docs.cloud.google.com/model-armor/data-residency
- API de sanitización de prompt: https://docs.cloud.google.com/model-armor/reference/rest/v1/projects.locations.templates/sanitizeUserPrompt
- API de sanitización de respuesta: https://docs.cloud.google.com/model-armor/reference/rest/v1/projects.locations.templates/sanitizeModelResponse

## Próximo incremento, sujeto a confirmación

1. Aprobar e instalar una versión fijada de garak y revisar sus dependencias/licencias.
2. Proveer un worker local o aislado con política de red que permita solo el mock local; validar que no pueda alcanzar endpoints públicos.
3. Implementar una cola idempotente con límites distribuidos por tenant, persistir versión/hash de informe y aplicar redacción de secretos antes de registrar evidencia.
4. Aprobar por separado la autorización de Google Cloud, la ubicación UE y el posible gasto; entonces implementar el transporte REST con identidad de workload y consentimiento por tenant.
