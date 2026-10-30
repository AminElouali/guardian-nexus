# Guardian AI Security Assessment — estado del laboratorio

**Estado:** ejecutable en desarrollo contra un agente de laboratorio local propio. No está habilitado como servicio para agentes o sistemas de clientes. No se ha creado una cuenta Scaleway, desplegado el worker ni conectado un proveedor de IA.

Resultados reproducibles de probes, recuperación de cola, escaneo de imagen y alternativas de worker: [validación técnica del 30 de octubre de 2026](guardian-ai-assessment-validation.md).

## Ejecución local

Requisitos: Docker Engine disponible y acceso a Internet únicamente durante la construcción de la imagen para descargar la base y dependencias. La evaluación en ejecución no descarga imágenes ni necesita acceso externo.

```sh
docker build --platform linux/amd64 \
  -f workers/guardian-ai-assessment/Dockerfile \
  -t guardian-ai-assessment:local \
  workers/guardian-ai-assessment

sh workers/guardian-ai-assessment/scripts/run-local.sh --self-test
sh workers/guardian-ai-assessment/scripts/run-local.sh
```

El runner fija el perfil `guardian-local-agent-v1`; no admite objetivos, URLs, probes ni parámetros Docker proporcionados por quien lo llama. Usa `--pull=never`, `--network=none`, filesystem de solo lectura, usuario no root, 0,5 CPU, 768 MiB de memoria, 64 procesos, timeout de hasta 120 segundos y `/tmp` efímero de 64 MiB. El agente de laboratorio escucha solo en loopback dentro del mismo contenedor. En la validación actual, IPv4 y DNS públicos resultaron bloqueados. IPv6 se informó como `unavailable` porque el kernel del host no ofrece ese protocolo; esto no se cuenta como prueba de bloqueo. Una activación remota queda bloqueada hasta verificar IPv4, IPv6 y DNS desde un entorno con capacidad dual-stack.

La evidencia conserva versión del motor, perfil y probe fijo, cantidad de solicitudes, resumen de puntuaciones, tipos y tamaño del informe, SHA-256, tiempos y resultado de las comprobaciones de red. No conserva el informe bruto, prompts, respuestas ni secretos. Una puntuación positiva es una señal del detector, no una vulnerabilidad confirmada. Una sola ejecución/probe no constituye una evaluación completa ni una garantía de seguridad.

## API, aislamiento y recuperación

- La API solo ofrece disponibilidad y ejecución cuando `NODE_ENV=development`, no está en despliegue y existe la imagen local.
- La cola ejecuta un contenedor cada vez por proceso API. No hay entrada de usuario hacia el agente ni credenciales dentro del contenedor.
- El estado y el resumen se guardan en `ai_assessment_jobs`, con clave idempotente por workspace, cuota, auditoría, roles owner/admin para iniciar o reintentar, y RLS forzado.
- El historial es legible por miembros del workspace. Reintentos limitados a dos intentos totales. Un poller de PostgreSQL reclama trabajos con `SKIP LOCKED`, leases de 45 segundos, heartbeats de 10 segundos y un único slot global; los leases caducados se recuperan automáticamente tras reinicio. No es una cola distribuida de alta disponibilidad.
- La prueba de red real descrita aquí corresponde al Docker local disponible en este entorno. Acredita el bloqueo observado de IPv4/DNS y el modo `network=none`, pero no el bloqueo de IPv6 ni el aislamiento de un proveedor cloud.

## Atribución y licencia

El módulo se presenta comercialmente como Guardian AI Security Assessment / Evaluación de Seguridad de IA. Usa NVIDIA Garak v0.17.1, proyecto de terceros bajo Apache-2.0. La atribución, versión y licencia se conservan en `manifest.json`, `THIRD_PARTY_NOTICES.md` y el detalle técnico de la evidencia. Guardian Nexus no reclama autoría del motor.

## Scaleway: preparado, no desplegado

No se ha creado una cuenta, no se han usado credenciales, no se ha subido la imagen ni se ha ejecutado ninguna tarea remota. La documentación oficial consultada el **30 de octubre de 2026** indica para Serverless Jobs:

- Cuota mensual por cuenta: 400.000 GB-s y 200.000 vCPU-s.
- Límites del servicio: 6 vCPU, 16 GB de memoria, 10 GB de almacenamiento efímero, 24 horas por ejecución; imagen `linux/amd64`.
- Para una estimación conservadora de **20 ejecuciones × 15 minutos × 1 GB y 0,5 vCPU**: 18.000 GB-s y 9.000 vCPU-s. Si toda la cuota estuviese disponible, el cómputo estaría dentro de la cuota gratuita; otros recursos o consumo de la cuenta pueden cambiar el coste. Registro de contenedores, impuestos y recursos adicionales no están incluidos.
- Por encima de la cuota publicada, la FAQ consultada muestra €0,000002/GB-s y €0,00001/vCPU-s. La facturación y las cuotas pueden cambiar; recalcular en la consola antes de cualquier despliegue.
- Las alertas de facturación son notificaciones, no un límite automático de gasto. El interruptor operativo previsto es no activar el disparador, cancelar ejecuciones activas y revocar el permiso de despliegue; esto requiere control operativo y no se ha configurado.

**Bloqueo de seguridad:** la FAQ oficial de Serverless Jobs indica que el producto todavía no admite VPC ni Private Networks. No se ha verificado un control que garantice el bloqueo de egress público IPv4/IPv6 y DNS desde un job. La red privada o el ingreso privado no equivalen a una política de denegación de salida. Por tanto, Scaleway Serverless Jobs no se debe usar para este evaluador hasta demostrar desde el job una regla externa de egress denegado y repetir los tests de conectividad. La opción Serverless Containers tampoco se considera válida sin esa prueba. Región UE y residencia extremo a extremo no verificadas.

Fuentes oficiales:

- [Serverless Jobs FAQ y cuota/costes](https://www.scaleway.com/en/docs/serverless-jobs/faq)
- [Límites de Serverless Jobs](https://www.scaleway.com/en/docs/serverless-jobs/reference-content/jobs-limitations/)
- [Serverless Containers FAQ y cuota/costes](https://www.scaleway.com/en/docs/serverless-containers/faq)
- [Precios de Serverless](https://www.scaleway.com/en/pricing/serverless/)
- [Alertas de facturación](https://www.scaleway.com/en/docs/billing/how-to/use-billing-alerts/)

## Activación futura, con aprobación

1. Crear la cuenta y seleccionar región solo tras verificar disponibilidad, contrato y residencia aplicables.
2. Mantener la clave de la cuenta en los secretos del workspace; nunca copiarla a código, imágenes, logs o chat. Crear credenciales con alcance mínimo, rotación y revocación.
3. Subir imagen firmada `linux/amd64` a un registry controlado y revisar todos los costes del registro.
4. No habilitar trabajos hasta disponer de control de red externo con denegación de salida probada desde el propio runtime para IPv4, IPv6 y DNS, más allowlist de loopback.
5. Empezar con concurrencia 1, límites de tiempo/CPU/memoria y disparo manual. Configurar alertas, probar el procedimiento de cancelación y revocación y verificar cuotas antes de habilitar más ejecuciones.
6. Aprobar por separado el despliegue, el consentimiento de región y cualquier coste. Este documento no representa autorización para crear recursos.
