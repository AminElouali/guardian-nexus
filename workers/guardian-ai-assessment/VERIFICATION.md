# Guardian Verification Engine (laboratorio local)

## Alcance

La Evaluación de Seguridad de IA incluye un motor determinista que ejecuta
fixtures sintéticos con herramientas locales instrumentadas. No realiza
inferencia con un LLM y no evalúa un agente real de cliente. La interfaz y los
informes usan la marca Guardian Nexus; los resultados se identifican como
laboratorio interno.

El diseño toma como referencia general la evaluación de uso de herramientas y
límites de confianza. No se incorpora código, conjunto de datos ni dependencia
de AgentDojo. El motor Garak que sigue formando parte de la evaluación es de
terceros: Garak 0.17.1, licencia Apache-2.0,
<https://github.com/NVIDIA/garak>.

## Ejecución y aislamiento

El modo fijo `scripts/run-local.sh --verification-suite` ejecuta solamente el
conjunto Guardian Verification dentro del contenedor existente. El runner fija
`--network=none`, filesystem de solo lectura, 0,5 CPU, 768 MiB de memoria,
64 procesos, usuario no root, sin capacidades y `/tmp` efímero de 64 MiB. No
acepta objetivos, comandos Docker, credenciales ni parámetros proporcionados
por el solicitante. El evaluador no incluye clientes HTTP, DNS ni proveedores
de modelos.

El trabajo de cola conserva el mismo contenedor, permisos, cuota, lease y
alcance RLS existentes. La evidencia adicional se guarda dentro del resultado
JSONB del trabajo del workspace. No requiere una nueva tabla ni migración.
Los resultados anteriores sin `guardianVerification` siguen siendo válidos.
El conjunto tiene un límite de 15 segundos, 144 casos y concurrencia uno,
además de los límites del contenedor ya descritos.

El conjunto Guardian no prueba bloqueo de egress. La ruta Garak existente
conserva su comprobación propia; la disponibilidad IPv6 del kernel sigue siendo
una limitación independiente y no se afirma como bloqueada por este conjunto.

## Fixtures y oráculos

Hay tres escenarios: exfiltración de un canario sintético a un destinatario
externo, operación administrativa no autorizada e inyección indirecta en un
documento no confiable. Cada escenario y cada partición contiene 24 casos:
cuatro semillas por cada uno de seis tipos — fixture vulnerable, fixture
guardado, intento bloqueado y tres controles benignos.

Las políticas de cada escenario son listas separadas de los permisos efectivos
del fixture. Cada llamada registra operación, autorización, decisión de la
política, ejecución, cambio de estado y presencia de taint sintético. El oráculo
comprueba además que una llamada denegada no cambia el estado. Una concesión
intencionalmente excesiva en el fixture vulnerable permite observar un efecto
en memoria y clasificar la violación de política; no puede enviar correo ni
alterar un sistema externo.

Se informan siete objetivos separados: presencia de texto no confiable,
propagación de dato sintético, obediencia a la instrucción no confiable, intento
de acción, intento no autorizado, acción efectivamente ejecutada y violación
de política. La obediencia procede de la traza estructurada del agente de
fixture; los intentos y efectos proceden del registro de herramientas y del
estado; la política procede de un oráculo independiente de los permisos del
fixture. No se decide por coincidencia de cadenas ni por un juez LLM.

## Corpus y lectura de métricas

El corpus tiene 144 ejecuciones-fixture: 72 de calibración y 72 de holdout,
repartidas por igual entre los tres escenarios. Cada fila de métricas incluye
soporte positivo y negativo, TP, FP, TN, FN y denominadores de las tasas. Las
tasas describen exclusivamente la conformidad de estos fixtures y oráculos
deterministas. No estiman precisión general, robustez de LLM ni seguridad de
agentes en producción. Un resultado sin falsos positivos en este conjunto no es
una garantía.

La evidencia conserva versión de motor, agente, políticas y oráculo; cada
identificador incluye escenario, partición, semilla y tipo de fixture; también
incluye máscaras esperadas/observadas, contadores de autorización/ejecución/
cambios por operación y hashes SHA-256 por caso y del conjunto. El hash por
caso cubre el texto sintético y la traza completa instrumentada (argumentos y
transiciones de estado solo en forma de hash). No se conserva la traza
individual, prompts, respuestas ni valores del canario. El resultado marca
explícitamente `syntheticOnly`, cero llamadas externas y ausencia de datos de
clientes.

## Validación local

Con la imagen local ya construida, desde este directorio:

```sh
scripts/run-local.sh --unit-tests
scripts/run-local.sh --verification-suite
```

Ambas órdenes usan el runner fijo y las mismas restricciones de contenedor. La
salida de la segunda es evidencia del fixture local, no de un agente de cliente.
El modo de pruebas ejecuta también los controles del detector Garak ya
integrados, dentro del contenedor y sin inferencia LLM. Para generar un
resultado combinado se usa únicamente el flujo de trabajo de desarrollo
existente y no se habilitan objetivos externos.

El modo `--unit-tests` verifica el ID de imagen contra
`profile-image-lock.json` y monta el checkout completo de este worker en
`/opt/guardian-assessment` como solo lectura. Así, los tests, el código, los
manifiestos y los scripts helper proceden del mismo commit; las dependencias
instaladas proceden de la imagen fijada. Un ID distinto falla antes de crear el
contenedor.

## Pendientes

- No valida seguridad de un LLM real ni está habilitado como servicio para
  clientes.
- No se ha desplegado ningún worker remoto ni se ha probado una política de
  egress IPv6 externa.
- SBOM, licencias y avisos de la imagen completa siguen sujetos a la auditoría
  previa; esta implementación no los declara resueltos.
- No se añade Model Armor, cloud, dependencia Python, ni nuevo coste.
