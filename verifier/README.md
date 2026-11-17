# Verificador público del ledger / Public ledger verifier

## Español

`verify_approval_ledger.py` es un verificador independiente de un bundle v1 de Guardian Nexus. Solo usa Python 3, su biblioteca estándar y OpenSSL del sistema para Ed25519; no importa el monorepo, no necesita la API, una base de datos ni conexión de red.

El programa comprueba al inicio que el OpenSSL seleccionado puede exportar una clave pública SPKI con `pkey -pubin -in <public.pem> -pubout -outform DER` y verificar Ed25519 en bruto con `pkeyutl -verify -pubin -inkey <public.pem> -rawin -in <message> -sigfile <signature>`. La sonda verifica un vector público RFC 8032; no contiene ni usa una clave privada. Si las operaciones no están disponibles, imprime `unsupported_openssl` y una instrucción segura por stderr, y termina con código 2. Se puede elegir el binario con `--openssl PATH` (tiene prioridad) o con `LEDGER_OPENSSL`.

**macOS:** el OpenSSL de sistema puede ser LibreSSL. Instala OpenSSL 3 con Homebrew y pásale la ruta resuelta por Homebrew:

```sh
brew install openssl@3
python3 verifier/verify_approval_ledger.py \
  --openssl "$(brew --prefix openssl@3)/bin/openssl" \
  --bundle ./bundle.json \
  --trusted-keys ./trusted-ledger-keys.json
```

También se puede usar `LEDGER_OPENSSL="$(brew --prefix openssl@3)/bin/openssl"` antes del comando. No se selecciona un binario solo por su número de versión: la prueba funcional decide. OpenSSL 1.1.1 documenta que `pkeyutl` no admite Ed25519; OpenSSL 3.0 documenta `-rawin` y su requisito para EdDSA. La documentación de `pkeyutl` de OpenBSD/LibreSSL consultada no muestra `-rawin`, así que no se presupone compatibilidad. En este entorno se probó OpenSSL 3.0.13; OpenSSL 1.1.1 y LibreSSL no se ejecutaron. No se implementó Ed25519 en Python puro: no hay una primitiva Ed25519 en la biblioteca estándar y mantener una implementación criptográfica propia aumentaría el riesgo; se prefiere rechazar un backend no compatible.

Guarda el bundle JSON exportado y un archivo JSON de claves públicas de confianza recibido por un canal separado. El almacén v1 puede ser el mapa heredado `{"key-id":"PEM SPKI"}` o el registro versionado con `version: 1` y, por clave, `publicKeyPem`, `validFrom`, `status` y opcionalmente `validUntil`/`revokedAt`. El bundle nunca establece confianza en sus propias claves.

```sh
python3 verifier/verify_approval_ledger.py \
  --bundle ./bundle.json \
  --trusted-keys ./trusted-ledger-keys.json \
  --checkpoint ./checkpoint.json \
  --checkpoint-trusted-keys ./trusted-checkpoint-keys.json
```

`--checkpoint` y `--checkpoint-trusted-keys` se proporcionan juntos o se omiten juntos. También se puede fijar una hora canónica con `--at 2026-11-17T10:03:00.000Z`. La salida es una sola línea JSON (`valid` y un código fijo); el proceso termina con 0 si acepta y distinto de 0 si rechaza. La cadena valida canonicalización, hashes SHA-256, separación de dominio, firmas Ed25519, secuencias, enlaces, correspondencia de recibos y consumo único. Se rechazan nombres JSON duplicados, decimales, enteros no seguros, codificación base64url no canónica y campos fuera del contrato.

Sin checkpoint, una cadena autocontenida no puede demostrar que se omitieron eventos posteriores: un prefijo íntegro puede verificarse. Un checkpoint firmado limita la afirmación a su workspace y secuencia. Un checkpoint DEMO firmado con una clave creada por quien verifica es **autoanclado**; prueba consistencia con ese checkpoint, no que sea el más reciente. Para detectar checkpoints antiguos se necesita obtener el checkpoint actual por un canal confiable e independiente.

**IMPLEMENTADO:** verificación offline v1, claves heredadas y versionadas, checkpoints independientes y pruebas diferenciales. **PROYECTADO:** distribución y conservación de un checkpoint reciente por un tercero/canal independiente, y aislamiento del firmante respecto del servidor que escribe el ledger. No se afirma cumplimiento de un estándar externo.

Las pruebas generan cada ejecución un bundle de dos eventos y un checkpoint con claves efímeras; las claves privadas viven solo en memoria y se eliminan los archivos temporales al acabar.

## English

`verify_approval_ledger.py` is a standalone verifier for a Guardian Nexus v1 bundle. It uses Python 3, the standard library, and system OpenSSL for Ed25519. It does not import the monorepo, call the API, access a database, or use the network.

At startup it checks that the selected OpenSSL can export an SPKI public key using `pkey -pubin -in <public.pem> -pubout -outform DER` and verify raw Ed25519 using `pkeyutl -verify -pubin -inkey <public.pem> -rawin -in <message> -sigfile <signature>`. The probe checks a public RFC 8032 vector and contains/uses no private key. If unsupported, it emits `unsupported_openssl`, prints a safe instruction to stderr, and exits with status 2. Select a binary with `--openssl PATH` (highest priority) or `LEDGER_OPENSSL`.

**macOS:** the system OpenSSL command may be LibreSSL. Install OpenSSL 3 with Homebrew and use Homebrew's resolved path:

```sh
brew install openssl@3
python3 verifier/verify_approval_ledger.py \
  --openssl "$(brew --prefix openssl@3)/bin/openssl" \
  --bundle ./bundle.json \
  --trusted-keys ./trusted-ledger-keys.json
```

Alternatively, set `LEDGER_OPENSSL="$(brew --prefix openssl@3)/bin/openssl"` for that command. The verifier does not trust a version label alone; the functional probe is decisive. OpenSSL 1.1.1 documents that `pkeyutl` does not support Ed25519; OpenSSL 3.0 documents `-rawin` and its requirement for EdDSA. The OpenBSD/LibreSSL `pkeyutl` documentation reviewed does not show `-rawin`, so compatibility is not assumed. OpenSSL 3.0.13 was tested in this environment; OpenSSL 1.1.1 and LibreSSL were not executed. Pure-Python Ed25519 was not added: the Python standard library has no Ed25519 primitive, and maintaining a custom cryptographic implementation would add risk. The verifier instead fails closed when its backend is not compatible.

Provide the exported bundle and an out-of-band public-key trust file. The v1 trust store accepts either the legacy `{"key-id":"SPKI PEM"}` map or a versioned registry with `version: 1` and per-key `publicKeyPem`, `validFrom`, `status`, and optional `validUntil`/`revokedAt`. Keys embedded in a bundle are never trusted.

```sh
python3 verifier/verify_approval_ledger.py \
  --bundle ./bundle.json \
  --trusted-keys ./trusted-ledger-keys.json \
  --checkpoint ./checkpoint.json \
  --checkpoint-trusted-keys ./trusted-checkpoint-keys.json
```

Pass `--checkpoint` and `--checkpoint-trusted-keys` together, or omit both. `--at 2026-11-17T10:03:00.000Z` selects a canonical verification time. Output is one JSON line (`valid` plus a fixed code); exit status is 0 for acceptance and nonzero for rejection. Verification covers v1 canonicalization, SHA-256, domain separation, Ed25519 signatures, event sequence and links, receipt/event matching, and single consumption. Duplicate JSON names, decimals, unsafe integers, non-canonical base64url, and fields outside the contract are rejected.

Without a checkpoint, a self-contained chain cannot prove that later events were omitted; a valid prefix may verify. A signed checkpoint only attests to its workspace and sequence. A DEMO checkpoint signed by the verifier is **self-anchored**: it proves consistency with that checkpoint, not that the checkpoint is current. Detecting an old checkpoint requires obtaining the latest checkpoint from an independent trusted channel.

**IMPLEMENTED:** offline v1 verification, legacy and versioned keys, independent checkpoints, and differential tests. **PROJECTED:** independent distribution/retention of a recent checkpoint and separation of the signer from the server that writes the ledger. No external-standard compliance is claimed.

Tests generate a two-event bundle and checkpoint per run using ephemeral keys; private keys stay in memory and temporary files are removed afterward.
