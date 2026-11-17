# Verificador público del ledger / Public ledger verifier

## Español

`verify_approval_ledger.py` es un verificador independiente de un bundle v1 de Guardian Nexus. Solo usa Python 3, su biblioteca estándar y OpenSSL del sistema para Ed25519; no importa el monorepo, no necesita la API, una base de datos ni conexión de red.

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
