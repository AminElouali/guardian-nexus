# Saneamiento del historial para publicación — 2026-11-12

## Resultado

El historial de las ramas locales publicables fue saneado, pero no se publicó.
El repositorio GitHub consultado sigue vacío; el conector de GitHub no quedó
disponible para escritura. La copia de recuperación original se conserva en el
área privada de metadatos Git, fuera del árbol y de las referencias publicables.

## Alcance y preservación

- Estado inicial: `main` en
  `4e5bdcb5658ac9683e60ce22b72842cb08bbd6c8`, árbol limpio.
- Se procesaron las referencias locales `main`, `replit-agent` y
  `subrepl-6j0z1fhu`; no había tags. El historial procesado contiene 286 commits
  únicos: 209 en `main`, 273 en `replit-agent` y 8 en `subrepl-6j0z1fhu`.
- Este informe/checkpoint se añade después como un nuevo commit de evidencia en
  `main`; no altera los árboles saneados anteriores.
- Se conservó el número de commits y la evolución de los árboles fuera de los
  elementos retirados. La rama corta no contenía esos elementos y no necesitó
  reescritura.
- El commit original
  `f1d5b467b861e72a0e5ba8ec91fa69d75ea3588e` tiene como equivalente saneado
  `0ee7637c6f3e001022939f6172374b1d7b0229be`. Coinciden autor, fecha y asunto;
  la comparación de árboles no encontró diferencias fuera de los elementos
  retirados. El hash original no se conserva en las ramas saneadas.
- `git-filter-repo` no estaba disponible; se usó el filtro por índice de
  `git filter-branch`, tras verificar una copia de recuperación. Se eliminaron
  las referencias temporales `refs/original` después de validar la copia.

## Elementos retirados de todos los commits de las ramas publicables

- Dos capturas WebP de interfaces de terceros en `.canvas/assets/`.
- `.agents/agent_assets_metadata.toml`, que contenía un localizador de
  almacenamiento interno y un identificador opaco de versión.
- `.codex/hooks.json`, que exponía rutas absolutas del entorno de desarrollo.

Se inspeccionaron los árboles de los 286 commits. No aparecieron copias de esas
imágenes bajo otros nombres. La búsqueda posterior no encontró sus referencias
textuales, localizadores internos ni rutas locales de hooks en los blobs
alcanzables desde las ramas publicables. Los blobs originales ya no son
alcanzables desde dichas ramas.

## Revisión de secretos y datos

- Escaneo final de 2.291 blobs alcanzables desde las ramas publicables: sin patrones
  reconocibles de claves privadas, certificados, JWT o tokens comunes de
  proveedores.
- Permanecen URIs de base de datos únicamente en dos archivos de prueba; las
  cadenas contienen marcadores de prueba/ejemplo/loopback y no son inferencia
  ni credenciales de producción. No se copiaron sus valores a este informe.
- Los correos detectados usan dominios de ejemplo o internos; no se detectaron
  correos de otros dominios, SSN ni patrones de teléfono en contexto telefónico.
  Los números que pasan el patrón Luhn aparecen en pruebas, esquemas generados
  y checkpoints sin contexto de tarjeta; no se identificaron como tarjetas.
- No hay `.env` real, claves/certificados por nombre, bases locales ni dumps en
  el árbol saneado. `.env.example` se conserva.
- `.gitignore` en `main` conserva exclusiones preventivas para archivos `.env`
  reales, claves/certificados y bases/dumps locales; mantiene la excepción para
  `.env.example` y no excluye los SQL de migración.

## Referencias que no se publicarán

Solo se publicarán referencias explícitas `refs/heads/*` y `refs/tags/*`; no se
usará `git push --mirror`. Los refs internos de Replit y el remote-tracking
`gitsafe-backup/main` se conservan localmente y no forman parte del conjunto
publicable. No hay tags.

## Destino y bloqueo de escritura

- La API pública de GitHub confirmó `AminElouali/guardian-nexus`, visibilidad
  pública, rama predeterminada `main`, tamaño cero, cero ramas y cero tags; la
  consulta de commits respondió que el repositorio está vacío.
- No hay remote GitHub configurado en este checkout. El conector GitHub siguió
  en estado `connect` después del intento de adjuntarlo; no se accedió a
  credenciales ni se hizo push.
- Por tanto, no se sobrescribió contenido ajeno y no se afirma publicación.
  El siguiente bloqueo externo es obtener una conexión GitHub lista para
  escritura. Después se debe volver a comprobar el destino y enviar solo las
  referencias explícitas saneadas.

## Validaciones y límites

- Comparación del árbol original y su equivalente saneado: sin diferencias fuera
  de los elementos retirados.
- Verificación de rutas, blobs y marcadores en los 286 commits alcanzables desde
  ramas locales; tags ausentes.
- GitHub: comprobación pública de metadatos y de ramas/tags/commits; no se
  escribió en el destino.
- No se ejecutaron Qwen, workers, servicios, Docker, sockets, PostgreSQL,
  migraciones ni workflow de CI. La preparación no valida RLS ni persistencia.
- `hostBoundaryReady=false`, `integratedAssessmentReady=false` y
  `workerAdmission=disabled` permanecen cerrados.
