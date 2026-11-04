# Guardian Nexus Risk Intelligence — fase 1

**Versión del catálogo:** `0.1.0`  
**Contrato:** `guardian-risk-intelligence-catalog/1.0.0`  
**Fecha de revisión registrada:** `2026-11-04`

La fuente de datos tipada de esta biblioteca es
`artifacts/eu-security-platform/src/risk-intelligence/catalog.v1.ts`; la vista
autenticada de solo lectura está en `/risk-intelligence`. El catálogo no se
importa en el Policy Engine, no genera puntuaciones y no cambia decisiones.
El Policy Engine existente sigue siendo el único decisor determinista.

## Estado de alcance

- **Correo y bases de datos:** pérdidas, peligros, acciones de control
  inseguras, escenarios causales, restricciones y especificaciones sintéticas
  preparadas. Las especificaciones figuran como `prepared_not_executed`; esta
  fase no las ejecutó contra el worker o el Policy Engine.
- **Finanzas, soporte, programación, navegador, infraestructura y
  multiagente:** fichas de alcance y riesgos iniciales `design_only`; el
  modelado STPA detallado y los casos ejecutables siguen pendientes.
- **Runtime:** no verificado por este catálogo. La existencia de una
  restricción escrita no demuestra que esté aplicada ni que una prueba real
  haya pasado.
- **Datos:** no se importaron probes de garak ni datasets/payloads de
  Hugging Face. Los textos de entrada del catálogo son descripciones sintéticas
  originales, no corpus de benchmark.

## Referencias y licencias

La ficha estructurada `sources` en `catalog.v1.ts` contiene URL, versión o
alcance observado, procedencia, revisión de licencia y uso concreto.

1. **MITRE ATLAS.** Se verificaron en páginas oficiales `AML.T0051` (LLM
   Prompt Injection), `AML.T0051.001` (Indirect) y `AML.M0020` (Generative AI
   Guardrails). El repositorio `mitre-atlas/atlas-data` declara Apache-2.0;
   esta licencia se atribuye solo a ese repositorio, no a todo contenido del
   sitio. Se citan identificadores y enlaces, sin copiar descripciones.
2. **OWASP GenAI Security Project, Agentic AI Security Initiative y Top 10
   Agentic Applications 2026.** Se verificaron las páginas oficiales. No se
   verificó una licencia explícita para el contenido concreto referido; se
   enlaza y se usa como orientación conceptual, sin copiar texto, gráficos o
   identificadores de riesgo.
3. **NIST AI RMF 1.0, NIST AI 100-1 (enero de 2023).** La página oficial de
   derechos de NIST describe la información de sus páginas como información
   pública distribuible salvo material marcado como protegido y solicita
   atribución apropiada. Se usa como política de reutilización de NIST, no
   como licencia SPDX ni asesoría legal. Se nombran Govern, Map, Measure y
   Manage; no se declara conformidad.
4. **MIT PSASS, STPA Handbook MIT-STAMP-001.** El resultado de búsqueda de la
   página oficial indica disponibilidad gratuita, pero la descarga directa
   devolvió una página de mantenimiento durante esta revisión. No se verificó
   licencia explícita ni se descargó el manual. Se usa la estructura analítica
   STPA con redacción propia y sin reproducir texto o figuras.
5. **garak y Hugging Face Datasets.** Referencias metodológicas únicamente.
   No se ejecutaron probes, ni se eligió, descargó o reutilizó un dataset. Las
   licencias de probes individuales y de cualquier dataset futuro deben
   revisarse por revisión exacta antes de incorporarlos.

## Cómo revisar y ampliar

- Mantener `GNRI-*` como identificadores locales. No son IDs de MITRE, OWASP,
  NIST ni STPA.
- Para añadir una referencia externa, comprobar la página oficial y registrar
  URL, versión/revisión, fecha, procedencia, licencia específica y alcance de
  uso. Si no hay licencia verificada, enlazar sin copiar contenido.
- Mantener escenarios ficticios y especificaciones separadas de resultados
  ejecutados. Un caso pasa a `verified` solo tras una ejecución reproducible
  con evidencia, versión y resultado registrado.
- Antes de vincular una restricción a comportamiento, agregar una prueba
  negativa que demuestre que DENY y `require_approval` no despachan, y una
  positiva mínima bajo Policy ON. Policy OFF permanece contrafactual y nunca
  invoca adaptadores.
- No convertir etiquetas, referencias o análisis STPA en puntuaciones de
  autorización. Cambios de política requieren su propio análisis y pruebas.
