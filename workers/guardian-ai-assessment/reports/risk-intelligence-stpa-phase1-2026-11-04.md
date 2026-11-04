# Guardian Nexus Risk Intelligence / STPA — fase 1

**Fecha:** 2026-11-04  
**Catálogo:** `0.1.0` (`guardian-risk-intelligence-catalog/1.0.0`)  
**Ámbito:** desarrollo; catálogo estático y vista autenticada de solo lectura.

## Resultado

Se añadió una biblioteca trazable de riesgos basada en referencias públicas y
un primer modelado STPA para correo y bases de datos. El catálogo contiene
pérdidas, peligros, acciones de control inseguras, escenarios causales,
restricciones verificables y ocho fichas verticales.

- Correo y bases de datos: modelado inicial y cuatro especificaciones de
  pruebas sintéticas por vertical; estado `prepared_not_executed`.
- Finanzas, soporte, programación, navegador, infraestructura y multiagente:
  estado `design_only`; no se presentan como modelados o probados en detalle.
- Se verificaron los IDs MITRE ATLAS `AML.T0051`, `AML.T0051.001` y
  `AML.M0020` en páginas oficiales. Los IDs `GNRI-*` son propios del catálogo.
- La página `/risk-intelligence` está dentro del `AuthGuard` y del marco de
  workspace actual. Es de solo lectura: no contiene formularios, botones de
  ejecución, controles de política ni acceso al API.
- No se cambió el Policy Engine, el runner Qwen, Docker, cola, API o esquema
  PostgreSQL. No se ejecutó Qwen ni Docker; no se conectaron sistemas
  externos; no se importaron datasets ni probes.

## Evidencia de fuentes y límites

Fuentes revisadas el 2026-11-04: MITRE ATLAS (la licencia Apache-2.0 se
atribuye únicamente a `mitre-atlas/atlas-data`); OWASP GenAI Agentic Security
(sin licencia explícita verificada para la pieza referida, enlace solamente);
NIST AI RMF 1.0 junto con la política oficial de reutilización de NIST; MIT
PSASS STPA Handbook (se informa disponibilidad gratuita según el listado
oficial, pero la descarga respondió con una página de mantenimiento y no se
verificó licencia); enlaces a garak y Hugging Face sin copiar o ejecutar
material. El detalle de cada revisión está en `catalog.v1.ts`.

No se afirma autorización legal, cumplimiento normativo, cobertura completa,
eficacia de controles ni seguridad de ningún agente. Las pruebas listadas son
objetivos de prueba, no detecciones ni decisiones observadas.

## Pruebas ejecutadas

- `pnpm --filter @workspace/eu-security-platform exec tsx --test src/components/RiskIntelligencePage.test.tsx`
  — 3/3.
- `pnpm --filter @workspace/eu-security-platform run typecheck` — pasó.
- `PORT=18753 BASE_PATH=/ pnpm --filter @workspace/eu-security-platform run build`
  — pasó. Vite registró un aviso de sourcemap preexistente en
  `src/components/ui/tooltip.tsx` y aviso de chunk JavaScript >500 kB.
- Regresión de componentes existente más catálogo:
  `pnpm --filter @workspace/eu-security-platform exec tsx --test
  src/components/RiskIntelligencePage.test.tsx
  src/components/AiEvaluationPage.integration.test.tsx` — 11/11.
- Un intento inicial de build sin variables falló antes de compilar porque el
  config requiere `PORT` y `BASE_PATH`; se repitió con los valores del
  artefacto, sin editar su configuración.

La captura de `/risk-intelligence` sin sesión mostró el inicio de sesión de
Clerk, como exige la ruta. No se verificó una sesión real autenticada en
navegador. Los tests cubren renderizado SSR del componente,
procedencia/referencias, estados honestos y ausencia de controles de mutación,
pero no sustituyen una prueba visual autenticada.
