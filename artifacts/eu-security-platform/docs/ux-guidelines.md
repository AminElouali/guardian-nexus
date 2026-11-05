# Guardian Nexus UI: laboratorio y gobernanza

## Propósito

La interfaz debe ayudar a una persona a seguir el recorrido **propuesta → verificación de procedencia → decisión de política → resultado simulado o bloqueado → evidencia**. La pantalla describe evidencia del laboratorio; no implica que un proveedor, una cuenta empresarial o una acción real esté conectado.

## Sistema visual

- Reutilizar los tokens globales existentes (`--background`, `--foreground`, `--card`, `--primary`, `--sidebar`, `--muted` y `--destructive`) y la tipografía de la aplicación. El laboratorio usa superficies claras, azul marino para jerarquía, verde azulado para controles permitidos y un acento cálido para advertencias.
- Reservar el color y el icono para ayudar a reconocer estados; acompañar siempre el color con una etiqueta legible.
- Usar texto de lectura de 13–14 px en explicaciones y 12 px como mínimo para controles, descripciones y estados clave. Los identificadores técnicos pueden ser menores solo cuando no sean la única explicación.
- Mantener contornos de foco visibles, áreas táctiles de al menos 40 px en los controles principales y movimiento reducido cuando el sistema lo solicite.

## Estados de evidencia

| Estado | Significado visible | Límite que debe conservarse |
| --- | --- | --- |
| `ALLOW` | Permitido dentro del simulador sintético | No significa que una acción empresarial real se haya completado. |
| `DENY` | Bloqueado antes del adaptador | Indicar la razón entendible y que no se ejecutó. |
| `REQUIRE_APPROVAL` | Requiere revisión humana | No presentarlo como aprobado ni como ejecutado. |
| `NO_PROPOSAL` | No se recibió una propuesta evaluable | No contabilizarlo ni describirlo como `DENY`. |

Las vistas de fixtures deterministas, inferencia local Qwen, marcadores Qwen adaptados, `message.tool_calls` nativos y pruebas no ejecutadas deben conservar etiquetas de procedencia separadas. No mostrar prompts, respuestas o argumentos en bruto.

## Navegación

- **Espacio de trabajo:** resumen, activos y equipo.
- **Seguridad y gobernanza:** Seguridad IA, Risk Intelligence y preparación.
- **Conexiones y gestión:** conexiones, planes y hoja de ruta.
- Dentro de Seguridad IA, proporcionar accesos directos a fixtures, evidencia Qwen, aprobaciones e historial/auditoría sin crear rutas o permisos nuevos.

## Interacciones

- En el laboratorio, mostrar primero la elección del perfil y del escenario. La acción primaria debe nombrar con precisión si crea una previsualización determinista o encola un trabajo aislado.
- Mantener estados de carga, error, vacío y resultado, con reintento cuando exista y sin borrar historial al reiniciar la selección.
- Los detalles técnicos y hashes van en paneles desplegables; la explicación ejecutiva queda visible.
- `Policy OFF` se describe únicamente como contrafactual en un clon; nunca como ejecución.

## Alcance

Los ocho perfiles son ejemplos de laboratorio con herramientas y datos sintéticos. La amplitud de perfiles, una captura visual o una muestra pequeña no constituyen una tasa general de eficacia ni una integración con correo, bases de datos, bancos, nubes o sistemas de clientes.

## Checkpoint de UX (2026-11-05)

- Base de trabajo: `a911d0f`.
- El menú conserva las nueve rutas existentes y las agrupa por espacio de trabajo, seguridad/gobernanza y conexiones/gestión. Seguridad IA separa Laboratorio, Aprobaciones y Auditoría en pestañas accesibles; Risk Intelligence y Conexiones siguen en sus rutas actuales.
- El laboratorio conserva sus fixtures, llamadas API, disponibilidad de Qwen, bandeja y resultados. No se cambió el Policy Engine, la autenticación, los permisos ni la persistencia.
- Verificación: suite de integración de Seguridad IA 11/11; typecheck de la aplicación; typecheck de mockup; build Vite; `git diff --check`; revisión visual de la comparación actual/rediseño a 1280 px y 390 px.
- El navegador de captura muestra Clerk en la pantalla de inicio de sesión. No se hizo login ni se validó una sesión autenticada en navegador.
- No se ejecutó Qwen, el worker ni Docker; no hubo conexiones a servicios empresariales y no se publicó ni desplegó.
- El build pasa con el aviso existente de ubicación de sourcemap en `tooltip.tsx` y el aviso de bundle JavaScript mayor de 500 kB.
