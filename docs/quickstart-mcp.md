# Conecta tu agente a Guardian Nexus en 5 minutos (MCP)

Guardian Nexus se sitúa entre tu agente de IA y las acciones delicadas. El agente propone una acción y Guardian Nexus decide qué hacer con ella:

- **ALLOW**: la acción se ejecuta.
- **DENY**: la acción se bloquea.
- **REQUIRE_APPROVAL**: la acción queda en espera hasta que una persona de tu equipo la apruebe.

Cada aprobación genera un **recibo firmado** (Ed25519) y queda en un registro de auditoría en el que solo se puede añadir.

> **Estado actual (MVP).** Las acciones disponibles por MCP son **sintéticas**: simulan una respuesta de soporte y un correo externo, y no envían nada real. Sirven para probar la integración y las reglas de punta a punta. Los conectores con proveedores reales todavía no están disponibles.

---

## Lo que necesitas

1. Una cuenta en Guardian Nexus y un **workspace** en el que seas *owner* o *admin*.
2. Un cliente compatible con **MCP por HTTP** (*Streamable HTTP*, protocolo `2025-03-26`), por ejemplo un agente propio o un framework de agentes con soporte MCP.

---

## Paso 1 — Registra tu agente

En el panel de Guardian Nexus, abre **Agentes → Registrar agente** y dale un nombre. Por ejemplo: `soporte-bot`.

Guardian Nexus te mostrará **una sola vez** la credencial del agente:

```
gnx_agent_v1_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

Guárdala en el gestor de secretos de tu agente. Guardian Nexus solo conserva su huella SHA-256, así que si la pierdes no se puede recuperar: rota la credencial y se generará una nueva.

Cada agente actúa en nombre de la persona que lo registró, y siempre dentro de un único workspace.

---

## Paso 2 — Configura el servidor MCP

- **URL:** `https://<tu-dominio-guardian>/api/workspaces/<WORKSPACE_ID>/mcp`
- **Cabecera:** `Authorization: Bearer gnx_agent_v1_...`

Ejemplo de configuración genérica de un cliente MCP:

```json
{
  "mcpServers": {
    "guardian-nexus": {
      "type": "http",
      "url": "https://<tu-dominio-guardian>/api/workspaces/<WORKSPACE_ID>/mcp",
      "headers": {
        "Authorization": "Bearer ${GUARDIAN_AGENT_TOKEN}"
      }
    }
  }
}
```

Comprueba la conexión con `tools/list`. Deberías ver estas herramientas:

| Herramienta | Qué hace |
|---|---|
| `reply_to_support` | Propone una respuesta sintética a un caso de soporte, con compensación opcional en céntimos (`compensation_cents`). |
| `send_external_email` | Propone un correo externo de prueba. |
| `guardian_approval_status` | Consulta el estado de una solicitud creada por este agente. |

---

## Paso 3 — Entiende las tres respuestas

**1. Permitida.** La acción se ejecuta y la respuesta incluye `status: "executed"`.

**2. Requiere aprobación.** La acción **no** se ejecuta. La respuesta incluye:

```json
{ "approvalId": "…", "status": "pending", "retryWithSameArguments": true }
```

Tu agente debe:
1. Esperar, consultando de vez en cuando `guardian_approval_status` con ese `approval_id`.
2. Cuando el estado sea `approved`, **repetir la misma llamada con exactamente los mismos argumentos**. Guardian Nexus comprueba el recibo firmado y ejecuta la acción **una sola vez**.

**3. Bloqueada.** La respuesta trae `isError: true` y un `reasonCode` que explica el motivo, por ejemplo `approval_rejected`, `approval_expired` o un argumento no válido.

### Reintentos seguros

Si tu agente repite una llamada que ya se ejecutó (por ejemplo, porque se cortó la red), Guardian Nexus **no la ejecuta otra vez**: devuelve el mismo resultado con `replayed: true`. Puedes reintentar sin miedo a duplicar acciones.

En cambio, se **rechazan**:
- un recibo usado por **otro agente** o desde **otro workspace**;
- un recibo usado con **argumentos distintos** de los aprobados (por ejemplo, otro importe);
- una solicitud **caducada**.

---

## Paso 4 — Aprueba desde el panel

Las solicitudes pendientes aparecen en la **bandeja de aprobaciones** del workspace. Tiene que aprobarlas una persona **distinta** de la que pidió la acción: nadie puede aprobar sus propias peticiones.

Al aprobar se emite el recibo firmado y queda en el registro. Puedes exportar el registro y verificar las firmas y la cadena de hashes con los verificadores incluidos (TypeScript y Python, ver `docs/approval-ledger-v1.md`).

---

## Paso 5 — Ajusta las reglas

En **Reglas** elige una plantilla (*Prudente*, *Equilibrada* o *Solo lectura*) y define tus límites, por ejemplo el importe máximo de compensación. Guardian Nexus versiona cada cambio de reglas, y cada decisión queda vinculada a la versión de la regla que la tomó.

---

## Errores frecuentes

| Respuesta | Causa probable | Qué hacer |
|---|---|---|
| HTTP 401 `Agent authentication failed` | Credencial incorrecta, revocada o de otro workspace. | Revisa la cabecera `Authorization` y el `WORKSPACE_ID`, o rota la credencial. |
| HTTP 429 | Demasiados intentos de autenticación seguidos. | Espera los segundos que indica `Retry-After`. |
| `-32602 Argumentos no válidos` | Los argumentos no cumplen el esquema de la herramienta. | Compara con el `inputSchema` que devuelve `tools/list`. |
| `-32004 Solicitud no disponible` | El `approval_id` no existe o no pertenece a este agente. | Usa el `approvalId` que recibiste en la respuesta original. |

---

## Seguridad, en resumen

- Cada workspace está aislado a nivel de base de datos (PostgreSQL RLS forzado).
- Las credenciales de los agentes se guardan solo como huella SHA-256 y se pueden rotar o revocar al instante.
- Los recibos van firmados con Ed25519 y son de un solo uso.
- El registro de auditoría solo admite añadir entradas: la aplicación no puede editarlas ni borrarlas.
- Cada versión pasa una batería automática de ataques (autorización, credenciales, reutilización y manipulación de recibos, inyección) antes de publicarse.
