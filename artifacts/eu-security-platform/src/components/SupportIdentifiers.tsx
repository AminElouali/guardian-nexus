import * as React from "react";
import { useState } from "react";

type SupportIdentifiersProps = {
  userId?: string | null;
  workspaceId?: string | null;
};

export function SupportIdentifiers({
  userId,
  workspaceId,
}: SupportIdentifiersProps) {
  const [copyMessage, setCopyMessage] = useState("");
  const identifiers = [
    userId
      ? {
          key: "user",
          label: "Identificador de usuario",
          value: userId,
          buttonLabel: "Copiar identificador de usuario",
        }
      : null,
    workspaceId
      ? {
          key: "workspace",
          label: "Identificador del espacio",
          value: workspaceId,
          buttonLabel: "Copiar identificador del espacio",
        }
      : null,
  ].filter((identifier) => identifier !== null);

  if (identifiers.length === 0) return null;

  async function copyIdentifier(value: string, label: string): Promise<void> {
    if (typeof navigator === "undefined" || !navigator.clipboard?.writeText) {
      setCopyMessage("El portapapeles no está disponible en este navegador.");
      return;
    }
    try {
      await navigator.clipboard.writeText(value);
      setCopyMessage(`${label} copiado.`);
    } catch {
      setCopyMessage("No se pudo copiar el identificador.");
    }
  }

  return (
    <section
      className="panel support-identifiers"
      aria-label="Identificadores técnicos"
      data-testid="support-identifiers"
    >
      <div className="panel-heading">
        <div>
          <div className="panel-kicker">SOPORTE Y DEMOSTRACIONES</div>
          <h2>Identificadores técnicos</h2>
        </div>
      </div>
      <p className="support-identifiers-note">
        Son identificadores técnicos para soporte y demostraciones; no son
        credenciales ni añaden personas al espacio.
      </p>
      <div className="support-identifiers-list">
        {identifiers.map((identifier) => (
          <div className="support-identifier-row" key={identifier.key}>
            <div>
              <span>{identifier.label}</span>
              <code data-testid={`support-id-${identifier.key}`}>
                {identifier.value}
              </code>
            </div>
            <button
              type="button"
              className="button button-secondary"
              aria-label={identifier.buttonLabel}
              onClick={() =>
                void copyIdentifier(identifier.value, identifier.label)
              }
              data-testid={`button-copy-support-id-${identifier.key}`}
            >
              Copiar
            </button>
          </div>
        ))}
      </div>
      {copyMessage && (
        <p role="status" className="support-identifiers-status">
          {copyMessage}
        </p>
      )}
    </section>
  );
}
