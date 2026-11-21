import React, { useEffect, useState, type FormEvent } from "react";
import { useQueryClient } from "@tanstack/react-query";
import {
  getGetWorkspaceGmailConnectionQueryKey,
  useBeginGoogleGmailAuthorization,
  useDisconnectWorkspaceGmail,
  useGetWorkspaceGmailConnection,
  useUpdateWorkspaceGmailRecipients,
  type Workspace,
  type WorkspaceGmailConnectionStatus,
} from "@workspace/api-client-react";
import { Check, CircleAlert, LoaderCircle, Mail, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";

export function GmailConnectionCardView({
  status,
  canManage,
  busy = false,
  allowlistValue = "",
  feedback = "",
  error = "",
  onConnect = () => undefined,
  onDisconnect = () => undefined,
  onSaveRecipients = () => undefined,
  onAllowlistChange = () => undefined,
}: {
  status: WorkspaceGmailConnectionStatus | null;
  canManage: boolean;
  busy?: boolean;
  allowlistValue?: string;
  feedback?: string;
  error?: string;
  onConnect?: () => void;
  onDisconnect?: () => void;
  onSaveRecipients?: (event: FormEvent<HTMLFormElement>) => void;
  onAllowlistChange?: (value: string) => void;
}) {
  return (
    <section className="integration-card connector-card gmail-connector-card" data-testid="gmail-connection-card">
      <div className="integration-card-top">
        <div className="integration-logo gmail-integration-logo"><Mail size={20} /></div>
        <span className="integration-index">03 / CORREO</span>
      </div>
      <div className="integration-title-row">
        <div>
          <h2>Gmail (modo prueba)</h2>
          <p>Gmail API · envío de prueba</p>
        </div>
        {status?.connected && <span className="connector-status connector-status-active">Conectado</span>}
      </div>
      <p className="connector-card-copy">
        Envía solo el mensaje fijo de prueba, después de la decisión de Guardian y la aprobación humana.
        No se lee el buzón ni se guarda el cuerpo en Guardian Nexus.
      </p>

      <div className="connector-disclaimer gmail-connector-scope" role="note">
        <ShieldCheck size={17} />
        <div>
          <b>Permisos solicitados</b>
          <p><code>gmail.send</code>, <code>openid</code> y <code>email</code>. No se solicita acceso de lectura al buzón.</p>
        </div>
      </div>

      {(feedback || error) && (
        <div className={`connector-feedback ${error ? "connector-feedback-error" : ""}`} role={error ? "alert" : "status"}>
          {error ? <CircleAlert size={16} /> : <Check size={16} />}
          {error || feedback}
        </div>
      )}

      {!canManage ? (
        <p className="connector-role-note">Solo propietarios y administradores pueden ver o gestionar la conexión de Gmail.</p>
      ) : !status ? (
        <div className="connector-prerequisite">
          <span>Estado</span>
          <b>No disponible</b>
        </div>
      ) : !status.configured ? (
        <div className="connector-prerequisite" data-testid="gmail-not-configured">
          <span>Estado</span>
          <b>No configurado</b>
          <p>Falta configurar la aplicación OAuth de Google o la caja fuerte del servidor.</p>
        </div>
      ) : !status.connected ? (
        <div className="connector-gmail-actions">
          <span className="connector-status">Sin cuenta conectada</span>
          <Button type="button" onClick={onConnect} disabled={busy} data-testid="button-gmail-connect">
            {busy ? "Abriendo Google…" : "Conectar Gmail"}
          </Button>
        </div>
      ) : (
        <>
          <div className="connector-prerequisite">
            <span>Cuenta conectada</span>
            <b className="gmail-account-email">{status.accountEmail ?? "No disponible"}</b>
          </div>
          <form className="connector-form gmail-allowlist-form" onSubmit={onSaveRecipients}>
            <label htmlFor="gmail-allowed-recipients">Correos o dominios permitidos</label>
            <textarea
              id="gmail-allowed-recipients"
              value={allowlistValue}
              onChange={(event) => onAllowlistChange(event.target.value)}
              rows={3}
              disabled={busy}
              aria-describedby="gmail-allowlist-help"
              data-testid="input-gmail-allowlist"
            />
            <small id="gmail-allowlist-help">Al conectar, solo se permite por defecto la cuenta conectada. Usa una dirección exacta o un dominio como @empresa.test.</small>
            <Button type="submit" variant="outline" disabled={busy} data-testid="button-gmail-save-recipients">
              Guardar lista permitida
            </Button>
            <Button type="button" variant="outline" disabled={busy} onClick={onDisconnect} data-testid="button-gmail-disconnect">
              Desconectar Gmail
            </Button>
          </form>
        </>
      )}
    </section>
  );
}

export default function GmailConnectionCard({ workspace }: { workspace: Workspace }) {
  const queryClient = useQueryClient();
  const canManage = workspace.role === "owner" || workspace.role === "admin";
  const query = useGetWorkspaceGmailConnection(workspace.id, {
    query: { enabled: canManage },
  });
  const begin = useBeginGoogleGmailAuthorization();
  const disconnect = useDisconnectWorkspaceGmail();
  const updateRecipients = useUpdateWorkspaceGmailRecipients();
  const [allowlistValue, setAllowlistValue] = useState("");
  const [allowlistInitializedFor, setAllowlistInitializedFor] = useState("");
  const [feedback, setFeedback] = useState("");
  const [error, setError] = useState("");

  const status = query.data ?? null;
  useEffect(() => {
    if (status?.connected && allowlistInitializedFor !== workspace.id) {
      setAllowlistValue(status.allowedRecipients.join("\n"));
      setAllowlistInitializedFor(workspace.id);
    } else if (!status?.connected && allowlistInitializedFor === workspace.id) {
      setAllowlistValue("");
      setAllowlistInitializedFor("");
    }
  }, [allowlistInitializedFor, status, workspace.id]);
  const invalidate = async () => {
    await queryClient.invalidateQueries({
      queryKey: getGetWorkspaceGmailConnectionQueryKey(workspace.id),
    });
  };
  const busy = begin.isPending || disconnect.isPending || updateRecipients.isPending;

  async function connect() {
    setError("");
    setFeedback("");
    try {
      const result = await begin.mutateAsync({ workspaceId: workspace.id });
      window.location.assign(result.authorizationUrl);
    } catch {
      setError("No se pudo iniciar la conexión. Comprueba la configuración de Google y vuelve a intentarlo.");
    }
  }

  async function disconnectGmail() {
    if (!window.confirm("¿Desconectar Gmail de este espacio de trabajo?")) return;
    setError("");
    setFeedback("");
    try {
      const result = await disconnect.mutateAsync({ workspaceId: workspace.id });
      setFeedback(result.providerRevoked
        ? "Gmail se desconectó y Google confirmó la revocación."
        : "Gmail se desconectó en Guardian. Si Google no confirmó la revocación, revoca el acceso desde tu cuenta de Google.");
      await invalidate();
      setAllowlistValue("");
      setAllowlistInitializedFor("");
    } catch {
      setError("No se pudo desconectar Gmail.");
    }
  }

  async function saveRecipients(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setFeedback("");
    const allowedRecipients = allowlistValue
      .split(/[\n,]/)
      .map((value) => value.trim())
      .filter(Boolean);
    try {
      const result = await updateRecipients.mutateAsync({
        workspaceId: workspace.id,
        data: { allowedRecipients },
      });
      setAllowlistValue(result.allowedRecipients.join("\n"));
      setFeedback("La lista permitida de Gmail se actualizó.");
      await invalidate();
    } catch {
      setError("No se pudo guardar la lista. Usa correos o dominios exactos, sin comodines.");
    }
  }

  if (canManage && query.isLoading) {
    return (
      <section className="connector-card" data-testid="gmail-connection-loading" role="status">
        <LoaderCircle className="spin" size={18} /> Cargando el estado de Gmail
      </section>
    );
  }

  if (canManage && query.isError) {
    return (
      <section className="connector-card" data-testid="gmail-connection-error" role="alert">
        No se pudo cargar Gmail. Comprueba tu conexión y vuelve a intentarlo.
        <Button variant="outline" onClick={() => query.refetch()}>Reintentar</Button>
      </section>
    );
  }

  return (
    <GmailConnectionCardView
      status={status}
      canManage={canManage}
      busy={busy}
      allowlistValue={allowlistValue}
      feedback={feedback}
      error={error}
      onConnect={() => void connect()}
      onDisconnect={() => void disconnectGmail()}
      onSaveRecipients={(event) => void saveRecipients(event)}
      onAllowlistChange={setAllowlistValue}
    />
  );
}
