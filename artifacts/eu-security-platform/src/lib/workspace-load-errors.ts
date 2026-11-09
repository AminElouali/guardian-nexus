export type WorkspaceLoadErrorKind =
  | "session"
  | "forbidden"
  | "not-found"
  | "unavailable"
  | "server"
  | "invalid-response"
  | "request"
  | "network"
  | "unexpected";

export type WorkspaceLoadErrorCopy = {
  kind: WorkspaceLoadErrorKind;
  title: string;
  detail: string;
};

function asRecord(error: unknown): Record<string, unknown> | null {
  return typeof error === "object" && error !== null
    ? (error as Record<string, unknown>)
    : null;
}

export function getWorkspaceLoadErrorCopy(
  error: unknown,
): WorkspaceLoadErrorCopy {
  const record = asRecord(error);
  const name = typeof record?.name === "string" ? record.name : "";
  const status =
    typeof record?.status === "number" ? record.status : undefined;

  if (
    name === "ResponseParseError" ||
    name === "ZodError" ||
    name === "SyntaxError"
  ) {
    return {
      kind: "invalid-response",
      title: "La respuesta no tiene el formato esperado",
      detail:
        "No se pudieron interpretar los datos recibidos. Reintenta; si vuelve a ocurrir, contacta a la persona administradora.",
    };
  }

  if (status === 401) {
    return {
      kind: "session",
      title: "No se pudo validar la sesión",
      detail:
        "El navegador muestra una sesión iniciada, pero el servicio no ha podido confirmarla. Reintenta; si persiste, cierra sesión y vuelve a entrar.",
    };
  }

  if (status === 403) {
    return {
      kind: "forbidden",
      title: "Tu cuenta no tiene acceso a este espacio",
      detail:
        "Pide a la persona administradora que compruebe tu membresía y el acceso asignado.",
    };
  }

  if (status === 404) {
    return {
      kind: "not-found",
      title: "El espacio o recurso ya no está disponible",
      detail:
        "Vuelve al resumen y comprueba que estás usando un espacio asociado a tu cuenta.",
    };
  }

  if (status === 502 || status === 503 || status === 504) {
    return {
      kind: "unavailable",
      title: "La API del espacio no está disponible",
      detail:
        "No se pudo recuperar la información. Reintenta cuando el servicio vuelva a estar disponible; no se ha confirmado ninguna operación.",
    };
  }

  if (status !== undefined && status >= 500) {
    return {
      kind: "server",
      title: "El servicio no pudo completar la consulta",
      detail:
        "Reintenta. Si el problema continúa, contacta a la persona administradora; no mostramos detalles técnicos en esta pantalla.",
    };
  }

  if (status !== undefined && status >= 400) {
    return {
      kind: "request",
      title: "No se pudieron recuperar estos datos",
      detail:
        "Comprueba que el espacio sigue disponible para tu cuenta y vuelve a intentarlo.",
    };
  }

  const message =
    typeof record?.message === "string" ? record.message.toLowerCase() : "";
  if (
    name === "TypeError" ||
    /failed to fetch|network error|load failed/.test(message)
  ) {
    return {
      kind: "network",
      title: "No se pudo establecer la conexión",
      detail:
        "Comprueba tu conexión e inténtalo de nuevo. No se ha confirmado ninguna operación.",
    };
  }

  return {
    kind: "unexpected",
    title: "No se ha podido cargar esta vista",
    detail:
      "Ha ocurrido un problema inesperado al recuperar los datos. Reintenta; no mostramos información interna del servicio.",
  };
}
