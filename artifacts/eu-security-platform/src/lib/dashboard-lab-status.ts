export type DashboardLabStatusPresentation = {
  title: string;
  description: string;
  tone: "positive" | "warning" | "neutral";
};

export function getDashboardLabStatusPresentation(
  status: string | null | undefined,
): DashboardLabStatusPresentation {
  if (status === "ready") {
    return {
      title: "Disponible para pruebas sintéticas",
      description:
        "La API informa que el laboratorio puede aceptar evaluaciones sintéticas; esto no equivale a analizar sistemas reales.",
      tone: "positive",
    };
  }

  if (status === "disabled") {
    return {
      title: "Deshabilitado",
      description:
        "La API informa que el laboratorio no acepta nuevas evaluaciones en este espacio.",
      tone: "warning",
    };
  }

  if (status === "unavailable") {
    return {
      title: "No disponible",
      description:
        "El servicio no confirma la disponibilidad del laboratorio; no se asume que esté listo.",
      tone: "warning",
    };
  }

  if (status === "loading") {
    return {
      title: "Comprobando…",
      description: "Consultando la disponibilidad informada por la API.",
      tone: "neutral",
    };
  }

  if (status === "error") {
    return {
      title: "Estado no verificado",
      description:
        "No se pudo consultar la disponibilidad; la interfaz no supone que el laboratorio esté habilitado.",
      tone: "warning",
    };
  }

  return {
    title: "Estado no verificado",
    description:
      "La API no devolvió un estado reconocido; el laboratorio permanece sin confirmar.",
    tone: "warning",
  };
}
