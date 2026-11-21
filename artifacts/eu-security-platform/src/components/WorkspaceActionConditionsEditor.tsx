import React, { useState } from "react";
import type {
  WorkspaceActionRule,
  WorkspaceActionRuleState,
  WorkspaceRuleCondition,
} from "@workspace/api-client-react";

type RuleDecision = WorkspaceActionRule["decision"];
type ConditionDraft = {
  field: string;
  op: string;
  value: string;
  windowSeconds: string;
};

const volumeWindows = [
  { value: "60", label: "por minuto" },
  { value: "300", label: "cada 5 minutos" },
  { value: "900", label: "cada 15 minutos" },
  { value: "3600", label: "por hora" },
  { value: "86400", label: "por día" },
];
type VolumeWindowSeconds = 60 | 300 | 900 | 3600 | 86400;

function parseWindowSeconds(value: string): VolumeWindowSeconds | null {
  switch (value) {
    case "60": return 60;
    case "300": return 300;
    case "900": return 900;
    case "3600": return 3600;
    case "86400": return 86400;
    default: return null;
  }
}

const contextFields = [
  { name: "context.data_sensitivity", label: "Sensibilidad del dato", type: "context" },
  { name: "context.environment", label: "Entorno", type: "context" },
  { name: "context.action_count", label: "Volumen de acciones", type: "context" },
];

function defaultCondition(field: string): ConditionDraft {
  if (field === "context.data_sensitivity") {
    return { field, op: "eq", value: "sensitive", windowSeconds: "3600" };
  }
  if (field === "context.environment") {
    return { field, op: "eq", value: "test", windowSeconds: "3600" };
  }
  if (field === "context.action_count") {
    return { field, op: "gt", value: "10", windowSeconds: "3600" };
  }
  if (["to", "recipient_email", "forward_to"].includes(field)) {
    return { field, op: "domain_in", value: "example.test", windowSeconds: "3600" };
  }
  return { field, op: "eq", value: "", windowSeconds: "3600" };
}

function normalizeCondition(draft: ConditionDraft): WorkspaceRuleCondition | null {
  if (draft.field === "context.data_sensitivity") {
    if (!["normal", "sensitive"].includes(draft.value)) return null;
    return { field: draft.field, op: "eq", value: draft.value };
  }
  if (draft.field === "context.environment") {
    if (!["test", "production"].includes(draft.value)) return null;
    return { field: draft.field, op: "eq", value: draft.value };
  }
  if (draft.field === "context.action_count") {
    const count = Number(draft.value);
    const windowSeconds = parseWindowSeconds(draft.windowSeconds);
    if (
      !Number.isSafeInteger(count) ||
      count < 0 ||
      windowSeconds === null
    ) return null;
    if (draft.op === "gt") {
      return { field: draft.field, op: "gt", value: count, windowSeconds };
    }
    if (draft.op === "lte") {
      return { field: draft.field, op: "lte", value: count, windowSeconds };
    }
    return null;
  }
  if (["to", "recipient_email", "forward_to"].includes(draft.field)) {
    const domains = draft.value.split(",").map((domain) => domain.trim().toLowerCase()).filter(Boolean);
    if (!domains.length || domains.length > 20) return null;
    return { field: draft.field, op: "domain_in", value: domains };
  }
  if (draft.op === "gt" || draft.op === "lte") {
    const value = Number(draft.value);
    if (!Number.isSafeInteger(value) || value < 0) return null;
    return { field: draft.field, op: draft.op, value };
  }
  if (draft.value === "true" || draft.value === "false") {
    return { field: draft.field, op: "eq", value: draft.value === "true" };
  }
  if (!draft.value.trim()) return null;
  return { field: draft.field, op: "eq", value: draft.value };
}

export function buildConditionalActionRule(
  decision: RuleDecision,
  conditions: ConditionDraft[],
): WorkspaceActionRule | null {
  const normalized = conditions.map(normalizeCondition);
  if (!normalized.length || normalized.some((item) => item === null)) return null;
  const validConditions: WorkspaceRuleCondition[] = [];
  for (const condition of normalized) {
    if (!condition) return null;
    validConditions.push(condition);
  }
  return {
    id: "workspace-conditional-policy",
    decision,
    when: { all: validConditions },
  };
}

export function buildConditionalActionRules(
  decision: RuleDecision,
  fallbackDecision: RuleDecision,
  conditions: ConditionDraft[],
): WorkspaceActionRule[] | null {
  const conditional = buildConditionalActionRule(decision, conditions);
  if (!conditional) return null;
  return [
    conditional,
    {
      id: "workspace-conditional-fallback",
      decision: fallbackDecision,
      when: {},
    },
  ];
}

export function WorkspaceActionConditionsEditor({
  actions,
  canManage,
  busy,
  onSave,
}: {
  actions: WorkspaceActionRuleState[];
  canManage: boolean;
  busy: boolean;
  onSave: (actionType: string, rules: WorkspaceActionRule[]) => Promise<void>;
}) {
  const [actionType, setActionType] = useState(actions[0]?.actionType ?? "");
  const selected = actions.find((action) => action.actionType === actionType) ?? actions[0];
  const [decision, setDecision] = useState<RuleDecision>("require_approval");
  const [fallbackDecision, setFallbackDecision] = useState<RuleDecision>("deny");
  const [conditions, setConditions] = useState<ConditionDraft[]>([
    defaultCondition("context.data_sensitivity"),
  ]);
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");

  const changeAction = (nextActionType: string) => {
    setActionType(nextActionType);
    setConditions([defaultCondition("context.data_sensitivity")]);
    setStatus("");
    setError("");
  };

  const updateCondition = (index: number, patch: Partial<ConditionDraft>) => {
    setConditions((current) => current.map((condition, conditionIndex) =>
      conditionIndex === index ? { ...condition, ...patch } : condition,
    ));
  };

  const save = async () => {
    if (!selected || !canManage || busy) return;
    const rules = buildConditionalActionRules(decision, fallbackDecision, conditions);
    if (!rules) {
      setError("Revisa las condiciones: introduce valores válidos y dominios exactos.");
      setStatus("");
      return;
    }
    setError("");
    setStatus("");
    try {
      await onSave(selected.actionType, rules);
      setStatus("Borrador guardado como una nueva versión. La versión activa no cambia; las versiones anteriores siguen en el historial.");
    } catch {
      setError("No se pudo guardar el borrador. La regla activa no ha cambiado.");
    }
  };

  if (!selected) return null;

  return <section className="wre-rules wre-condition-editor" aria-labelledby="conditions-heading" data-testid="workspace-condition-editor">
    <div className="wre-section-heading">
      <div><p className="wre-index">CONDICIONES POR WORKSPACE</p><h2 id="conditions-heading">Ajusta una acción</h2></div>
      <p>Las condiciones se guardan en una nueva versión. Si un dato de contexto no se puede comprobar, la acción pide aprobación o se bloquea.</p>
    </div>
    <div className="wre-condition-card">
      <label htmlFor="condition-action">Acción
        <select
          id="condition-action"
          value={selected.actionType}
          onChange={(event) => changeAction(event.target.value)}
          data-testid="condition-action"
        >
          {actions.map((action) => <option key={action.actionType} value={action.actionType}>{action.service} · {action.label}</option>)}
        </select>
      </label>
      <label htmlFor="condition-decision">Decisión cuando se cumplan las condiciones
        <select
          id="condition-decision"
          value={decision}
          onChange={(event) => setDecision(event.target.value as RuleDecision)}
          disabled={!canManage}
          data-testid="condition-decision"
        >
          <option value="allow">Permitir</option>
          <option value="require_approval">Pedir aprobación</option>
          <option value="deny">Bloquear</option>
        </select>
      </label>
      <label htmlFor="condition-fallback">Decisión si no se cumplen
        <select
          id="condition-fallback"
          value={fallbackDecision}
          onChange={(event) => setFallbackDecision(event.target.value as RuleDecision)}
          disabled={!canManage}
          data-testid="condition-fallback"
        >
          <option value="deny">Bloquear</option>
          <option value="require_approval">Pedir aprobación</option>
          <option value="allow">Permitir</option>
        </select>
      </label>
      <div className="wre-condition-list">
        {conditions.map((condition, index) => {
          const fields = [
            ...contextFields,
            ...selected.argumentFields.map((field) => ({
              name: field.name,
              label: field.name.replaceAll("_", " "),
              type: field.type,
            })),
          ];
          const field = fields.find((candidate) => candidate.name === condition.field);
          const isVolume = condition.field === "context.action_count";
          const isSensitivity = condition.field === "context.data_sensitivity";
          const isEnvironment = condition.field === "context.environment";
          const isDomain = ["to", "recipient_email", "forward_to"].includes(condition.field);
          return <div className="wre-condition-row" key={`${condition.field}-${index}`}>
            <label htmlFor={`condition-field-${index}`}>Condición
              <select
                id={`condition-field-${index}`}
                value={condition.field}
                disabled={!canManage}
                onChange={(event) => setConditions((current) => current.map((item, itemIndex) =>
                  itemIndex === index ? defaultCondition(event.target.value) : item,
                ))}
                data-testid={`condition-field-${index}`}
              >
                {fields.map((candidate) => <option key={candidate.name} value={candidate.name}>{candidate.label}</option>)}
              </select>
            </label>
            {isVolume ? <>
              <label htmlFor={`condition-op-${index}`}>Límite
                <select id={`condition-op-${index}`} value={condition.op} disabled={!canManage} onChange={(event) => updateCondition(index, { op: event.target.value })}>
                  <option value="gt">Más de</option><option value="lte">Hasta</option>
                </select>
              </label>
              <label htmlFor={`condition-value-${index}`}>Acciones
                <input id={`condition-value-${index}`} type="number" min="0" max="100000" value={condition.value} disabled={!canManage} onChange={(event) => updateCondition(index, { value: event.target.value })} />
              </label>
              <label htmlFor={`condition-window-${index}`}>Ventana
                <select id={`condition-window-${index}`} value={condition.windowSeconds} disabled={!canManage} onChange={(event) => updateCondition(index, { windowSeconds: event.target.value })}>
                  {volumeWindows.map((window) => <option key={window.value} value={window.value}>{window.label}</option>)}
                </select>
              </label>
            </> : isSensitivity ? <label htmlFor={`condition-value-${index}`}>Tipo de dato
              <select id={`condition-value-${index}`} value={condition.value} disabled={!canManage} onChange={(event) => updateCondition(index, { value: event.target.value })}>
                <option value="sensitive">Personal o sensible</option><option value="normal">Normal</option>
              </select>
            </label> : isEnvironment ? <label htmlFor={`condition-value-${index}`}>Entorno
              <select id={`condition-value-${index}`} value={condition.value} disabled={!canManage} onChange={(event) => updateCondition(index, { value: event.target.value })}>
                <option value="test">Pruebas</option><option value="production">Producción</option>
              </select>
            </label> : isDomain ? <label htmlFor={`condition-value-${index}`}>Dominios de confianza
              <input id={`condition-value-${index}`} type="text" value={condition.value} disabled={!canManage} placeholder="example.test, empresa.example" onChange={(event) => updateCondition(index, { value: event.target.value })} />
            </label> : <label htmlFor={`condition-value-${index}`}>Valor
              {field?.type === "number" ? <>
                <select aria-label={`Comparación de ${field.label}`} value={condition.op} disabled={!canManage} onChange={(event) => updateCondition(index, { op: event.target.value })}>
                  <option value="lte">Hasta</option><option value="gt">Más de</option>
                </select>
                <input id={`condition-value-${index}`} type="number" min="0" value={condition.value} disabled={!canManage} onChange={(event) => updateCondition(index, { value: event.target.value })} />
              </> : field?.type === "boolean" ? <select id={`condition-value-${index}`} value={condition.value} disabled={!canManage} onChange={(event) => updateCondition(index, { value: event.target.value })}>
                <option value="true">Sí</option><option value="false">No</option>
              </select> : <input id={`condition-value-${index}`} type="text" value={condition.value} disabled={!canManage} onChange={(event) => updateCondition(index, { value: event.target.value })} />}
            </label>}
            {canManage && conditions.length > 1 && <button type="button" className="wre-condition-remove" aria-label="Quitar condición" onClick={() => setConditions((current) => current.filter((_, itemIndex) => itemIndex !== index))}>Quitar</button>}
          </div>;
        })}
      </div>
      {canManage && conditions.length < 8 && <button type="button" className="wre-condition-add" onClick={() => setConditions((current) => [...current, defaultCondition("context.environment")])} data-testid="condition-add">Añadir condición</button>}
      {error && <p role="alert" className="wre-inline-error" data-testid="condition-error">{error}</p>}
      {status && <p role="status" className="wre-status" data-testid="condition-status">{status}</p>}
      {canManage
        ? <button type="button" className="wre-condition-save" disabled={busy} onClick={() => void save()} data-testid="condition-save">Guardar borrador</button>
        : <p className="wre-readonly-note">Solo owner o admin puede cambiar las condiciones. Puedes consultar las reglas activas.</p>}
    </div>
  </section>;
}
