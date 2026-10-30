export const MODEL_ARMOR_EU_LOCATIONS = [
  "eu",
  "europe-southwest1",
  "europe-west1",
  "europe-west3",
  "europe-west4",
  "europe-west9",
] as const;

export type ModelArmorEuLocation =
  (typeof MODEL_ARMOR_EU_LOCATIONS)[number];

export type ModelArmorReadiness =
  | { state: "disabled"; reason: "feature_flag_off" }
  | { state: "needs_consent"; reason: "tenant_consent_required" }
  | { state: "blocked"; reason: "missing_configuration" | "non_eu_location" }
  | { state: "prepared"; location: ModelArmorEuLocation };

export type ModelArmorSanitizationRequest = {
  mode: "user_prompt" | "model_response";
  projectId: string;
  location: ModelArmorEuLocation;
  templateId: string;
  text: string;
};

export type ModelArmorSanitizationResult = {
  sanitizedText: string;
  triggeredFilters: string[];
};

export interface ModelArmorTransport {
  sanitize(
    request: ModelArmorSanitizationRequest,
    accessToken: string,
  ): Promise<ModelArmorSanitizationResult>;
}

export interface ModelArmorAccessTokenProvider {
  getAccessToken(): Promise<string>;
}

export function getModelArmorReadiness(input: {
  featureFlag: boolean;
  tenantConsent: boolean;
  projectId?: string;
  location?: string;
  promptTemplateId?: string;
  responseTemplateId?: string;
}): ModelArmorReadiness {
  if (!input.featureFlag) {
    return { state: "disabled", reason: "feature_flag_off" };
  }
  if (!input.tenantConsent) {
    return { state: "needs_consent", reason: "tenant_consent_required" };
  }
  if (!input.projectId || !input.promptTemplateId || !input.responseTemplateId) {
    return { state: "blocked", reason: "missing_configuration" };
  }
  if (
    !MODEL_ARMOR_EU_LOCATIONS.includes(
      input.location as ModelArmorEuLocation,
    )
  ) {
    return { state: "blocked", reason: "non_eu_location" };
  }
  return {
    state: "prepared",
    location: input.location as ModelArmorEuLocation,
  };
}

/**
 * Optional per-tenant adapter seam. No transport is installed or called unless
 * the server flag, tenant consent, EU location and required configuration pass.
 * The bearer token is held only in memory and never logged or persisted.
 */
export class ModelArmorAdapter {
  constructor(
    private readonly readiness: ModelArmorReadiness,
    private readonly projectId: string | undefined,
    private readonly promptTemplateId: string | undefined,
    private readonly responseTemplateId: string | undefined,
    private readonly tokenProvider: ModelArmorAccessTokenProvider | undefined,
    private readonly transport: ModelArmorTransport | undefined,
  ) {}

  async sanitize(
    mode: "user_prompt" | "model_response",
    text: string,
  ): Promise<ModelArmorSanitizationResult> {
    if (this.readiness.state !== "prepared") {
      throw new Error("Model Armor is not enabled for this tenant.");
    }
    if (
      !this.projectId ||
      !this.promptTemplateId ||
      !this.responseTemplateId ||
      !this.tokenProvider ||
      !this.transport
    ) {
      throw new Error("Model Armor adapter is missing runtime configuration.");
    }
    if (typeof text !== "string" || text.length === 0 || text.length > 24_000) {
      throw new Error("Model Armor input must contain 1–24000 characters.");
    }

    const accessToken = await this.tokenProvider.getAccessToken();
    if (!accessToken || accessToken.length > 16_384) {
      throw new Error("Model Armor authorization is unavailable.");
    }
    return this.transport.sanitize(
      {
        mode,
        projectId: this.projectId,
        location: this.readiness.location,
        templateId:
          mode === "user_prompt"
            ? this.promptTemplateId
            : this.responseTemplateId,
        text,
      },
      accessToken,
    );
  }
}
