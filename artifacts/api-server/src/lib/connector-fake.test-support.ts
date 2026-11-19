import type {
  ConnectorExecutionAdapter,
  ConnectorExecutionAdapterResult,
} from "./workspace-connector-executions";

export type FakeConnectorInvocation = {
  workspaceId: string;
  actionType: string;
  argumentNames: string[];
  credentialReceived: boolean;
};

export function createFakeLabConnector(input?: {
  failInvocationNumber?: number;
  responseSummary?: string;
}): {
  adapter: ConnectorExecutionAdapter;
  invocations: FakeConnectorInvocation[];
  networkCalls: number;
} {
  const invocations: FakeConnectorInvocation[] = [];
  const state = { networkCalls: 0 };
  const adapter: ConnectorExecutionAdapter = {
    serviceId: "lab.fake.v1",
    async execute(request): Promise<ConnectorExecutionAdapterResult> {
      invocations.push({
        workspaceId: request.workspaceId,
        actionType: request.actionType,
        argumentNames: Object.keys(request.arguments).sort(),
        credentialReceived: request.credential.length > 0,
      });
      if (invocations.length === input?.failInvocationNumber) {
        throw new Error("fake_connector_failure");
      }
      return {
        resultCode: "captured_locally",
        summary:
          input?.responseSummary ??
          "Acción capturada por el conector falso del laboratorio; no hubo conexión de red.",
      };
    },
  };
  return {
    adapter,
    invocations,
    get networkCalls() {
      return state.networkCalls;
    },
  };
}
