export interface AssessmentBrokerSocket {
  isSocket: boolean;
  uid: number;
  gid: number;
  mode: number;
}

export interface AssessmentBrokerBoundaryInput {
  processRole: string | undefined;
  processUid: number | null;
  processGroups: number[];
  apiUid: number | null;
  apiGroups: number[];
  brokerUid: number | null;
  socket: AssessmentBrokerSocket | null;
  brokerDatabaseIdentityVerified: boolean;
}

export type AssessmentBrokerBoundaryResult =
  | { allowed: true; reasonCode: null }
  | { allowed: false; reasonCode: string };

function canAccessDockerSocket(
  uid: number,
  groups: number[],
  socket: AssessmentBrokerSocket,
): boolean {
  if (uid === 0) return true;
  if (uid === socket.uid) return (socket.mode & 0o600) === 0o600;
  if (groups.includes(socket.gid)) return (socket.mode & 0o060) === 0o060;
  return (socket.mode & 0o006) === 0o006;
}

export function evaluateAssessmentBrokerBoundary(
  input: AssessmentBrokerBoundaryInput,
): AssessmentBrokerBoundaryResult {
  if (input.processRole !== "assessment-broker") {
    return { allowed: false, reasonCode: "assessment_broker_role_required" };
  }
  if (input.processUid === null || input.apiUid === null) {
    return { allowed: false, reasonCode: "assessment_broker_uid_unverified" };
  }
  if (input.brokerUid === null || input.processUid !== input.brokerUid) {
    return { allowed: false, reasonCode: "assessment_broker_uid_mismatch" };
  }
  if (input.processUid === input.apiUid) {
    return { allowed: false, reasonCode: "assessment_broker_shared_uid" };
  }
  if (!input.socket?.isSocket) {
    return { allowed: false, reasonCode: "assessment_docker_socket_unverified" };
  }
  if (
    canAccessDockerSocket(input.apiUid, input.apiGroups, input.socket)
  ) {
    return { allowed: false, reasonCode: "assessment_api_can_access_docker" };
  }
  if (
    !canAccessDockerSocket(input.processUid, input.processGroups, input.socket)
  ) {
    return {
      allowed: false,
      reasonCode: "assessment_broker_cannot_access_docker",
    };
  }
  if (!input.brokerDatabaseIdentityVerified) {
    return {
      allowed: false,
      reasonCode: "assessment_broker_database_identity_unverified",
    };
  }
  return { allowed: true, reasonCode: null };
}
