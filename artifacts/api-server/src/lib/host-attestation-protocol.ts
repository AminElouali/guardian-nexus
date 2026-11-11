import {
  createHash,
  createPublicKey,
  randomBytes,
  randomUUID,
  verify as verifySignature,
  type KeyObject,
} from "node:crypto";
import {
  closeSync,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
} from "node:fs";
import { constants as fsConstants } from "node:fs";
import path from "node:path";
import {
  hostAttestationPayloadSchema,
  hostAttestationResponseEnvelopeSchema,
  type HostBoundaryAttestationEnvelope,
  type HostBoundaryAttestationPayload,
} from "@workspace/api-zod";

export {
  hostAttestationPayloadSchema,
  hostAttestationResponseEnvelopeSchema,
};
export type HostAttestationPayload = HostBoundaryAttestationPayload;
export type HostAttestationResponseEnvelope = HostBoundaryAttestationEnvelope;

export const HOST_ATTESTATION_CHALLENGE_TTL_MS = 2 * 60 * 1000;
export const HOST_ATTESTATION_TRUST_ANCHOR_PATH =
  "/etc/guardian-nexus/host-boundary-attestor-ed25519.pem";
export const HOST_ATTESTATION_SUPERVISOR_ID =
  "guardian-nexus-independent-host-supervisor-v1";
export const HOST_ATTESTATION_DOMAIN =
  "guardian-nexus-host-challenge-response-v1\n";

const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const COMMIT_PATTERN = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/;

export type HostRuntimeIdentity = {
  runtimeCommit: string;
  runtimeDigestSha256: string;
};

export type HostServiceIdentity = {
  uid: number;
  gid: number;
  groups: number[];
};

export type HostAttestationChallenge = {
  id: string;
  workspaceId: string;
  nonceSha256: string;
  runtimeCommit: string;
  runtimeDigestSha256: string;
  issuedAt: Date;
  expiresAt: Date;
  issuedByUserId: string;
};

export type HostChallengeConsumption =
  | { kind: "consumed"; challenge: HostAttestationChallenge }
  | { kind: "missing" }
  | { kind: "replay" }
  | { kind: "expired" };

export interface HostAttestationNonceRepository {
  insert(challenge: HostAttestationChallenge): Promise<void>;
  consume(input: {
    challengeId: string;
    workspaceId: string;
    now: Date;
  }): Promise<HostChallengeConsumption>;
  finish(input: {
    challengeId: string;
    workspaceId: string;
    status: "verified" | "rejected";
    responseSha256: string;
    supervisorId: string | null;
    finishedAt: Date;
  }): Promise<void>;
}

export type HostAttestationProtocolResult = {
  attestationStatus:
    | "verified"
    | "rejected"
    | "expired"
    | "challenge_not_found"
    | "replay_rejected"
    | "prerequisite_unavailable";
  reasonCode: string | null;
  hostBoundaryReady: false;
  integratedAssessmentReady: false;
  workerAdmission: "disabled";
};

export class HostAttestationProtocolError extends Error {
  constructor(readonly reasonCode: string) {
    super(reasonCode);
    this.name = "HostAttestationProtocolError";
  }
}

export type HostAttestationProtocolDependencies = {
  repository: HostAttestationNonceRepository;
  loadTrustAnchor: () => { supervisorId: string; publicKey: KeyObject };
  getRuntimeIdentity: () => HostRuntimeIdentity;
  getApiIdentity: () => HostServiceIdentity;
  now?: () => Date;
  createId?: () => string;
  createNonce?: () => string;
};

function hashHex(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    const encoded = JSON.stringify(value);
    if (encoded === undefined) {
      throw new HostAttestationProtocolError(
        "assessment_host_attestation_payload_invalid",
      );
    }
    return encoded;
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(",")}}`;
}

export function canonicalHostAttestationBytes(
  payload: HostAttestationPayload,
): Buffer {
  return Buffer.from(
    `${HOST_ATTESTATION_DOMAIN}${canonicalJson(payload)}`,
    "utf8",
  );
}

function parseDate(value: string): Date | null {
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) ? new Date(milliseconds) : null;
}

function equalGroups(left: number[], right: number[]): boolean {
  return (
    [...new Set(left)].sort((a, b) => a - b).join(",") ===
    [...new Set(right)].sort((a, b) => a - b).join(",")
  );
}

function validateClaims(
  payload: HostAttestationPayload,
  expectedApiIdentity: HostServiceIdentity,
): string | null {
  const services = ["api", "broker", "worker"] as const;
  const identities = services.map((name) => payload.serviceIdentities[name]);
  if (
    new Set(identities.map((identity) => identity.uid)).size !== 3 ||
    new Set(identities.map((identity) => identity.gid)).size !== 3 ||
    new Set(identities.map((identity) => identity.databaseRole)).size !== 3
  ) {
    return "assessment_host_identities_not_separate";
  }
  for (const identity of identities) {
    if (
      !identity.groups.includes(identity.gid) ||
      new Set(identity.groups).size !== identity.groups.length
    ) {
      return "assessment_host_service_identity_invalid";
    }
  }

  const api = payload.serviceIdentities.api;
  if (
    api.uid !== expectedApiIdentity.uid ||
    api.gid !== expectedApiIdentity.gid ||
    !equalGroups(api.groups, expectedApiIdentity.groups)
  ) {
    return "assessment_host_api_identity_mismatch";
  }
  if (
    payload.serviceIdentities.api.databaseRole !== "app_runtime" ||
    payload.serviceIdentities.broker.databaseRole !==
      "app_ai_assessment_broker" ||
    payload.serviceIdentities.worker.databaseRole !==
      "app_ai_assessment_worker"
  ) {
    return "assessment_host_database_role_invalid";
  }

  const socketGroupGid = payload.claims.dockerSocket.groupGid;
  if (
    payload.serviceIdentities.api.groups.includes(socketGroupGid) ||
    payload.serviceIdentities.worker.groups.includes(socketGroupGid) ||
    !payload.serviceIdentities.broker.groups.includes(socketGroupGid)
  ) {
    return "assessment_host_socket_group_access_invalid";
  }
  for (const service of services) {
    const identity = payload.serviceIdentities[service];
    const session = payload.claims.databaseSessions[service];
    if (
      session.role !== identity.databaseRole ||
      session.superuser ||
      session.bypassRls
    ) {
      return "assessment_host_database_role_invalid";
    }
  }
  const namespaceKinds = ["user", "pid", "mount", "network"] as const;
  for (const kind of namespaceKinds) {
    if (
      new Set(services.map((service) => payload.claims.namespaces[service][kind]))
        .size !== services.length
    ) {
      return "assessment_host_namespaces_not_separate";
    }
  }
  return null;
}

function protocolResult(
  attestationStatus: HostAttestationProtocolResult["attestationStatus"],
  reasonCode: string | null,
): HostAttestationProtocolResult {
  return {
    attestationStatus,
    reasonCode,
    // Protocol verification records evidence only. The admission gate is
    // intentionally not wired to this result in this increment.
    hostBoundaryReady: false,
    integratedAssessmentReady: false,
    workerAdmission: "disabled",
  };
}

export function createHostAttestationChallenge(
  dependencies: HostAttestationProtocolDependencies,
) {
  const now = dependencies.now ?? (() => new Date());
  const createId = dependencies.createId ?? randomUUID;
  const createNonce =
    dependencies.createNonce ??
    (() => randomBytes(32).toString("base64url"));

  return {
    async issue(input: {
      workspaceId: string;
      issuedByUserId: string;
    }): Promise<{
      id: string;
      workspaceId: string;
      nonce: string;
      issuedAt: string;
      expiresAt: string;
      runtimeCommit: string;
      runtimeDigestSha256: string;
    }> {
      let trustAnchor: ReturnType<typeof dependencies.loadTrustAnchor>;
      let runtimeIdentity: HostRuntimeIdentity;
      try {
        trustAnchor = dependencies.loadTrustAnchor();
        runtimeIdentity = dependencies.getRuntimeIdentity();
      } catch {
        throw new HostAttestationProtocolError(
          "assessment_host_attestation_prerequisite_unavailable",
        );
      }
      if (
        trustAnchor.supervisorId !== HOST_ATTESTATION_SUPERVISOR_ID ||
        trustAnchor.publicKey.asymmetricKeyType !== "ed25519" ||
        !COMMIT_PATTERN.test(runtimeIdentity.runtimeCommit) ||
        !SHA256_PATTERN.test(runtimeIdentity.runtimeDigestSha256)
      ) {
        throw new HostAttestationProtocolError(
          "assessment_host_attestation_prerequisite_invalid",
        );
      }
      let apiIdentity: HostServiceIdentity;
      try {
        apiIdentity = dependencies.getApiIdentity();
      } catch {
        throw new HostAttestationProtocolError(
          "assessment_host_api_identity_unavailable",
        );
      }
      if (
        apiIdentity.uid <= 0 ||
        apiIdentity.gid <= 0 ||
        !apiIdentity.groups.includes(apiIdentity.gid)
      ) {
        throw new HostAttestationProtocolError(
          "assessment_host_api_identity_unavailable",
        );
      }

      const issuedAt = now();
      const expiresAt = new Date(
        issuedAt.getTime() + HOST_ATTESTATION_CHALLENGE_TTL_MS,
      );
      const nonce = createNonce();
      if (!/^[A-Za-z0-9_-]{43}$/.test(nonce)) {
        throw new HostAttestationProtocolError(
          "assessment_host_challenge_nonce_invalid",
        );
      }
      const id = createId();
      await dependencies.repository.insert({
        id,
        workspaceId: input.workspaceId,
        nonceSha256: hashHex(nonce),
        runtimeCommit: runtimeIdentity.runtimeCommit,
        runtimeDigestSha256: runtimeIdentity.runtimeDigestSha256,
        issuedAt,
        expiresAt,
        issuedByUserId: input.issuedByUserId,
      });
      return {
        id,
        workspaceId: input.workspaceId,
        nonce,
        issuedAt: issuedAt.toISOString(),
        expiresAt: expiresAt.toISOString(),
        runtimeCommit: runtimeIdentity.runtimeCommit,
        runtimeDigestSha256: runtimeIdentity.runtimeDigestSha256,
      };
    },

    async respond(input: {
      workspaceId: string;
      challengeId: string;
      envelope: unknown;
    }): Promise<HostAttestationProtocolResult> {
      const parsed = hostAttestationResponseEnvelopeSchema.safeParse(
        input.envelope,
      );
      if (!parsed.success) {
        return protocolResult("rejected", "assessment_host_response_invalid");
      }

      let trustAnchor: ReturnType<typeof dependencies.loadTrustAnchor>;
      let runtimeIdentity: HostRuntimeIdentity;
      let apiIdentity: HostServiceIdentity;
      try {
        trustAnchor = dependencies.loadTrustAnchor();
        runtimeIdentity = dependencies.getRuntimeIdentity();
        apiIdentity = dependencies.getApiIdentity();
      } catch {
        return protocolResult(
          "prerequisite_unavailable",
          "assessment_host_attestation_prerequisite_unavailable",
        );
      }
      if (
        trustAnchor.supervisorId !== HOST_ATTESTATION_SUPERVISOR_ID ||
        trustAnchor.publicKey.asymmetricKeyType !== "ed25519" ||
        !COMMIT_PATTERN.test(runtimeIdentity.runtimeCommit) ||
        !SHA256_PATTERN.test(runtimeIdentity.runtimeDigestSha256)
      ) {
        return protocolResult(
          "prerequisite_unavailable",
          "assessment_host_attestation_prerequisite_invalid",
        );
      }

      const currentTime = now();
      const consumption = await dependencies.repository.consume({
        challengeId: input.challengeId,
        workspaceId: input.workspaceId,
        now: currentTime,
      });
      if (consumption.kind === "missing") {
        return protocolResult(
          "challenge_not_found",
          "assessment_host_challenge_not_found",
        );
      }
      if (consumption.kind === "replay") {
        return protocolResult(
          "replay_rejected",
          "assessment_host_challenge_replayed",
        );
      }
      if (consumption.kind === "expired") {
        return protocolResult(
          "expired",
          "assessment_host_challenge_expired",
        );
      }

      const { payload, signatureBase64 } = parsed.data;
      const responseSha256 = hashHex(
        `${canonicalJson(payload)}.${signatureBase64}`,
      );
      let reasonCode: string | null = null;
      const issuedAt = parseDate(payload.issuedAt);
      const expiresAt = parseDate(payload.expiresAt);
      const challenge = consumption.challenge;
      if (
        payload.supervisorId !== trustAnchor.supervisorId ||
        payload.workspaceId !== input.workspaceId ||
        payload.challengeId !== challenge.id ||
        hashHex(payload.nonce) !== challenge.nonceSha256
      ) {
        reasonCode = "assessment_host_challenge_binding_mismatch";
      } else if (
        payload.runtimeCommit !== challenge.runtimeCommit ||
        payload.runtimeCommit !== runtimeIdentity.runtimeCommit ||
        payload.runtimeDigestSha256 !== challenge.runtimeDigestSha256 ||
        payload.runtimeDigestSha256 !== runtimeIdentity.runtimeDigestSha256
      ) {
        reasonCode = "assessment_host_runtime_binding_mismatch";
      } else if (
        !issuedAt ||
        !expiresAt ||
        issuedAt.getTime() < challenge.issuedAt.getTime() - 5_000 ||
        issuedAt.getTime() > challenge.issuedAt.getTime() + 5_000 ||
        issuedAt.getTime() > currentTime.getTime() + 5_000 ||
        expiresAt.getTime() <= currentTime.getTime() ||
        expiresAt.getTime() > challenge.expiresAt.getTime() ||
        expiresAt.getTime() <= issuedAt.getTime()
      ) {
        reasonCode = "assessment_host_challenge_expired_or_stale";
      } else {
        reasonCode = validateClaims(payload, apiIdentity);
      }

      if (!reasonCode) {
        try {
          const signature = Buffer.from(signatureBase64, "base64");
          if (
            signature.length !== 64 ||
            signature.toString("base64") !== signatureBase64 ||
            !verifySignature(
              null,
              canonicalHostAttestationBytes(payload),
              trustAnchor.publicKey,
              signature,
            )
          ) {
            reasonCode = "assessment_host_signature_invalid";
          }
        } catch {
          reasonCode = "assessment_host_signature_invalid";
        }
      }

      const verified = reasonCode === null;
      await dependencies.repository.finish({
        challengeId: challenge.id,
        workspaceId: challenge.workspaceId,
        status: verified ? "verified" : "rejected",
        responseSha256,
        supervisorId: payload.supervisorId,
        finishedAt: currentTime,
      });
      return protocolResult(
        verified ? "verified" : "rejected",
        verified ? "assessment_runtime_gate_remains_closed" : reasonCode,
      );
    },
  };
}

function verifyRootOwnedDirectoryChain(directory: string): void {
  let current = path.resolve(directory);
  while (true) {
    const stat = lstatSync(current);
    if (
      !stat.isDirectory() ||
      stat.uid !== 0 ||
      (stat.mode & 0o022) !== 0
    ) {
      throw new HostAttestationProtocolError(
        "assessment_host_trust_anchor_untrusted",
      );
    }
    const parent = path.dirname(current);
    if (parent === current) return;
    current = parent;
  }
}

export function loadPinnedHostTrustAnchor(): {
  supervisorId: string;
  publicKey: KeyObject;
} {
  let descriptor: number | undefined;
  try {
    const trustPath = HOST_ATTESTATION_TRUST_ANCHOR_PATH;
    const before = lstatSync(trustPath);
    if (
      !before.isFile() ||
      before.uid !== 0 ||
      (before.mode & 0o022) !== 0 ||
      before.nlink !== 1 ||
      before.size < 1 ||
      before.size > 16 * 1024
    ) {
      throw new HostAttestationProtocolError(
        "assessment_host_trust_anchor_untrusted",
      );
    }
    verifyRootOwnedDirectoryChain(path.dirname(trustPath));
    const noFollow = fsConstants.O_NOFOLLOW;
    if (typeof noFollow !== "number") {
      throw new HostAttestationProtocolError(
        "assessment_host_trust_anchor_nofollow_unavailable",
      );
    }
    descriptor = openSync(
      trustPath,
      fsConstants.O_RDONLY | noFollow,
    );
    const opened = fstatSync(descriptor);
    if (
      opened.dev !== before.dev ||
      opened.ino !== before.ino ||
      opened.uid !== 0 ||
      (opened.mode & 0o022) !== 0 ||
      !opened.isFile()
    ) {
      throw new HostAttestationProtocolError(
        "assessment_host_trust_anchor_changed",
      );
    }
    const keyBytes = readFileSync(descriptor);
    const keyPem = keyBytes.toString("ascii");
    if (
      keyBytes.length > 16 * 1024 ||
      !/^-----BEGIN PUBLIC KEY-----\r?\n[\s\S]+?\r?\n-----END PUBLIC KEY-----\r?\n?$/.test(
        keyPem,
      )
    ) {
      throw new HostAttestationProtocolError(
        "assessment_host_trust_anchor_not_public_pem",
      );
    }
    const publicKey = createPublicKey({
      key: keyBytes,
      format: "pem",
      type: "spki",
    });
    if (publicKey.asymmetricKeyType !== "ed25519") {
      throw new HostAttestationProtocolError(
        "assessment_host_trust_anchor_algorithm_invalid",
      );
    }
    return {
      supervisorId: HOST_ATTESTATION_SUPERVISOR_ID,
      publicKey,
    };
  } catch (error) {
    if (error instanceof HostAttestationProtocolError) throw error;
    throw new HostAttestationProtocolError(
      "assessment_host_trust_anchor_unavailable",
    );
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

export function getCurrentApiServiceIdentity(): HostServiceIdentity {
  const uid = process.getuid?.();
  const gid = process.getgid?.();
  const groups = process.getgroups?.();
  if (
    uid === undefined ||
    gid === undefined ||
    !groups ||
    uid <= 0 ||
    gid <= 0 ||
    !groups.includes(gid)
  ) {
    throw new HostAttestationProtocolError(
      "assessment_host_api_identity_unavailable",
    );
  }
  return {
    uid,
    gid,
    groups: [...new Set([...groups, gid])].sort((a, b) => a - b),
  };
}

export function computeCurrentHostRuntimeIdentity(
  cwd = process.cwd(),
): HostRuntimeIdentity {
  const candidateRoots = [path.resolve(cwd), path.resolve(cwd, "../..")];
  const sourcePaths = [
    "artifacts/api-server/src/lib/host-attestation-protocol.ts",
    "artifacts/api-server/src/lib/host-attestation-persistence.ts",
    "artifacts/api-server/src/lib/assessment-worker-api-gate.ts",
    "artifacts/api-server/src/lib/assessment-worker-mode.ts",
    "artifacts/api-server/src/lib/assessment-container-control.ts",
    "artifacts/api-server/src/lib/ai-assessment-sandbox.ts",
    "artifacts/api-server/src/routes/index.ts",
    "artifacts/api-server/src/routes/ai-assessment-lab.ts",
    "artifacts/api-server/src/lib/tenant-db.ts",
    "artifacts/api-server/src/middlewares/ai-assessment-json.ts",
    "artifacts/api-server/src/app.ts",
    "lib/db/src/index.ts",
    "lib/db/src/schema/host-attestation.ts",
    "lib/db/src/schema/index.ts",
    "lib/db/src/schema/roles.ts",
    "lib/db/scripts/bootstrap-runtime-role.mjs",
    "lib/db/sql/rls-policies.sql",
    "lib/api-spec/openapi.yaml",
    "lib/api-zod/src/host-attestation.ts",
    "lib/api-zod/src/index.ts",
    "workers/guardian-ai-assessment/guardian_ai_assessment/host_boundary_attestation.py",
    "workers/guardian-ai-assessment/guardian_ai_assessment/offline_qwen_runner.py",
    "workers/guardian-ai-assessment/guardian_ai_assessment/qwen_policy_lab.py",
    "workers/guardian-ai-assessment/Dockerfile",
    "workers/guardian-ai-assessment/Dockerfile.qwen.offline",
    "workers/guardian-ai-assessment/profile-image-lock.json",
    "workers/guardian-ai-assessment/requirements-runtime.txt",
    "workers/guardian-ai-assessment/requirements-qwen-runtime.txt",
  ];
  const root = candidateRoots.find((candidate) => {
    try {
      return lstatSync(path.join(candidate, sourcePaths[0])).isFile();
    } catch {
      return false;
    }
  });
  if (!root) {
    throw new HostAttestationProtocolError(
      "assessment_host_runtime_sources_unavailable",
    );
  }

  const gitDirectoryPath = path.join(root, ".git");
  let gitDirectory = gitDirectoryPath;
  try {
    if (lstatSync(gitDirectoryPath).isFile()) {
      const gitFile = readFileSync(gitDirectoryPath, "utf8").trim();
      const match = /^gitdir: (.+)$/.exec(gitFile);
      if (!match) throw new Error("Invalid gitdir marker");
      gitDirectory = path.resolve(root, match[1]);
    }
    const head = readFileSync(path.join(gitDirectory, "HEAD"), "utf8").trim();
    let runtimeCommit: string | undefined;
    if (COMMIT_PATTERN.test(head)) {
      runtimeCommit = head;
    } else {
      const ref = /^ref: (refs\/[A-Za-z0-9_./-]+)$/.exec(head)?.[1];
      if (!ref || ref.split("/").includes("..")) throw new Error("Invalid HEAD");
      try {
        runtimeCommit = readFileSync(path.join(gitDirectory, ref), "utf8").trim();
      } catch {
        const packedRefs = readFileSync(
          path.join(gitDirectory, "packed-refs"),
          "utf8",
        );
        runtimeCommit = packedRefs
          .split("\n")
          .map((line) => line.match(/^([a-f0-9]{40,64})\s+(.+)$/))
          .find((entry) => entry?.[2] === ref)?.[1];
      }
    }
    if (!runtimeCommit || !COMMIT_PATTERN.test(runtimeCommit)) {
      throw new Error("Could not resolve the checked-out commit");
    }
    const sourceHashes: Record<string, string> = {};
    for (const relativePath of sourcePaths) {
      const absolutePath = path.join(root, relativePath);
      if (!lstatSync(absolutePath).isFile()) throw new Error("Not a regular source");
      sourceHashes[relativePath] = createHash("sha256")
        .update(readFileSync(absolutePath))
        .digest("hex");
    }
    const runtimeEntry = process.argv[1];
    if (!runtimeEntry) throw new Error("Runtime entry is missing");
    const runtimeEntryPath = path.resolve(cwd, runtimeEntry);
    const relativeRuntimeEntry = path.relative(root, runtimeEntryPath);
    if (
      relativeRuntimeEntry === "" ||
      relativeRuntimeEntry === ".." ||
      relativeRuntimeEntry.startsWith(`..${path.sep}`) ||
      path.isAbsolute(relativeRuntimeEntry)
    ) {
      throw new Error("Runtime entry is outside the workspace");
    }
    if (!lstatSync(runtimeEntryPath).isFile()) {
      throw new Error("Runtime entry is not a regular file");
    }
    sourceHashes[`runtime-entry:${relativeRuntimeEntry}`] = createHash("sha256")
      .update(readFileSync(runtimeEntryPath))
      .digest("hex");
    return {
      runtimeCommit,
      runtimeDigestSha256: hashHex(canonicalJson(sourceHashes)),
    };
  } catch {
    throw new HostAttestationProtocolError(
      "assessment_host_runtime_identity_unavailable",
    );
  }
}

export function hashHostAttestationNonce(nonce: string): string {
  return hashHex(nonce);
}
