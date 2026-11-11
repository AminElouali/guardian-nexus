import { z } from "zod/v4";

const sha256Pattern = /^[a-f0-9]{64}$/;
const commitPattern = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/;

const serviceIdentitySchema = z
  .object({
    uid: z.number().int().positive(),
    gid: z.number().int().positive(),
    groups: z.array(z.number().int().positive()).min(1).max(64),
    databaseRole: z.string().min(1).max(128),
  })
  .strict();

const processClaimsSchema = z
  .object({
    noNewPrivileges: z.literal(true),
    seccompEnforced: z.literal(true),
    seccompProfileSha256: z.string().regex(sha256Pattern),
    capabilities: z.array(z.never()).max(0),
    readOnlyRoot: z.literal(true),
  })
  .strict();

const namespaceSchema = z
  .object({
    user: z.string().min(1).max(128),
    pid: z.string().min(1).max(128),
    mount: z.string().min(1).max(128),
    network: z.string().min(1).max(128),
  })
  .strict();

const databaseSessionSchema = z
  .object({
    databaseName: z.string().regex(/^guardian_lab_[a-z0-9_]{1,50}$/),
    role: z.string().min(1).max(128),
    superuser: z.literal(false),
    bypassRls: z.literal(false),
  })
  .strict();

export const hostAttestationPayloadSchema = z
  .object({
    schemaVersion: z.literal(1),
    attestationType: z.literal("guardian_host_challenge_response"),
    supervisorId: z.string().min(1).max(160),
    workspaceId: z.string().uuid(),
    challengeId: z.string().uuid(),
    nonce: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
    issuedAt: z.string().datetime({ offset: true }),
    expiresAt: z.string().datetime({ offset: true }),
    runtimeCommit: z.string().regex(commitPattern),
    runtimeDigestSha256: z.string().regex(sha256Pattern),
    serviceIdentities: z
      .object({
        api: serviceIdentitySchema,
        broker: serviceIdentitySchema,
        worker: serviceIdentitySchema,
      })
      .strict(),
    claims: z
      .object({
        namespaces: z
          .object({
            api: namespaceSchema,
            broker: namespaceSchema,
            worker: namespaceSchema,
          })
          .strict(),
        processHardening: z
          .object({
            api: processClaimsSchema,
            broker: processClaimsSchema,
            worker: processClaimsSchema,
          })
          .strict(),
        dockerSocket: z
          .object({
            groupGid: z.number().int().positive(),
            apiAccess: z.literal("denied"),
            brokerAccess: z.literal("allowed"),
            workerAccess: z.literal("denied"),
            mountedIntoApi: z.literal(false),
            mountedIntoWorker: z.literal(false),
          })
          .strict(),
        inheritedFileDescriptors: z
          .object({
            api: z.array(z.number().int().nonnegative()).max(0),
            broker: z.array(z.number().int().nonnegative()).max(0),
            worker: z.array(z.number().int().nonnegative()).max(0),
          })
          .strict(),
        databaseSessions: z
          .object({
            api: databaseSessionSchema,
            broker: databaseSessionSchema,
            worker: databaseSessionSchema,
          })
          .strict(),
        workerNetworkEgressDenied: z.literal(true),
      })
      .strict(),
  })
  .strict();

export const hostAttestationResponseEnvelopeSchema = z
  .object({
    payload: hostAttestationPayloadSchema,
    signatureBase64: z.string().regex(/^[A-Za-z0-9+/]{86}==$/),
  })
  .strict();

export type HostBoundaryAttestationPayload = z.infer<
  typeof hostAttestationPayloadSchema
>;
export type HostBoundaryAttestationEnvelope = z.infer<
  typeof hostAttestationResponseEnvelopeSchema
>;
