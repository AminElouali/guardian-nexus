import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { connect } from "node:net";

const RECEIPT_DOMAIN = "guardian-nexus:approval-receipt:v1\n";
const RECEIPT_FIELDS = [
  "version",
  "keyId",
  "receiptId",
  "workspaceId",
  "approvalId",
  "proposalBindingSha256",
  "actionSha256",
  "requestedBy",
  "approvedBy",
  "approvedByRole",
  "issuedAt",
  "expiresAt",
  "nonce",
];
const SHA256 = /^[a-f0-9]{64}$/;
const KEY_ID = /^[A-Za-z0-9._-]{1,64}$/;
const BASE64URL = /^[A-Za-z0-9_-]{86}$/;
const SANDBOX_EMAIL = /^[A-Za-z0-9._+-]+@(?:example\.test|guardian\.invalid)$/;
const GUARD_CREDENTIAL = /^[A-Za-z0-9_-]{43,128}$/;

export class GuardianGuardError extends Error {
  constructor(code) {
    super(code);
    this.name = "GuardianGuardError";
    this.code = code;
  }
}

function hasExactKeys(value, expected) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const keys = Reflect.ownKeys(value);
  return keys.length === expected.length &&
    expected.every((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      return descriptor?.enumerable === true && "value" in descriptor;
    }) &&
    keys.every((key) => typeof key === "string" && expected.includes(key));
}

function assertScalarString(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new GuardianGuardError("canonicalization_invalid");
      }
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new GuardianGuardError("canonicalization_invalid");
    }
  }
}

export function canonicalizeV1(value) {
  let nodeCount = 0;
  const visit = (item, depth) => {
    nodeCount += 1;
    if (nodeCount > 20_000 || depth > 64) {
      throw new GuardianGuardError("canonicalization_invalid");
    }
    if (typeof item === "string") {
      assertScalarString(item);
      return JSON.stringify(item);
    }
    if (typeof item === "boolean") return item ? "true" : "false";
    if (typeof item === "number") {
      if (!Number.isSafeInteger(item) || Object.is(item, -0)) {
        throw new GuardianGuardError("canonicalization_invalid");
      }
      return String(item);
    }
    if (Array.isArray(item)) {
      return `[${item.map((value) => visit(value, depth + 1)).join(",")}]`;
    }
    if (
      item === null ||
      typeof item !== "object" ||
      (Object.getPrototypeOf(item) !== Object.prototype &&
        Object.getPrototypeOf(item) !== null) ||
      Reflect.ownKeys(item).length !== Object.keys(item).length
    ) {
      throw new GuardianGuardError("canonicalization_invalid");
    }
    return `{${Object.keys(item).sort().map((key) => {
      assertScalarString(key);
      const descriptor = Object.getOwnPropertyDescriptor(item, key);
      if (!descriptor?.enumerable || !("value" in descriptor)) {
        throw new GuardianGuardError("canonicalization_invalid");
      }
      return `${JSON.stringify(key)}:${visit(descriptor.value, depth + 1)}`;
    }).join(",")}}`;
  };
  return visit(value, 0);
}

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function canonicalTimestamp(value) {
  if (typeof value !== "string") return false;
  const date = new Date(value);
  return Number.isFinite(date.getTime()) && date.toISOString() === value;
}

function resolvePublicKey(keyId, trustedKeys, signedAt) {
  if (!KEY_ID.test(keyId)) return { error: "unknown_key" };
  const configured = trustedKeys instanceof Map
    ? trustedKeys.get(keyId)
    : trustedKeys?.[keyId];
  if (!configured) return { error: "unknown_key" };
  let source = configured;
  if (
    configured &&
    typeof configured === "object" &&
    !("type" in configured) &&
    "publicKey" in configured
  ) {
    const { publicKey, validFrom, validUntil, revokedAt, status } = configured;
    if (
      !canonicalTimestamp(validFrom) ||
      !["active", "retired", "revoked"].includes(status) ||
      (validUntil !== undefined && !canonicalTimestamp(validUntil)) ||
      (revokedAt !== undefined && !canonicalTimestamp(revokedAt)) ||
      (status === "retired" && validUntil === undefined) ||
      (status === "revoked" && revokedAt === undefined) ||
      (status !== "revoked" && revokedAt !== undefined)
    ) {
      return { error: "trusted_key_invalid" };
    }
    const signedTime = Date.parse(signedAt);
    if (
      signedTime < Date.parse(validFrom) ||
      (validUntil !== undefined && signedTime >= Date.parse(validUntil))
    ) {
      return { error: "key_not_valid_at_signing_time" };
    }
    if (status === "revoked" && signedTime >= Date.parse(revokedAt)) {
      return { error: "key_revoked_at_signing_time" };
    }
    source = publicKey;
  }
  try {
    const key = source?.type === "public"
      ? source
      : createPublicKey(source);
    if (key.asymmetricKeyType !== "ed25519" || key.type !== "public") {
      return { error: "trusted_key_invalid" };
    }
    return { key };
  } catch {
    return { error: "trusted_key_invalid" };
  }
}

export function verifyApprovalReceiptOffline(
  receipt,
  trustedKeys,
  expected,
  verificationTime = new Date(),
) {
  if (!(verificationTime instanceof Date) || !Number.isFinite(verificationTime.getTime())) {
    return { valid: false, code: "receipt_invalid" };
  }
  if (
    !hasExactKeys(receipt, ["payload", "payloadSha256", "signature"]) ||
    !hasExactKeys(receipt.payload, RECEIPT_FIELDS)
  ) {
    return { valid: false, code: "receipt_invalid" };
  }
  const payload = receipt.payload;
  if (
    payload.version !== 1 ||
    !KEY_ID.test(payload.keyId) ||
    ![payload.receiptId, payload.workspaceId, payload.approvalId, payload.requestedBy, payload.approvedBy]
      .every((value) => typeof value === "string" && value.length > 0) ||
    payload.requestedBy === payload.approvedBy ||
    !SHA256.test(payload.proposalBindingSha256) ||
    !SHA256.test(payload.actionSha256) ||
    !["owner", "admin"].includes(payload.approvedByRole) ||
    !canonicalTimestamp(payload.issuedAt) ||
    !canonicalTimestamp(payload.expiresAt) ||
    Date.parse(payload.issuedAt) >= Date.parse(payload.expiresAt) ||
    typeof payload.nonce !== "string" ||
    !/^[A-Za-z0-9_-]{32,128}$/.test(payload.nonce)
  ) {
    return { valid: false, code: "receipt_invalid" };
  }
  const resolution = resolvePublicKey(payload.keyId, trustedKeys, payload.issuedAt);
  if (resolution.error) return { valid: false, code: resolution.error };
  let signingBytes;
  try {
    signingBytes = Buffer.from(`${RECEIPT_DOMAIN}${canonicalizeV1(payload)}`, "utf8");
  } catch (error) {
    return {
      valid: false,
      code: error instanceof GuardianGuardError
        ? error.code
        : "canonicalization_invalid",
    };
  }
  const expectedDigest = digest(signingBytes);
  if (!SHA256.test(receipt.payloadSha256) || expectedDigest !== receipt.payloadSha256) {
    return { valid: false, code: "receipt_hash_mismatch" };
  }
  if (typeof receipt.signature !== "string" || !BASE64URL.test(receipt.signature)) {
    return { valid: false, code: "receipt_signature_invalid" };
  }
  const signature = Buffer.from(receipt.signature, "base64url");
  if (
    signature.length !== 64 ||
    signature.toString("base64url") !== receipt.signature ||
    !cryptoVerify(null, signingBytes, resolution.key, signature)
  ) {
    return { valid: false, code: "receipt_signature_invalid" };
  }
  for (const key of [
    "workspaceId",
    "approvalId",
    "proposalBindingSha256",
    "actionSha256",
    "requestedBy",
    "approvedBy",
    "approvedByRole",
  ]) {
    if (payload[key] !== expected?.[key]) {
      return { valid: false, code: "receipt_reference_mismatch" };
    }
  }
  if (verificationTime.getTime() >= Date.parse(payload.expiresAt)) {
    return { valid: false, code: "receipt_expired" };
  }
  if (Date.parse(payload.issuedAt) > verificationTime.getTime()) {
    return { valid: false, code: "receipt_invalid" };
  }
  return { valid: true, code: "ok" };
}

export function hashActionArguments(actionType, args) {
  if (typeof actionType !== "string" || actionType.length < 1) {
    throw new GuardianGuardError("action_invalid");
  }
  const argumentsSha256 = digest(Buffer.from(canonicalizeV1(args), "utf8"));
  return {
    argumentsSha256,
    actionSha256: digest(Buffer.from(
      canonicalizeV1({ actionType, argumentsSha256 }),
      "utf8",
    )),
  };
}

function smtpResponseLine(socket, state) {
  return new Promise((resolve, reject) => {
    const consume = () => {
      const index = state.buffer.indexOf("\n");
      if (index < 0) return;
      const line = state.buffer.slice(0, index).replace(/\r$/, "");
      state.buffer = state.buffer.slice(index + 1);
      resolve(line);
    };
    const onData = (chunk) => {
      state.buffer += chunk.toString("utf8");
      consume();
    };
    const onError = (error) => {
      socket.off("data", onData);
      reject(error);
    };
    socket.on("data", onData);
    socket.once("error", onError);
    const originalResolve = resolve;
    resolve = (line) => {
      socket.off("data", onData);
      socket.off("error", onError);
      originalResolve(line);
    };
    consume();
  });
}

async function smtpResponse(socket, state, expectedCode) {
  let lastLine = "";
  for (;;) {
    lastLine = await smtpResponseLine(socket, state);
    if (!/^[0-9]{3}[ -]/.test(lastLine)) {
      throw new GuardianGuardError("sandbox_smtp_protocol_error");
    }
    if (lastLine[3] === " ") break;
  }
  if (Number(lastLine.slice(0, 3)) !== expectedCode) {
    throw new GuardianGuardError("sandbox_smtp_rejected");
  }
}

function smtpCommand(socket, command) {
  socket.write(`${command}\r\n`);
}

async function sendSandboxEmail({ to, port, credential }) {
  if (
    !SANDBOX_EMAIL.test(to) ||
    !Number.isInteger(port) ||
    port < 1024 ||
    port > 65535
  ) {
    throw new GuardianGuardError("sandbox_target_invalid");
  }
  if (typeof credential !== "string" || !GUARD_CREDENTIAL.test(credential)) {
    throw new GuardianGuardError("sandbox_guard_credential_invalid");
  }
  const socket = connect({ host: "127.0.0.1", port });
  const state = { buffer: "" };
  await new Promise((resolve, reject) => {
    socket.once("connect", resolve);
    socket.once("error", reject);
  });
  try {
    await smtpResponse(socket, state, 220);
    smtpCommand(socket, "EHLO guardian-nexus.local");
    await smtpResponse(socket, state, 250);
    smtpCommand(socket, "AUTH PLAIN");
    await smtpResponse(socket, state, 334);
    const authPayload = Buffer.from(
      `\0guardian-guard\0${credential}`,
      "utf8",
    ).toString("base64");
    smtpCommand(socket, authPayload);
    await smtpResponse(socket, state, 235);
    smtpCommand(socket, "MAIL FROM:<guardian-demo@localhost.invalid>");
    await smtpResponse(socket, state, 250);
    smtpCommand(socket, `RCPT TO:<${to}>`);
    await smtpResponse(socket, state, 250);
    smtpCommand(socket, "DATA");
    await smtpResponse(socket, state, 354);
    const message = [
      `To: ${to}`,
      "From: guardian-demo@localhost.invalid",
      "Subject: [DEMO] Guardian Nexus local capture",
      "MIME-Version: 1.0",
      "Content-Type: text/plain; charset=utf-8",
      "",
      "[SYNTHETIC] Mensaje de prueba de Guardian Nexus. Capturado localmente; no se entrega a un proveedor externo.",
    ].join("\r\n").replace(/^\./gm, "..");
    socket.write(`${message}\r\n.\r\n`);
    await smtpResponse(socket, state, 250);
    smtpCommand(socket, "QUIT");
    await smtpResponse(socket, state, 221);
  } finally {
    socket.end();
  }
}

export async function executeGuardedSandboxAction({
  apiBaseUrl,
  requestHeaders = {},
  receipt,
  trustedKeys,
  expected,
  action,
  sandboxSmtp,
  fetchImpl = globalThis.fetch,
  verificationTime = new Date(),
}) {
  if (
    action?.actionType !== "guardian.email.send.external.v1" ||
    action?.args?.template_id !== "guardian-demo-email-v1" ||
    typeof action?.args?.to !== "string" ||
    !SANDBOX_EMAIL.test(action.args.to)
  ) {
    throw new GuardianGuardError("action_not_supported");
  }
  if (
    !Number.isInteger(sandboxSmtp?.port) ||
    sandboxSmtp.port < 1024 ||
    sandboxSmtp.port > 65535
  ) {
    throw new GuardianGuardError("sandbox_target_invalid");
  }
  if (
    typeof sandboxSmtp.credential !== "string" ||
    !GUARD_CREDENTIAL.test(sandboxSmtp.credential)
  ) {
    throw new GuardianGuardError("sandbox_guard_credential_invalid");
  }
  const hashes = hashActionArguments(action.actionType, action.args);
  const verification = verifyApprovalReceiptOffline(
    receipt,
    trustedKeys,
    { ...expected, actionSha256: hashes.actionSha256 },
    verificationTime,
  );
  if (!verification.valid) throw new GuardianGuardError(verification.code);
  let base;
  try {
    base = new URL(apiBaseUrl);
  } catch {
    throw new GuardianGuardError("ledger_url_invalid");
  }
  if (
    !["http:", "https:"].includes(base.protocol) ||
    base.username ||
    base.password ||
    typeof fetchImpl !== "function"
  ) {
    throw new GuardianGuardError("ledger_url_invalid");
  }
  const url = new URL(
    `/api/workspaces/${encodeURIComponent(expected.workspaceId)}` +
      `/ai-security-assessments/approvals/${encodeURIComponent(expected.approvalId)}` +
      "/receipt/consume",
    base,
  );
  let response;
  try {
    response = await fetchImpl(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...requestHeaders,
      },
      body: JSON.stringify({ receipt }),
    });
  } catch {
    throw new GuardianGuardError("ledger_unavailable");
  }
  if (!response.ok) {
    throw new GuardianGuardError(
      response.status === 409 ? "receipt_rejected" : "ledger_unavailable",
    );
  }
  let consumed;
  try {
    consumed = await response.json();
  } catch {
    throw new GuardianGuardError("ledger_unavailable");
  }
  if (
    consumed?.consumed !== true ||
    consumed.receiptId !== receipt.payload.receiptId ||
    !SHA256.test(consumed.consumedEventSha256)
  ) {
    throw new GuardianGuardError("ledger_unavailable");
  }
  await sendSandboxEmail({
    to: action.args.to,
    port: sandboxSmtp?.port,
    credential: sandboxSmtp?.credential,
  });
  return {
    executed: true,
    mode: "local_smtp_capture_only",
    receiptId: receipt.payload.receiptId,
    consumedEventSha256: consumed.consumedEventSha256,
    actionSha256: hashes.actionSha256,
    externalEffect: false,
  };
}
