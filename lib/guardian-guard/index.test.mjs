import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  sign,
  timingSafeEqual,
} from "node:crypto";
import { createServer as createHttpServer } from "node:http";
import { connect as connectTcp, createServer as createTcpServer } from "node:net";
import { once } from "node:events";
import { test } from "node:test";
import {
  executeGuardedSandboxAction,
  hashActionArguments,
  verifyApprovalReceiptOffline,
} from "./index.mjs";

const domain = "guardian-nexus:approval-receipt:v1\n";
const now = new Date("2026-05-04T12:00:01.000Z");
const context = {
  workspaceId: "11111111-1111-4111-8111-111111111111",
  approvalId: "22222222-2222-4222-8222-222222222222",
  proposalBindingSha256: "a".repeat(64),
  requestedBy: "synthetic-agent",
  approvedBy: "synthetic-admin",
  approvedByRole: "admin",
};
const action = {
  actionType: "guardian.email.send.external.v1",
  args: {
    to: "qa@example.test",
    template_id: "guardian-demo-email-v1",
  },
};
const guardCredential = randomBytes(32).toString("base64url");

function canonical(value) {
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return String(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) =>
    `${JSON.stringify(key)}:${canonical(value[key])}`,
  ).join(",")}}`;
}

function signedReceipt(pair, overrides = {}) {
  const payload = {
    version: 1,
    keyId: "demo-ledger-key",
    receiptId: "33333333-3333-4333-8333-333333333333",
    ...context,
    actionSha256: hashActionArguments(action.actionType, action.args).actionSha256,
    issuedAt: "2026-05-04T12:00:00.000Z",
    expiresAt: "2026-05-04T12:05:00.000Z",
    nonce: "A".repeat(43),
    ...overrides,
  };
  const bytes = Buffer.from(`${domain}${canonical(payload)}`, "utf8");
  return {
    payload,
    payloadSha256: createHash("sha256").update(bytes).digest("hex"),
    signature: sign(null, bytes, pair.privateKey).toString("base64url"),
  };
}

async function startSmtpCapture(credential = guardCredential) {
  const captured = [];
  const expectedAuth = Buffer.from(`\0guardian-guard\0${credential}`, "utf8");
  const server = createTcpServer((socket) => {
    let buffer = "";
    let dataMode = false;
    let awaitingAuth = false;
    let authenticated = false;
    let message = [];
    socket.write("220 local capture ready\r\n");
    socket.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      for (;;) {
        const newline = buffer.indexOf("\n");
        if (newline < 0) break;
        const line = buffer.slice(0, newline).replace(/\r$/, "");
        buffer = buffer.slice(newline + 1);
        if (dataMode) {
          if (line === ".") {
            dataMode = false;
            captured.push(message.join("\r\n"));
            message = [];
            socket.write("250 captured locally\r\n");
          } else {
            message.push(line.startsWith("..") ? line.slice(1) : line);
          }
          continue;
        }
        if (awaitingAuth) {
          awaitingAuth = false;
          const decoded = Buffer.from(line, "base64");
          const valid =
            decoded.toString("base64") === line &&
            decoded.length === expectedAuth.length &&
            timingSafeEqual(decoded, expectedAuth);
          if (!valid) {
            socket.write("535 invalid guard credential\r\n");
            continue;
          }
          authenticated = true;
          socket.write("235 guard authenticated\r\n");
          continue;
        }
        if (line.startsWith("EHLO ")) socket.write("250 local capture\r\n");
        else if (line === "AUTH PLAIN") {
          awaitingAuth = true;
          socket.write("334 provide guard credential\r\n");
        } else if (!authenticated) socket.write("530 guard authentication required\r\n");
        else if (line.startsWith("MAIL FROM:")) socket.write("250 sender accepted\r\n");
        else if (line.startsWith("RCPT TO:")) socket.write("250 recipient accepted\r\n");
        else if (line === "DATA") {
          dataMode = true;
          socket.write("354 end with dot\r\n");
        } else if (line === "QUIT") {
          socket.write("221 bye\r\n");
        } else {
          socket.write("500 unsupported\r\n");
        }
      }
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  return { server, port: address.port, captured };
}

async function attemptDirectSmtpWithoutGuardCredential(port) {
  const socket = connectTcp({ host: "127.0.0.1", port });
  let buffer = "";
  const nextLine = () => new Promise((resolveLine, reject) => {
    const onData = (chunk) => {
      buffer += chunk.toString("utf8");
      const newline = buffer.indexOf("\n");
      if (newline < 0) return;
      const line = buffer.slice(0, newline).replace(/\r$/, "");
      buffer = buffer.slice(newline + 1);
      socket.off("data", onData);
      socket.off("error", onError);
      resolveLine(line);
    };
    const onError = (error) => {
      socket.off("data", onData);
      reject(error);
    };
    socket.on("data", onData);
    socket.once("error", onError);
  });
  await once(socket, "connect");
  try {
    assert.match(await nextLine(), /^220\b/);
    socket.write("EHLO direct-agent.local\r\n");
    assert.match(await nextLine(), /^250\b/);
    socket.write("MAIL FROM:<agent@localhost.invalid>\r\n");
    return await nextLine();
  } finally {
    socket.end();
  }
}

async function startConsumeApi() {
  let used = false;
  const received = [];
  const server = createHttpServer((request, response) => {
    let body = "";
    request.on("data", (chunk) => { body += chunk.toString("utf8"); });
    request.on("end", () => {
      received.push(JSON.parse(body));
      if (used) {
        response.writeHead(409, { "content-type": "application/json" });
        response.end('{"error":"already consumed"}');
        return;
      }
      used = true;
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({
        consumed: true,
        receiptId: received[0].receipt.payload.receiptId,
        consumedEventSha256: "b".repeat(64),
      }));
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  return { server, baseUrl: `http://127.0.0.1:${address.port}`, received };
}

function guardInput({ receipt, key, apiBaseUrl, smtpPort, actionValue = action }) {
  return {
    apiBaseUrl,
    requestHeaders: { "x-guardian-test-user": context.approvedBy },
    receipt,
    trustedKeys: { "demo-ledger-key": key },
    expected: { ...context, actionSha256: receipt.payload.actionSha256 },
    action: actionValue,
    sandboxSmtp: { port: smtpPort, credential: guardCredential },
    verificationTime: now,
  };
}

test("guard verifies offline, consumes once, and sends only to the local SMTP capture", async (t) => {
  const pair = generateKeyPairSync("ed25519");
  const receipt = signedReceipt(pair);
  const smtp = await startSmtpCapture();
  const api = await startConsumeApi();
  t.after(async () => {
    await Promise.all([
      new Promise((resolve) => smtp.server.close(resolve)),
      new Promise((resolve) => api.server.close(resolve)),
    ]);
  });
  assert.match(await attemptDirectSmtpWithoutGuardCredential(smtp.port), /^530\b/);
  assert.equal(smtp.captured.length, 0, "direct access cannot reach the tool");
  const trustedKey = pair.publicKey;
  const verified = verifyApprovalReceiptOffline(
    receipt,
    { "demo-ledger-key": trustedKey },
    { ...context, actionSha256: receipt.payload.actionSha256 },
    now,
  );
  assert.deepEqual(verified, { valid: true, code: "ok" });

  const result = await executeGuardedSandboxAction(
    guardInput({
      receipt,
      key: trustedKey,
      apiBaseUrl: api.baseUrl,
      smtpPort: smtp.port,
    }),
  );
  assert.equal(result.executed, true);
  assert.equal(result.mode, "local_smtp_capture_only");
  assert.equal(result.externalEffect, false);
  assert.equal(api.received.length, 1);
  assert.match(smtp.captured[0], /To: qa@example\.test/);
  assert.match(smtp.captured[0], /\[SYNTHETIC\]/);

  await assert.rejects(
    executeGuardedSandboxAction(
      guardInput({
        receipt,
        key: trustedKey,
        apiBaseUrl: api.baseUrl,
        smtpPort: smtp.port,
      }),
    ),
    (error) => error.code === "receipt_rejected",
  );
  assert.equal(api.received.length, 2);
  assert.equal(smtp.captured.length, 1);
});

test("guard rejects another action, altered arguments, expired receipts and untrusted keys before consumption", async (t) => {
  const pair = generateKeyPairSync("ed25519");
  const other = generateKeyPairSync("ed25519");
  const receipt = signedReceipt(pair);
  const api = await startConsumeApi();
  t.after(() => new Promise((resolve) => api.server.close(resolve)));
  const common = guardInput({
    receipt,
    key: pair.publicKey,
    apiBaseUrl: api.baseUrl,
    smtpPort: 2525,
  });

  await assert.rejects(
    executeGuardedSandboxAction({
      ...common,
      sandboxSmtp: { ...common.sandboxSmtp, credential: "" },
    }),
    (error) => error.code === "sandbox_guard_credential_invalid",
  );
  await assert.rejects(
    executeGuardedSandboxAction({
      ...common,
      expected: { ...context, workspaceId: "99999999-9999-4999-8999-999999999999" },
    }),
    (error) => error.code === "receipt_reference_mismatch",
  );
  const alteredSignature = {
    ...receipt,
    signature: `${receipt.signature[0] === "A" ? "B" : "A"}${receipt.signature.slice(1)}`,
  };
  assert.notEqual(alteredSignature.signature, receipt.signature);
  await assert.rejects(
    executeGuardedSandboxAction({ ...common, receipt: alteredSignature }),
    (error) => error.code === "receipt_signature_invalid",
  );

  await assert.rejects(
    executeGuardedSandboxAction({
      ...common,
      action: { actionType: "guardian.support.reply.send.v1", args: {} },
    }),
    (error) => error.code === "action_not_supported",
  );
  await assert.rejects(
    executeGuardedSandboxAction({
      ...common,
      action: { ...action, args: { ...action.args, to: "other@example.test" } },
    }),
    (error) => error.code === "receipt_reference_mismatch",
  );
  await assert.rejects(
    executeGuardedSandboxAction({
      ...common,
      trustedKeys: { "demo-ledger-key": other.publicKey },
    }),
    (error) => error.code === "receipt_signature_invalid",
  );
  const expired = signedReceipt(pair, { expiresAt: "2026-05-04T12:00:00.500Z" });
  await assert.rejects(
    executeGuardedSandboxAction({
      ...common,
      receipt: expired,
    }),
    (error) => error.code === "receipt_expired",
  );
  assert.equal(api.received.length, 0);
});

test("concurrent reuse of one receipt consumes it once and captures one message", async (t) => {
  const pair = generateKeyPairSync("ed25519");
  const receipt = signedReceipt(pair);
  const smtp = await startSmtpCapture();
  const api = await startConsumeApi();
  t.after(async () => {
    await Promise.all([
      new Promise((resolve) => smtp.server.close(resolve)),
      new Promise((resolve) => api.server.close(resolve)),
    ]);
  });
  const input = guardInput({
    receipt,
    key: pair.publicKey,
    apiBaseUrl: api.baseUrl,
    smtpPort: smtp.port,
  });
  const outcomes = await Promise.allSettled([
    executeGuardedSandboxAction(input),
    executeGuardedSandboxAction(input),
  ]);
  const successes = outcomes.filter((outcome) => outcome.status === "fulfilled");
  const failures = outcomes.filter((outcome) => outcome.status === "rejected");
  assert.equal(successes.length, 1);
  assert.equal(failures.length, 1);
  assert.equal(failures[0].reason.code, "receipt_rejected");
  assert.equal(api.received.length, 2);
  assert.equal(smtp.captured.length, 1);
});

test("guard fails closed when the consume ledger cannot be reached", async () => {
  const pair = generateKeyPairSync("ed25519");
  const receipt = signedReceipt(pair);
  await assert.rejects(
    executeGuardedSandboxAction(
      guardInput({
        receipt,
        key: pair.publicKey,
        apiBaseUrl: "http://127.0.0.1:1",
        smtpPort: 2525,
      }),
    ),
    (error) => error.code === "ledger_unavailable",
  );
});

test("guard refuses unsupported SMTP hosts and port values", async () => {
  const pair = generateKeyPairSync("ed25519");
  const receipt = signedReceipt(pair);
  const api = await startConsumeApi();
  try {
    const invalidAction = { ...action, args: { ...action.args, to: "qa@example.com" } };
    await assert.rejects(
      executeGuardedSandboxAction(
        guardInput({
          receipt,
          key: pair.publicKey,
          apiBaseUrl: api.baseUrl,
          smtpPort: 2525,
          actionValue: invalidAction,
        }),
      ),
      (error) => error.code === "action_not_supported",
    );
    assert.equal(api.received.length, 0);
  } finally {
    await new Promise((resolve) => api.server.close(resolve));
  }
});
