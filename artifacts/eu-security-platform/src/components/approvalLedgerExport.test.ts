import assert from "node:assert/strict";
import { test } from "node:test";
import {
  customFetch,
  setAuthTokenGetter,
} from "@workspace/api-client-react";
import {
  approvalLedgerExportFailureMessage,
  requestAndDownloadApprovalLedgerBundle,
} from "./approvalLedgerExport";

async function withMockedFetch<T>(
  mock: typeof fetch,
  run: () => Promise<T>,
): Promise<T> {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = mock;
  setAuthTokenGetter(null);
  try {
    return await run();
  } finally {
    globalThis.fetch = originalFetch;
    setAuthTokenGetter(null);
  }
}

test("ledger export distinguishes a rejected network request from an HTTP response", async () => {
  const failure = await withMockedFetch(
    async () => {
      throw new TypeError("private network detail");
    },
    () =>
      requestAndDownloadApprovalLedgerBundle(
        () => customFetch("/api/test"),
        () => assert.fail("download must not run after a failed request"),
      ),
  );
  assert.deepEqual(failure, {
    ok: false,
    failure: { kind: "network" },
  });
  assert.match(
    approvalLedgerExportFailureMessage({ kind: "network" }),
    /No se recibió una respuesta HTTP/,
  );
});

test("ledger export classifies request construction and auth setup exceptions as client errors", async () => {
  let fetchCalled = false;
  const failure = await withMockedFetch(
    async () => {
      fetchCalled = true;
      return new Response("{}");
    },
    () =>
      requestAndDownloadApprovalLedgerBundle(
        async () => {
          // Mirrors generated-client JSON serialization or a token getter failing
          // before customFetch invokes the browser's fetch implementation.
          throw new TypeError("private client detail");
        },
        () => assert.fail("download must not run after a failed request"),
      ),
  );
  assert.equal(fetchCalled, false);
  assert.deepEqual(failure, {
    ok: false,
    failure: { kind: "client" },
  });
  assert.doesNotMatch(
    approvalLedgerExportFailureMessage({ kind: "client" }),
    /private client detail/,
  );
});

test("ledger export reports HTTP limits and malformed responses separately", async () => {
  const httpFailure = await withMockedFetch(
    async () =>
      new Response(JSON.stringify({ error: "bounded response" }), {
        status: 413,
        headers: { "content-type": "application/json" },
      }),
    () =>
      requestAndDownloadApprovalLedgerBundle(
        () => customFetch("/api/test", { method: "POST", body: "{}" }),
        () => assert.fail("download must not run after an HTTP error"),
      ),
  );
  assert.deepEqual(httpFailure, {
    ok: false,
    failure: { kind: "http", status: 413 },
  });
  assert.equal(
    approvalLedgerExportFailureMessage({ kind: "http", status: 413 }),
    "La API respondió con HTTP 413.",
  );

  const clientFailure = await withMockedFetch(
    async () =>
      new Response("not-json", {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    () =>
      requestAndDownloadApprovalLedgerBundle(
        () => customFetch("/api/test", { responseType: "json" }),
        () => assert.fail("download must not run after an unreadable response"),
      ),
  );
  assert.deepEqual(clientFailure, {
    ok: false,
    failure: { kind: "client" },
  });
});

test("ledger export reports a browser download failure only after the request succeeds", async () => {
  let downloadAttempted = false;
  const failure = await withMockedFetch(
    async () =>
      new Response(JSON.stringify({ version: 1 }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    () =>
      requestAndDownloadApprovalLedgerBundle(
        () => customFetch<{ version: number }>("/api/test"),
        () => {
          downloadAttempted = true;
          throw new Error("private browser detail");
        },
      ),
  );
  assert.equal(downloadAttempted, true);
  assert.deepEqual(failure, {
    ok: false,
    failure: { kind: "download" },
  });
  assert.match(
    approvalLedgerExportFailureMessage({ kind: "download" }),
    /el navegador no pudo iniciar la descarga/,
  );
});

test("ledger export keeps successful bundle data intact for the download callback", async () => {
  const bundle = { version: 1, events: [], receipts: [] };
  let downloaded: unknown;
  const result = await requestAndDownloadApprovalLedgerBundle(
    async () => bundle,
    (value) => {
      downloaded = value;
    },
  );
  assert.deepEqual(result, { ok: true });
  assert.equal(downloaded, bundle);
});
