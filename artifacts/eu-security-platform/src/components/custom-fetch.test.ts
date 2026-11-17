import assert from "node:assert/strict";
import { test } from "node:test";
import {
  ApiError,
  customFetch,
  FetchTransportError,
  ResponseParseError,
  setAuthTokenGetter,
} from "@workspace/api-client-react";

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

test("customFetch marks a rejected fetch as transport failure without exposing its message", async () => {
  let requestCount = 0;
  await withMockedFetch(
    async () => {
      requestCount += 1;
      throw new TypeError("private network detail sentinel");
    },
    async () => {
      await assert.rejects(
        customFetch("/api/test"),
        (error: unknown) =>
          error instanceof FetchTransportError &&
          error instanceof TypeError &&
          error.name === "TypeError" &&
          error.message === "api_transport_failed" &&
          !error.message.includes("private network detail sentinel"),
      );
    },
  );
  assert.equal(requestCount, 1);
});

test("customFetch preserves a real HTTP status for API errors", async () => {
  await withMockedFetch(
    async () =>
      new Response(JSON.stringify({ error: "bounded response" }), {
        status: 413,
        headers: { "content-type": "application/json" },
      }),
    async () => {
      await assert.rejects(
        customFetch("/api/test", { method: "POST", body: "{}" }),
        (error: unknown) =>
          error instanceof ApiError &&
          error.status === 413,
      );
    },
  );
});

test("customFetch retains the HTTP status when a successful response is not parseable", async () => {
  await withMockedFetch(
    async () =>
      new Response("not-json", {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    async () => {
      await assert.rejects(
        customFetch("/api/test", { responseType: "json" }),
        (error: unknown) =>
          error instanceof ResponseParseError &&
          error.status === 200,
      );
    },
  );
});
