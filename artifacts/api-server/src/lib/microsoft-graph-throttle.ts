export function parseRetryAfterMs(
  retryAfter: string | null,
  nowMs = Date.now(),
): number | null {
  if (retryAfter === null) return null;
  const value = retryAfter.trim();
  if (!value) return null;

  if (/^\d+(?:\.\d+)?$/.test(value)) {
    return Math.max(0, Math.ceil(Number(value) * 1000));
  }

  const retryAt = Date.parse(value);
  return Number.isFinite(retryAt) ? Math.max(0, retryAt - nowMs) : null;
}

export async function microsoftGraphGetWithRetry(
  url: string,
  accessToken: string,
  options: {
    fetchImpl?: typeof fetch;
    sleep?: (milliseconds: number) => Promise<void>;
    maxRetries?: number;
    maxInlineWaitMs?: number;
    now?: () => number;
  } = {},
): Promise<Response> {
  const target = new URL(url);
  if (
    target.protocol !== "https:" ||
    target.hostname !== "graph.microsoft.com" ||
    !target.pathname.startsWith("/v1.0/")
  ) {
    throw new Error("Microsoft Graph reader only permits HTTPS v1.0 Graph URLs.");
  }

  const fetchImpl = options.fetchImpl ?? fetch;
  const sleep =
    options.sleep ??
    ((milliseconds: number) =>
      new Promise<void>((resolve) => setTimeout(resolve, milliseconds)));
  const maxRetries = options.maxRetries ?? 3;
  const maxInlineWaitMs = options.maxInlineWaitMs ?? 60_000;

  for (let attempt = 0; ; attempt += 1) {
    const response = await fetchImpl(target, {
      method: "GET",
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (response.status !== 429 || attempt >= maxRetries) return response;

    const retryAfter = parseRetryAfterMs(
      response.headers.get("Retry-After"),
      options.now?.() ?? Date.now(),
    );
    const delay =
      retryAfter ?? Math.min(30_000, 250 * 2 ** attempt);

    // Do not retry early when the server asks for a long wait. A durable job
    // queue should reschedule that request instead of holding an API worker.
    if (delay > maxInlineWaitMs) return response;
    await sleep(delay);
  }
}
