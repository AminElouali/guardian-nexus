export function safeHttpRequestLog(input: {
  id?: string;
  method?: string;
  url?: string;
}): { id?: string; method?: string; url?: string } {
  return {
    ...(input.id ? { id: input.id } : {}),
    ...(input.method ? { method: input.method } : {}),
    ...(input.url ? { url: input.url.split("?", 1)[0] } : {}),
  };
}
