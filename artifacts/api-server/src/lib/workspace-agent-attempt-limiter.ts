type AttemptWindow = {
  startedAt: number;
  attempts: number;
};

export type WorkspaceAgentAttemptLimiter = {
  consume(key: string): {
    allowed: boolean;
    retryAfterSeconds: number;
  };
};

export function createWorkspaceAgentAttemptLimiter(input?: {
  maxAttempts?: number;
  windowMs?: number;
  now?: () => number;
}): WorkspaceAgentAttemptLimiter {
  const maxAttempts = input?.maxAttempts ?? 8;
  const windowMs = input?.windowMs ?? 60_000;
  const now = input?.now ?? Date.now;
  const windows = new Map<string, AttemptWindow>();

  if (
    !Number.isSafeInteger(maxAttempts) ||
    maxAttempts < 1 ||
    !Number.isSafeInteger(windowMs) ||
    windowMs < 1
  ) {
    throw new Error("agent_attempt_limiter_configuration_invalid");
  }

  return {
    consume(key) {
      const currentTime = now();
      let window = windows.get(key);
      if (!window || currentTime - window.startedAt >= windowMs) {
        window = { startedAt: currentTime, attempts: 0 };
        windows.set(key, window);
      }
      if (windows.size > 10_000) {
        for (const [existingKey, existingWindow] of windows) {
          if (currentTime - existingWindow.startedAt >= windowMs) {
            windows.delete(existingKey);
          }
        }
        while (windows.size > 10_000) {
          const oldestKey = windows.keys().next().value;
          if (oldestKey === undefined) break;
          windows.delete(oldestKey);
        }
      }

      if (window.attempts >= maxAttempts) {
        return {
          allowed: false,
          retryAfterSeconds: Math.max(
            1,
            Math.ceil((window.startedAt + windowMs - currentTime) / 1000),
          ),
        };
      }
      window.attempts += 1;
      return { allowed: true, retryAfterSeconds: 0 };
    },
  };
}
