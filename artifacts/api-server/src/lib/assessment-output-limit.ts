export type AssessmentOutputLimitState = {
  bytesReceived: number;
  exceeded: boolean;
};

export function createAssessmentOutputLimit(
  maxBytes: number,
  onExceeded: () => void,
): { recordChunk: (chunkBytes: number) => AssessmentOutputLimitState } {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) {
    throw new Error("invalid_assessment_output_limit");
  }

  let bytesReceived = 0;
  let exceeded = false;

  return {
    recordChunk(chunkBytes) {
      if (!Number.isSafeInteger(chunkBytes) || chunkBytes < 0) {
        throw new Error("invalid_assessment_output_chunk");
      }
      if (exceeded) return { bytesReceived: maxBytes + 1, exceeded: true };

      bytesReceived += chunkBytes;
      if (bytesReceived > maxBytes) {
        bytesReceived = maxBytes + 1;
        exceeded = true;
        onExceeded();
      }
      return { bytesReceived, exceeded };
    },
  };
}

export type AssessmentOutputCapture = {
  recordChunk: (chunk: Buffer) => void;
  readonly bytesReceived: number;
  readonly exceeded: boolean;
  readonly output: string;
};

export function createAssessmentOutputCapture(
  maxBytes: number,
  onExceeded: () => void,
): AssessmentOutputCapture {
  const limit = createAssessmentOutputLimit(maxBytes, onExceeded);
  let output = "";
  let bytesReceived = 0;
  let exceeded = false;

  return {
    recordChunk(chunk) {
      const state = limit.recordChunk(chunk.byteLength);
      bytesReceived = state.bytesReceived;
      exceeded = state.exceeded;
      if (!state.exceeded) output += chunk.toString("utf8");
    },
    get bytesReceived() {
      return bytesReceived;
    },
    get exceeded() {
      return exceeded;
    },
    get output() {
      return output;
    },
  };
}

export type AssessmentTimeout = {
  readonly timedOut: boolean;
  cancel: () => void;
};

export function createAssessmentTimeout(
  timeoutMs: number,
  onTimeout: () => void,
): AssessmentTimeout {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
    throw new Error("invalid_assessment_timeout");
  }

  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    try {
      onTimeout();
    } catch {
      // The timeout remains a failure even if the best-effort stop request fails.
    }
  }, timeoutMs);

  return {
    get timedOut() {
      return timedOut;
    },
    cancel() {
      clearTimeout(timer);
    },
  };
}

export function classifyAssessmentExecutionFailure(input: {
  timedOut: boolean;
  outputExceeded: boolean;
  exitCode: number | null;
}): "worker_timeout" | "worker_output_limit_exceeded" | "container_execution_failed" | null {
  if (input.timedOut) return "worker_timeout";
  if (input.outputExceeded) return "worker_output_limit_exceeded";
  if (input.exitCode !== 0) return "container_execution_failed";
  return null;
}
