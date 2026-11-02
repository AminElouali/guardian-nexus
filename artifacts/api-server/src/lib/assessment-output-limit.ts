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
