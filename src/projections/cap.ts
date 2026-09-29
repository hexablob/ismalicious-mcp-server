/**
 * Hard ceiling on what a tool hands back to the model.
 *
 * The projections are written to stay well under this; the cap is the
 * guarantee for the day an upstream field grows. Shrinks progressively —
 * long strings first, then arrays — and marks the result `truncated: true`
 * so the model knows it is looking at a summary.
 */

export const MAX_RESULT_BYTES = 4096;

function byteLength(value: unknown): number {
  return Buffer.byteLength(JSON.stringify(value), "utf8");
}

function clipStrings(value: unknown, max: number): unknown {
  if (typeof value === "string") {
    return value.length > max ? `${value.slice(0, max - 1)}…` : value;
  }
  if (Array.isArray(value)) return value.map((v) => clipStrings(v, max));
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = clipStrings(v, max);
    }
    return out;
  }
  return value;
}

function clipArrays(value: unknown, max: number): unknown {
  if (Array.isArray(value)) {
    return value.slice(0, max).map((v) => clipArrays(v, max));
  }
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = clipArrays(v, max);
    }
    return out;
  }
  return value;
}

export function capResult(
  value: unknown,
  maxBytes: number = MAX_RESULT_BYTES,
): unknown {
  if (byteLength(value) <= maxBytes) return value;
  const steps: Array<(v: unknown) => unknown> = [
    (v) => clipStrings(v, 400),
    (v) => clipArrays(v, 5),
    (v) => clipStrings(v, 160),
    (v) => clipArrays(v, 2),
  ];
  let current = value;
  for (const step of steps) {
    current = step(current);
    if (byteLength(current) <= maxBytes) {
      return markTruncated(current);
    }
  }
  const text = JSON.stringify(current);
  return {
    truncated: true,
    note: `Result exceeded ${maxBytes} bytes even after shrinking; preview follows.`,
    preview: text.slice(0, Math.max(0, maxBytes - 200)),
  };
}

function markTruncated(value: unknown): unknown {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return { ...(value as Record<string, unknown>), truncated: true };
  }
  return { truncated: true, value };
}
