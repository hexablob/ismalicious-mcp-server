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

/**
 * Opt-in for list-shaped results (`check_indicators`, `search_indicators`).
 * The generic steps below cut every array to 5 items, which turned a
 * 100-row batch — billed 100 requests — into 5 rows (measured 2026-09-30).
 * With this, whole rows are dropped from the end of `field` until the result
 * fits, the rest of the result is left alone, and the result says how many
 * rows it kept and dropped.
 */
export interface ListCap {
  /** The top-level array whose tail rows may be dropped. */
  field: string;
  /**
   * Extra top-level fields computed over the kept and dropped rows, e.g. how
   * many of the dropped rows were malicious. Tool-supplied totals (computed
   * over every row before the cap) are left as they are.
   */
  describe?(kept: unknown[], omitted: unknown[]): Record<string, unknown>;
}

function capList(
  value: Record<string, unknown>,
  rows: unknown[],
  maxBytes: number,
  list: ListCap,
): unknown {
  const total = rows.length;
  const candidate = (kept: number) => {
    const omitted = total - kept;
    return {
      ...value,
      ...list.describe?.(rows.slice(0, kept), rows.slice(kept)),
      returned: kept,
      omitted,
      truncated: true,
      note: `${omitted} of ${total} rows of \`${list.field}\` were dropped from the end to fit the ${maxBytes}-byte result limit; the other top-level counts cover all ${total}.`,
      [list.field]: rows.slice(0, kept),
    };
  };
  // Not even the other fields fit: nothing row-aware left to do.
  if (byteLength(candidate(0)) > maxBytes) {
    return capResult(candidate(0), maxBytes);
  }
  // Size grows with the number of rows kept: binary-search the largest fit.
  // `total` itself is known not to fit, or the cap would not have run.
  let lo = 0;
  let hi = total - 1;
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2);
    if (byteLength(candidate(mid)) <= maxBytes) lo = mid;
    else hi = mid - 1;
  }
  return candidate(lo);
}

export function capResult(
  value: unknown,
  maxBytes: number = MAX_RESULT_BYTES,
  list?: ListCap,
): unknown {
  if (byteLength(value) <= maxBytes) return value;
  if (
    list &&
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Array.isArray((value as Record<string, unknown>)[list.field]) &&
    ((value as Record<string, unknown>)[list.field] as unknown[]).length > 0
  ) {
    const record = value as Record<string, unknown>;
    return capList(record, record[list.field] as unknown[], maxBytes, list);
  }
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
