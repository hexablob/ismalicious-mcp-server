/** Tests for capResult's generic shrinking and its list-aware mode. */
import { describe, expect, it } from "vitest";
import { capResult } from "../cap.js";

const bytes = (v: unknown) => Buffer.byteLength(JSON.stringify(v));

describe("capResult", () => {
  it("returns a result under the ceiling untouched", () => {
    const value = { rows: [1, 2, 3] };
    expect(capResult(value, 1_000, { field: "rows" })).toBe(value);
  });

  it("without the list opt-in still clips arrays (the pre-0.3.2 behaviour)", () => {
    const rows = Array.from({ length: 50 }, (_, i) => ({ id: `row-${i}` }));
    const capped = capResult({ rows }, 600) as { rows: unknown[] };
    expect(capped.rows.length).toBeLessThanOrEqual(5);
  });

  it("with it, drops whole tail rows and describes both halves", () => {
    const rows = Array.from({ length: 50 }, (_, i) => ({
      id: `row-${i}`,
      bad: i % 2 === 0,
    }));
    const capped = capResult({ total: 50, rows }, 900, {
      field: "rows",
      describe: (kept, omitted) => ({
        badKept: kept.filter((r) => (r as { bad: boolean }).bad).length,
        badOmitted: omitted.filter((r) => (r as { bad: boolean }).bad).length,
      }),
    }) as Record<string, unknown> & { rows: { id: string }[] };
    expect(bytes(capped)).toBeLessThanOrEqual(900);
    expect(capped.rows.length).toBeGreaterThan(5);
    expect(capped.rows).toEqual(rows.slice(0, capped.rows.length));
    expect(capped.returned).toBe(capped.rows.length);
    expect(capped.omitted).toBe(50 - capped.rows.length);
    expect(capped.total).toBe(50);
    expect((capped.badKept as number) + (capped.badOmitted as number)).toBe(25);
    // The largest fit: one more row would not.
    expect(
      bytes({ ...capped, rows: rows.slice(0, capped.rows.length + 1) }),
    ).toBeGreaterThan(900);
  });

  it("falls back to generic shrinking when the other fields alone are too big", () => {
    const capped = capResult(
      { blurb: "x".repeat(5_000), rows: [{ id: 1 }] },
      300,
      { field: "rows" },
    ) as { truncated: boolean };
    expect(capped.truncated).toBe(true);
    expect(bytes(capped)).toBeLessThanOrEqual(300);
  });
});
