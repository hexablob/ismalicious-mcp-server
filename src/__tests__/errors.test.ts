import { describe, expect, it } from "vitest";
import {
  envelopeFromResponse,
  nextMonthStart,
  quotaFrom429,
} from "../errors.js";
import { response } from "./helpers.js";

const NOW = new Date("2026-09-04T12:00:00Z");

describe("quotaFrom429", () => {
  it("reads a monthly quota exhaustion from the body and resets next month", () => {
    const q = quotaFrom429(
      {
        error: "Monthly quota exceeded",
        usage: { current: 1000, limit: 1000 },
        upgradeRequired: true,
      },
      { plan: "FREE" },
      NOW,
    );
    expect(q).toMatchObject({
      kind: "monthly",
      used: 1000,
      limit: 1000,
      remaining: 0,
      plan: "FREE",
      retry_after: null,
    });
    expect(q.resets_at).toBe("2026-10-01T00:00:00.000Z");
  });

  it("reads the scan meter exhaustion", () => {
    const q = quotaFrom429(
      { error: "Scan quota exceeded", usage: 50, limit: 50 },
      {},
      NOW,
    );
    expect(q).toMatchObject({ kind: "scans", used: 50, limit: 50 });
  });

  it("reads a burst limit with the reset derived from Retry-After", () => {
    const q = quotaFrom429(
      { error: "Rate limit exceeded" },
      { retryAfterSec: 12, rateLimit: { limit: 60, remaining: 0 } },
      NOW,
    );
    expect(q).toMatchObject({
      kind: "burst",
      limit: 60,
      remaining: 0,
      retry_after: 12,
    });
    expect(q.resets_at).toBe("2026-09-04T12:00:12.000Z");
  });
});

describe("envelopeFromResponse", () => {
  it("is null for a 2xx JSON body", () => {
    expect(
      envelopeFromResponse(response(200, { a: 1 }), { keyConfigured: true }),
    ).toBeNull();
  });
  it("maps 403 and 5xx", () => {
    expect(
      envelopeFromResponse(response(403, { error: "Plan required" }), {
        keyConfigured: true,
      })?.error,
    ).toBe("forbidden");
    expect(
      envelopeFromResponse(response(502, null), { keyConfigured: true })?.error,
    ).toBe("upstream_error");
  });
  it("tells a missing key from a refused one on 401", () => {
    expect(
      envelopeFromResponse(response(401, {}), { keyConfigured: false })?.hint,
    ).toContain("No API key is configured");
    expect(
      envelopeFromResponse(response(401, {}), { keyConfigured: true })?.hint,
    ).toContain("refused");
  });
});

describe("nextMonthStart", () => {
  it("rolls over the year", () => {
    expect(nextMonthStart(new Date("2026-12-31T23:59:59Z"))).toBe(
      "2027-01-01T00:00:00.000Z",
    );
  });
});
