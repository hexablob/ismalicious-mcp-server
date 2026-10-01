/** Tests for the environment rules in config.ts. */
import { describe, expect, it, vi } from "vitest";
import {
  DEFAULT_API_BASE,
  DEFAULT_WEB_BASE,
  resolveBases,
  resolveCache,
  resolvePrewarm,
  resolveTimeoutOverride,
  resolveToolTimeouts,
  toolTimeoutVariable,
} from "../config.js";
import { MCP_TOOLS } from "../tools/index.js";

describe("resolveBases", () => {
  it("defaults both bases to the web API", () => {
    expect(resolveBases({})).toEqual({
      apiBase: DEFAULT_API_BASE,
      webBase: DEFAULT_WEB_BASE,
    });
    expect(DEFAULT_API_BASE).toBe("https://ismalicious.com/api");
  });

  it("keeps bootstrap_key on the web API when the keyed base is the Rust host", () => {
    expect(
      resolveBases({ ISMALICIOUS_API_BASE: "https://api.ismalicious.com" }),
    ).toEqual({
      apiBase: "https://api.ismalicious.com",
      webBase: "https://ismalicious.com/api",
    });
  });

  it("keeps following a custom ISMALICIOUS_API_BASE, as before", () => {
    expect(
      resolveBases({ ISMALICIOUS_API_BASE: "http://127.0.0.1:4000/api" }),
    ).toEqual({
      apiBase: "http://127.0.0.1:4000/api",
      webBase: "http://127.0.0.1:4000/api",
    });
  });

  it("lets ISMALICIOUS_WEB_BASE win", () => {
    expect(
      resolveBases({
        ISMALICIOUS_API_BASE: "https://api.ismalicious.com",
        ISMALICIOUS_WEB_BASE: "https://staging.ismalicious.com/api",
      }).webBase,
    ).toBe("https://staging.ismalicious.com/api");
  });
});

describe("timeouts", () => {
  it("names one variable per tool", () => {
    expect(toolTimeoutVariable("check_indicator")).toBe(
      "ISMALICIOUS_TIMEOUT_CHECK_INDICATOR_MS",
    );
  });

  it("reads per-tool timeouts and ignores invalid ones", () => {
    const log = vi.fn();
    expect(
      resolveToolTimeouts(
        {
          ISMALICIOUS_TIMEOUT_CHECK_INDICATOR_MS: "3000",
          ISMALICIOUS_TIMEOUT_GET_CVE_MS: "-1",
          ISMALICIOUS_TIMEOUT_NOPE_MS: "5",
        },
        MCP_TOOLS,
        log,
      ),
    ).toEqual({ check_indicator: 3000 });
    expect(log).toHaveBeenCalledWith(
      "ignoring ISMALICIOUS_TIMEOUT_GET_CVE_MS=-1 (not a positive number)",
    );
  });

  it("reads the global override", () => {
    const log = vi.fn();
    expect(
      resolveTimeoutOverride({ ISMALICIOUS_TIMEOUT_MS: "8000" }, log),
    ).toBe(8000);
    expect(resolveTimeoutOverride({ ISMALICIOUS_TIMEOUT_MS: "x" }, log)).toBe(
      undefined,
    );
    expect(resolveTimeoutOverride({}, log)).toBeUndefined();
  });
});

describe("resolveCache", () => {
  it("is on by default, off at 0, a TTL ceiling otherwise", () => {
    const log = vi.fn();
    expect(resolveCache({}, log)).toEqual({});
    expect(resolveCache({ ISMALICIOUS_CACHE_TTL_S: "0" }, log)).toBe(false);
    expect(resolveCache({ ISMALICIOUS_CACHE_TTL_S: "10" }, log)).toEqual({
      maxTtlSec: 10,
    });
    expect(resolveCache({ ISMALICIOUS_CACHE_TTL_S: "soon" }, log)).toEqual({});
    expect(log).toHaveBeenCalledTimes(1);
  });
});

describe("resolvePrewarm", () => {
  it("is on unless ISMALICIOUS_PREWARM is 0", () => {
    expect(resolvePrewarm({})).toBe(true);
    expect(resolvePrewarm({ ISMALICIOUS_PREWARM: "1" })).toBe(true);
    expect(resolvePrewarm({ ISMALICIOUS_PREWARM: "0" })).toBe(false);
    expect(resolvePrewarm({ ISMALICIOUS_PREWARM: "false" })).toBe(false);
  });
});
