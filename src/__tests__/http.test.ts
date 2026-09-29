import { afterEach, describe, expect, it, vi } from "vitest";
import {
  defaultHttpClient,
  HttpCancelledError,
  HttpNetworkError,
  HttpTimeoutError,
  parseQuotaHeaders,
} from "../http.js";
import { SERVER_VERSION } from "../version.js";

function fetchThatWaitsForAbort(): typeof fetch {
  return vi.fn(
    (_url: unknown, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () =>
          reject(Object.assign(new Error("aborted"), { name: "AbortError" })),
        );
      }),
  ) as unknown as typeof fetch;
}

function jsonResponse(
  status: number,
  body: string,
  headers: Record<string, string> = {},
) {
  return new Response(body, {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

afterEach(() => {
  vi.useRealTimers();
});

describe("parseQuotaHeaders", () => {
  it("reads burst, monthly, daily and plan headers", () => {
    const h = new Headers({
      "Retry-After": "30",
      "X-RateLimit-Limit": "60",
      "X-RateLimit-Remaining": "0",
      "X-RateLimit-Reset": "1760000000000",
      "X-RateLimit-Type": "burst",
      "X-Monthly-Usage": "990",
      "X-Monthly-Limit": "1000",
      "X-Monthly-Percentage": "99",
      "X-Daily-Usage": "4",
      "X-Daily-Limit": "5",
      "X-RateLimit-Plan": "FREE",
    });
    expect(parseQuotaHeaders(h)).toEqual({
      retryAfterSec: 30,
      rateLimit: {
        limit: 60,
        remaining: 0,
        resetMs: 1760000000000,
        type: "burst",
      },
      monthly: { usage: 990, limit: 1000, percentage: 99 },
      daily: { usage: 4, limit: 5 },
      plan: "FREE",
    });
  });

  it("returns an empty object when nothing is set", () => {
    expect(parseQuotaHeaders(new Headers())).toEqual({});
  });
});

describe("defaultHttpClient", () => {
  it("sends the identification headers and omits X-API-KEY without a key", async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse(200, '{"ok":true}'),
    ) as unknown as typeof fetch;
    const client = defaultHttpClient({
      baseUrl: "https://x/api/",
      apiKeyHeader: null,
      fetchImpl,
    });
    await client.withTool("get_cve").get("/cve?id=CVE-2021-44228");
    const [url, init] = (
      fetchImpl as unknown as { mock: { calls: [string, RequestInit][] } }
    ).mock.calls[0];
    expect(url).toBe("https://x/api/cve?id=CVE-2021-44228");
    const headers = init.headers as Record<string, string>;
    expect(headers["User-Agent"]).toBe(`ismalicious-mcp/${SERVER_VERSION}`);
    expect(headers["X-Ismalicious-Tool"]).toBe("get_cve");
    expect(headers["X-API-KEY"]).toBeUndefined();
    expect(headers["Content-Type"]).toBeUndefined();
  });

  it("sends X-API-KEY once set, and JSON bodies on POST", async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse(200, "{}"),
    ) as unknown as typeof fetch;
    const client = defaultHttpClient({
      baseUrl: "https://x/api",
      apiKeyHeader: null,
      fetchImpl,
    });
    client.setApiKeyHeader("abc");
    await client.post("/gate/scan", { content: "x" });
    const [, init] = (
      fetchImpl as unknown as { mock: { calls: [string, RequestInit][] } }
    ).mock.calls[0];
    expect((init.headers as Record<string, string>)["X-API-KEY"]).toBe("abc");
    expect(init.method).toBe("POST");
    expect(init.body).toBe('{"content":"x"}');
  });

  it("parses JSON bodies, quota headers, and flags non-JSON bodies", async () => {
    let n = 0;
    const fetchImpl = vi.fn(async () =>
      n++ === 0
        ? jsonResponse(200, '{"a":1}', {
            "X-Monthly-Usage": "1",
            "X-Monthly-Limit": "10",
          })
        : new Response("<html>", { status: 200 }),
    ) as unknown as typeof fetch;
    const client = defaultHttpClient({
      baseUrl: "https://x/api",
      apiKeyHeader: "k",
      fetchImpl,
    });
    const ok = await client.get("/a");
    expect(ok).toEqual({
      status: 200,
      json: { a: 1 },
      invalidBody: false,
      headers: { monthly: { usage: 1, limit: 10 } },
    });
    const bad = await client.get("/b");
    expect(bad.json).toBeNull();
    expect(bad.invalidBody).toBe(true);
  });

  it("aborts with HttpTimeoutError after timeoutMs", async () => {
    vi.useFakeTimers();
    const client = defaultHttpClient({
      baseUrl: "https://x/api",
      apiKeyHeader: "k",
      fetchImpl: fetchThatWaitsForAbort(),
    });
    const pending = client.get("/slow", { timeoutMs: 1000 });
    const assertion = expect(pending).rejects.toBeInstanceOf(HttpTimeoutError);
    await vi.advanceTimersByTimeAsync(1001);
    await assertion;
  });

  it("aborts with HttpCancelledError when the caller signal fires", async () => {
    const client = defaultHttpClient({
      baseUrl: "https://x/api",
      apiKeyHeader: "k",
      fetchImpl: fetchThatWaitsForAbort(),
    });
    const controller = new AbortController();
    const pending = client.get("/slow", {
      signal: controller.signal,
      timeoutMs: 60_000,
    });
    controller.abort("cancelled");
    await expect(pending).rejects.toBeInstanceOf(HttpCancelledError);
  });

  it("wraps other fetch failures in HttpNetworkError", async () => {
    const fetchImpl = vi.fn(async () => {
      throw new TypeError("fetch failed");
    }) as unknown as typeof fetch;
    const client = defaultHttpClient({
      baseUrl: "https://x/api",
      apiKeyHeader: "k",
      fetchImpl,
    });
    await expect(client.get("/x")).rejects.toBeInstanceOf(HttpNetworkError);
  });
});
