import { describe, expect, it, vi } from "vitest";
import { HttpCancelledError } from "../http.js";
import {
  createServer,
  PROTOCOL_VERSION,
  QUOTA_RESOURCE_URI,
} from "../server.js";
import { isError, parsed, response, stubHttp, text } from "./helpers.js";
import ipFixture from "./fixtures/check-ip-malicious.json";

function make(
  http = stubHttp(),
  extra: Partial<Parameters<typeof createServer>[0]> = {},
) {
  return createServer({
    baseUrl: "https://x/api",
    apiKeyHeader: "abc",
    http,
    ...extra,
  });
}

function call(name: string, args: Record<string, unknown>, id = 9) {
  return {
    jsonrpc: "2.0" as const,
    id,
    method: "tools/call",
    params: { name, arguments: args },
  };
}

describe("initialize", () => {
  it("advertises tools + resources, serverInfo and instructions", async () => {
    const res = await make().handle({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
    });
    expect(res?.result).toMatchObject({
      protocolVersion: PROTOCOL_VERSION,
      capabilities: { tools: { listChanged: true }, resources: {} },
    });
    expect((res?.result as { instructions: string }).instructions).toContain(
      "check_indicator",
    );
  });

  it("echoes a supported older protocol version and falls back otherwise", async () => {
    const older = await make().handle({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2025-03-26" },
    });
    expect((older?.result as { protocolVersion: string }).protocolVersion).toBe(
      "2025-03-26",
    );
    const unknown = await make().handle({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "1999-01-01" },
    });
    expect(
      (unknown?.result as { protocolVersion: string }).protocolVersion,
    ).toBe(PROTOCOL_VERSION);
  });
});

describe("notifications and unknown methods", () => {
  it("returns null for notifications/initialized", async () => {
    expect(
      await make().handle({
        jsonrpc: "2.0",
        method: "notifications/initialized",
      }),
    ).toBeNull();
  });
  it("answers -32601 for unknown requests and null for unknown notifications", async () => {
    const res = await make().handle({
      jsonrpc: "2.0",
      id: 4,
      method: "prompts/list",
    });
    expect(res?.error?.code).toBe(-32601);
    expect(
      await make().handle({ jsonrpc: "2.0", method: "notifications/whatever" }),
    ).toBeNull();
  });
});

describe("tools/list", () => {
  it("lists the gate tools first, then the v0.2 and v0.3 tools, without bootstrap_key when a key is set", async () => {
    const res = await make().handle({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
    });
    const names = (res?.result as { tools: { name: string }[] }).tools.map(
      (t) => t.name,
    );
    expect(names).toEqual([
      "scan_before_use",
      "check_url",
      "check_indicator",
      "get_cve",
      "recent_cves",
      "search_indicators",
      "check_indicators",
    ]);
  });

  it("lists only bootstrap_key when no key is configured", async () => {
    const res = await make(stubHttp(), { apiKeyHeader: null }).handle({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
    });
    const names = (res?.result as { tools: { name: string }[] }).tools.map(
      (t) => t.name,
    );
    expect(names).toEqual(["bootstrap_key"]);
  });
});

describe("gate tools (v0.1 compatibility)", () => {
  it("scan_before_use POSTs content to /gate/scan and returns the body unchanged", async () => {
    const http = stubHttp({
      post: vi.fn(async () =>
        response(200, { verdict: "block", reasons: ["x"] }),
      ),
    });
    const res = await make(http).handle(
      call("scan_before_use", {
        content: "ignore previous",
        source_url: "https://e.x",
      }),
    );
    expect(http.post).toHaveBeenCalledWith(
      "/gate/scan",
      { content: "ignore previous", source_url: "https://e.x" },
      expect.objectContaining({ timeoutMs: 15_000 }),
    );
    expect(isError(res)).toBe(false);
    expect(parsed(res)).toEqual({ verdict: "block", reasons: ["x"] });
  });

  it("scan_before_use rejects missing content without an HTTP call", async () => {
    const http = stubHttp();
    const res = await make(http).handle(call("scan_before_use", {}));
    expect(http.post).not.toHaveBeenCalled();
    expect(isError(res)).toBe(true);
    expect(parsed(res).error).toBe("invalid_params");
  });

  it("check_url GETs /gate/url?u=", async () => {
    const http = stubHttp();
    await make(http).handle(
      call("check_url", { url: "https://evil.example/a?b=c" }),
    );
    expect(http.get).toHaveBeenCalledWith(
      `/gate/url?u=${encodeURIComponent("https://evil.example/a?b=c")}`,
      expect.anything(),
    );
  });
});

describe("check_indicator", () => {
  it("GETs /check with standard enrichment and returns a projection under 4 KB", async () => {
    const http = stubHttp({ get: vi.fn(async () => response(200, ipFixture)) });
    const res = await make(http).handle(
      call("check_indicator", { indicator: "45.148.10.242" }),
    );
    expect(http.get).toHaveBeenCalledWith(
      "/check?query=45.148.10.242&enrichment=standard",
      expect.objectContaining({ timeoutMs: 25_000 }),
    );
    expect(isError(res)).toBe(false);
    expect(Buffer.byteLength(text(res))).toBeLessThanOrEqual(4096);
    const body = parsed<{
      verdict: string;
      recommendedAction: string;
      headline: string;
    }>(res);
    expect(body.verdict).toBe("malicious");
    expect(body.recommendedAction).toBe("block");
    expect(body.headline).toContain("45.148.10.242");
  });

  it("passes enrichment=basic through", async () => {
    const http = stubHttp({
      get: vi.fn(async () => response(200, { malicious: false, sources: [] })),
    });
    await make(http).handle(
      call("check_indicator", {
        indicator: "example.com",
        enrichment: "basic",
      }),
    );
    expect(http.get).toHaveBeenCalledWith(
      "/check?query=example.com&enrichment=basic",
      expect.anything(),
    );
  });
});

describe("get_cve / recent_cves", () => {
  it("refuses a malformed id before spending a request", async () => {
    const http = stubHttp();
    const res = await make(http).handle(call("get_cve", { id: "log4shell" }));
    expect(http.get).not.toHaveBeenCalled();
    expect(parsed(res).error).toBe("invalid_params");
  });

  it("uppercases the id and projects KEV/EPSS", async () => {
    const http = stubHttp({
      get: vi.fn(async () =>
        response(200, {
          id: "CVE-2021-44228",
          description: "Log4Shell",
          severity: "CRITICAL",
          cvssScore: 10,
          isKev: true,
          epssScore: 0.975,
        }),
      ),
    });
    const res = await make(http).handle(
      call("get_cve", { id: "cve-2021-44228" }),
    );
    expect(http.get).toHaveBeenCalledWith(
      "/cve?id=CVE-2021-44228",
      expect.objectContaining({ timeoutMs: 10_000 }),
    );
    const body = parsed<{
      kev: { listed: boolean };
      epss: { percent: number };
    }>(res);
    expect(body.kev.listed).toBe(true);
    expect(body.epss.percent).toBe(97.5);
  });

  it("maps a 404 to not_found with the canonical-route hint", async () => {
    const http = stubHttp({
      get: vi.fn(async () => response(404, { error: "CVE Not Found" })),
    });
    const res = await make(http).handle(
      call("get_cve", { id: "CVE-2099-0001" }),
    );
    expect(isError(res)).toBe(true);
    const body = parsed<{ error: string; hint: string }>(res);
    expect(body.error).toBe("not_found");
    expect(body.hint).toContain("GET /cve?id=");
    expect(body.hint).toContain("/vulnerabilities/{id}");
  });

  it("recent_cves clamps the limit to 20 and forwards severity", async () => {
    const http = stubHttp({
      get: vi.fn(async () => response(200, { count: 0, days: 7, cves: [] })),
    });
    await make(http).handle(
      call("recent_cves", { limit: 50, severity: "critical" }),
    );
    expect(http.get).toHaveBeenCalledWith(
      "/cve?recent=true&limit=20&severity=CRITICAL",
      expect.anything(),
    );
  });
});

describe("search_indicators", () => {
  it("POSTs /search with the keywords in the query string and no body", async () => {
    const http = stubHttp({
      post: vi.fn(async () =>
        response(200, {
          keywords: "paypal",
          hits: ["domain:paypal-login.example", "paypal-verify.example"],
          total_hits: 2,
        }),
      ),
    });
    const res = await make(http).handle(
      call("search_indicators", { keywords: " paypal " }),
    );
    expect(http.post).toHaveBeenCalledWith(
      "/search?keywords=paypal",
      undefined,
      expect.objectContaining({ timeoutMs: 20_000 }),
    );
    expect(isError(res)).toBe(false);
    expect(parsed(res)).toEqual({
      keywords: "paypal",
      total_hits: 2,
      total_hits_scope: "upstream_sample",
      returned: 2,
      truncated: null,
      indicators: [
        { value: "paypal-login.example", type: "domain" },
        { value: "paypal-verify.example" },
      ],
    });
  });

  it("applies limit client-side and flags truncation", async () => {
    const hits = Array.from({ length: 500 }, (_, i) => `domain:p${i}.example`);
    const http = stubHttp({
      post: vi.fn(async () =>
        response(200, { keywords: "p", hits, total_hits: 500 }),
      ),
    });
    const res = await make(http).handle(
      call("search_indicators", { keywords: "pay", limit: 3 }),
    );
    const body = parsed<{
      returned: number;
      truncated: boolean;
      indicators: unknown[];
    }>(res);
    expect(body.returned).toBe(3);
    expect(body.truncated).toBe(true);
    expect(body.indicators).toHaveLength(3);
  });

  it("refuses a one-character keyword without an HTTP call", async () => {
    const http = stubHttp();
    const res = await make(http).handle(
      call("search_indicators", { keywords: "p" }),
    );
    expect(http.post).not.toHaveBeenCalled();
    expect(parsed(res).error).toBe("invalid_params");
  });

  it.each([true, false, null, undefined])(
    "preserves explicit completeness metadata (%s), otherwise reports unknown",
    async (truncated) => {
      const http = stubHttp({
        post: vi.fn(async () =>
          response(200, {
            hits: ["domain:paypal.example"],
            total_hits: 1,
            truncated,
          }),
        ),
      });
      const res = await make(http).handle(
        call("search_indicators", {
          keywords: "paypal",
          limit: 100,
        }),
      );
      expect(parsed(res)).toMatchObject({
        total_hits: 1,
        total_hits_scope: "upstream_sample",
        returned: 1,
        truncated: truncated ?? null,
      });
    },
  );

  it("does not claim completeness for a custom Rust base without metadata", async () => {
    const hits = Array.from(
      { length: 25 },
      (_, i) => `domain:paypal-${i}.example`,
    );
    const http = stubHttp({
      post: vi.fn(async () => response(200, { hits, total_hits: 25 })),
    });
    const res = await make(http, {
      baseUrl: "https://api.ismalicious.com",
    }).handle(call("search_indicators", { keywords: "paypal", limit: 100 }));
    expect(parsed(res)).toMatchObject({ returned: 25, truncated: null });
  });

  it("keeps a corpus count distinct from the size of the returned sample", async () => {
    const http = stubHttp({
      post: vi.fn(async () =>
        response(200, {
          hits: ["paypal.example"],
          total_hits: 125,
        }),
      ),
    });
    const res = await make(http).handle(
      call("search_indicators", { keywords: "paypal" }),
    );
    expect(parsed(res)).toMatchObject({
      total_hits: 1,
      total_hits_scope: "upstream_sample",
      returned: 1,
      truncated: true,
    });
  });

  it.each([{}, { hits: [42] }])(
    "rejects a malformed API response instead of claiming zero matches",
    async (body) => {
      const http = stubHttp({ post: vi.fn(async () => response(200, body)) });
      const res = await make(http).handle(
        call("search_indicators", { keywords: "paypal" }),
      );
      expect(isError(res)).toBe(true);
      expect(parsed(res).error).toBe("upstream_error");
    },
  );

  it("relays a failed backend search as an error", async () => {
    const http = stubHttp({
      post: vi.fn(async () => response(500, { error: "Redis unavailable" })),
    });
    const res = await make(http).handle(
      call("search_indicators", { keywords: "paypal" }),
    );
    expect(isError(res)).toBe(true);
    expect(parsed(res).error).toBe("upstream_error");
  });
});

describe("check_indicators", () => {
  const row = (entity: string, malicious: boolean) => ({
    entity,
    type: "domain",
    isMalicious: malicious,
    confidence: 0.9,
    sources: malicious ? 4 : 0,
    categories: malicious ? ["phishing"] : [],
    riskScore: malicious ? 82 : 7,
    riskLevel: malicious ? "high" : "low",
    evidence: { big: "x".repeat(500) },
    analystStatus: "new",
    observedAt: "2026-09-01T00:00:00Z",
    recommendedAction: malicious ? "block" : "review",
    ...(malicious ? {} : { infrastructure: { attributes: ["cloud"] } }),
  });

  it("POSTs /bulk/check with trimmed entities and projects compact rows", async () => {
    const http = stubHttp({
      post: vi.fn(async () =>
        response(200, {
          success: true,
          total: 3,
          processed: 2,
          results: [row("evil.example", true), row("ok.example", false)],
          errors: ["1 duplicate/invalid entities were skipped"],
          processingTimeMs: 12,
        }),
      ),
    });
    const res = await make(http).handle(
      call("check_indicators", {
        indicators: [" evil.example ", "ok.example", "evil.example"],
      }),
    );
    expect(http.post).toHaveBeenCalledWith(
      "/bulk/check",
      {
        entities: ["evil.example", "ok.example", "evil.example"],
        enrichment: "standard",
        format: "json",
      },
      expect.objectContaining({ timeoutMs: 60_000 }),
    );
    expect(isError(res)).toBe(false);
    const body = parsed<{
      submitted: number;
      processed: number;
      malicious: number;
      notes: string[];
      results: Record<string, unknown>[];
    }>(res);
    expect(body).toMatchObject({ submitted: 3, processed: 2, malicious: 1 });
    expect(body.notes).toEqual(["1 duplicate/invalid entities were skipped"]);
    expect(body.results[0]).toEqual({
      entity: "evil.example",
      type: "domain",
      malicious: true,
      recommendedAction: "block",
      sources: 4,
      riskScore: 82,
      riskLevel: "high",
      categories: ["phishing"],
    });
    expect(body.results[1].infrastructure).toEqual(["cloud"]);
    expect(body.results[1]).not.toHaveProperty("evidence");
  });

  it("keeps a full batch of 100 rows instead of clipping to five", async () => {
    const results = Array.from({ length: 100 }, (_, i) =>
      row(`host-${i}.example`, i % 7 === 0),
    );
    const http = stubHttp({
      post: vi.fn(async () =>
        response(200, { success: true, total: 100, processed: 100, results }),
      ),
    });
    const res = await make(http).handle(
      call("check_indicators", {
        indicators: results.map((r) => r.entity),
        enrichment: "basic",
      }),
    );
    expect(http.post).toHaveBeenCalledWith(
      "/bulk/check",
      expect.objectContaining({ enrichment: "basic" }),
      expect.anything(),
    );
    const body = parsed<{ results: unknown[]; truncated?: boolean }>(res);
    expect(body.results).toHaveLength(100);
    expect(body.truncated).toBeUndefined();
  });

  it("refuses more than 100 indicators before spending a request", async () => {
    const http = stubHttp();
    const res = await make(http).handle(
      call("check_indicators", {
        indicators: Array.from({ length: 101 }, (_, i) => `h${i}.example`),
      }),
    );
    expect(http.post).not.toHaveBeenCalled();
    const body = parsed<{ error: string; message: string }>(res);
    expect(body.error).toBe("invalid_params");
    expect(body.message).toContain("one request");
  });

  it("relays a plan-limit 400 as bad_request with the API's message", async () => {
    const http = stubHttp({
      post: vi.fn(async () =>
        response(400, {
          success: false,
          total: 20,
          processed: 0,
          results: [],
          errors: [
            "Your plan (FREE) allows up to 10 entities per request. You submitted 20.",
          ],
        }),
      ),
    });
    const res = await make(http).handle(
      call("check_indicators", {
        indicators: Array.from({ length: 20 }, (_, i) => `h${i}.example`),
      }),
    );
    expect(isError(res)).toBe(true);
    expect(parsed(res).error).toBe("bad_request");
  });
});

describe("error envelope", () => {
  it("turns a 200 without JSON into upstream_error, never a success", async () => {
    const http = stubHttp({
      get: vi.fn(async () => response(200, null, {}, true)),
    });
    const res = await make(http).handle(call("check_url", { url: "a.b" }));
    expect(isError(res)).toBe(true);
    expect(parsed(res).error).toBe("upstream_error");
  });

  it("maps 429 with Retry-After to rate_limited with a burst quota block", async () => {
    const http = stubHttp({
      get: vi.fn(async () =>
        response(
          429,
          { error: "Rate limit exceeded", retryAfter: 30 },
          {
            retryAfterSec: 30,
            rateLimit: { limit: 60, remaining: 0 },
            plan: "FREE",
          },
        ),
      ),
    });
    const res = await make(http).handle(call("check_url", { url: "a.b" }));
    const body = parsed<{
      error: string;
      quota: { kind: string; retry_after: number; plan: string };
    }>(res);
    expect(body.error).toBe("rate_limited");
    expect(body.quota).toMatchObject({
      kind: "burst",
      retry_after: 30,
      plan: "FREE",
    });
  });

  it("maps 401 to unauthorized with the key hint", async () => {
    const http = stubHttp({
      get: vi.fn(async () => response(401, { error: "Invalid API key" })),
    });
    const res = await make(http).handle(call("check_url", { url: "a.b" }));
    const body = parsed<{ error: string; hint: string }>(res);
    expect(body.error).toBe("unauthorized");
    expect(body.hint).toContain("bootstrap_key");
  });

  it("refuses a key-requiring tool without a key, without an HTTP call", async () => {
    const http = stubHttp();
    const res = await make(http, { apiKeyHeader: null }).handle(
      call("check_url", { url: "a.b" }),
    );
    expect(http.get).not.toHaveBeenCalled();
    expect(parsed(res).error).toBe("unauthorized");
  });

  it("answers -32602 for an unknown tool", async () => {
    const res = await make().handle(call("nope", {}));
    expect(res?.error?.code).toBe(-32602);
  });
});

describe("cancellation", () => {
  it("drops the response of a request cancelled while in flight", async () => {
    const http = stubHttp({
      get: vi.fn(
        (_path: string, options?: { signal?: AbortSignal }) =>
          new Promise((_resolve, reject) => {
            options?.signal?.addEventListener("abort", () =>
              reject(new HttpCancelledError()),
            );
          }),
      ),
    });
    const server = make(http);
    const pending = server.handle(
      call("check_indicator", { indicator: "1.2.3.4" }, 42),
    );
    await Promise.resolve();
    await server.handle({
      jsonrpc: "2.0",
      method: "notifications/cancelled",
      params: { requestId: 42 },
    });
    expect(await pending).toBeNull();
  });

  it("still answers a request whose HTTP call failed for another reason", async () => {
    const http = stubHttp({
      get: vi.fn(async () => {
        throw new Error("ECONNRESET");
      }),
    });
    const res = await make(http).handle(call("check_url", { url: "a.b" }, 7));
    expect(res).not.toBeNull();
    expect(parsed(res).error).toBe("network_error");
  });
});

describe("bootstrap_key", () => {
  it("mints a key, unlocks the tool list and notifies list_changed", async () => {
    const notify = vi.fn();
    const http = stubHttp({
      post: vi.fn(async () =>
        response(201, {
          apiKey: "k",
          apiSecret: "s",
          quota: { requestsPerMonth: 1000 },
        }),
      ),
    });
    const server = make(http, { apiKeyHeader: null, notify });
    const res = await server.handle(
      call("bootstrap_key", { email: "Anas@Example.com" }),
    );
    expect(http.post).toHaveBeenCalledWith(
      "/keys/instant",
      { email: "anas@example.com" },
      expect.anything(),
    );
    const body = parsed<{
      ok: boolean;
      persist: { env: Record<string, string> };
    }>(res);
    expect(body.ok).toBe(true);
    expect(body.persist.env.ISMALICIOUS_API_KEY).toBe("k");
    expect(notify).toHaveBeenCalledWith({
      jsonrpc: "2.0",
      method: "notifications/tools/list_changed",
    });
    const list = await server.handle({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
    });
    expect((list?.result as { tools: unknown[] }).tools).toHaveLength(7);
  });

  it("explains the one-per-IP-per-day limit on 429", async () => {
    const http = stubHttp({
      post: vi.fn(async () => response(429, { error: "Rate limit exceeded" })),
    });
    const res = await make(http, { apiKeyHeader: null }).handle(
      call("bootstrap_key", { email: "a@b.co" }),
    );
    const body = parsed<{
      error: string;
      quota: { kind: string; limit: number };
      hint: string;
    }>(res);
    expect(body.error).toBe("rate_limited");
    expect(body.quota).toMatchObject({ kind: "issuance", limit: 1 });
    expect(body.hint).toContain("per day");
  });

  it("is refused once a key is configured", async () => {
    const res = await make().handle(call("bootstrap_key", { email: "a@b.co" }));
    expect(parsed(res).error).toBe("invalid_params");
  });
});

describe("quota resource", () => {
  it("lists and reads ismalicious://quota with the last seen headers", async () => {
    const http = stubHttp({
      get: vi.fn(async (path: string) =>
        path === "/gate/quota"
          ? response(200, { used: 2, limit: 100 })
          : response(
              200,
              { verdict: "allow" },
              { monthly: { usage: 10, limit: 1000 }, plan: "FREE" },
            ),
      ),
    });
    const server = make(http);
    await server.handle(call("check_url", { url: "a.b" }));
    const list = await server.handle({
      jsonrpc: "2.0",
      id: 5,
      method: "resources/list",
    });
    expect(
      (list?.result as { resources: { uri: string }[] }).resources[0].uri,
    ).toBe(QUOTA_RESOURCE_URI);
    const read = await server.handle({
      jsonrpc: "2.0",
      id: 6,
      method: "resources/read",
      params: { uri: QUOTA_RESOURCE_URI },
    });
    const contents = (read?.result as { contents: { text: string }[] })
      .contents[0];
    const body = JSON.parse(contents.text) as {
      scans: unknown;
      requests: { monthly: { limit: number }; plan: string };
    };
    expect(body.scans).toEqual({ used: 2, limit: 100 });
    expect(body.requests.monthly.limit).toBe(1000);
    expect(body.requests.plan).toBe("FREE");
  });

  it("answers -32002 for an unknown resource", async () => {
    const res = await make().handle({
      jsonrpc: "2.0",
      id: 6,
      method: "resources/read",
      params: { uri: "x://y" },
    });
    expect(res?.error?.code).toBe(-32002);
  });
});
