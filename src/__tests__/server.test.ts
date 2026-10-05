import { describe, expect, it, vi } from "vitest";
import { HttpCancelledError } from "../http.js";
import {
  createServer,
  PROTOCOL_VERSION,
  QUOTA_RESOURCE_URI,
} from "../server.js";
import { isError, parsed, response, stubHttp, text } from "./helpers.js";
import ipFixture from "./fixtures/check-ip-malicious.json";
// Real API bodies, held to the handler's output by
// apps/rust-api/tests/fast_check.rs.
import emailListed from "./fixtures/check-email-listed.json";
import phoneUnknown from "./fixtures/check-phone-unknown.json";
import bulkMixed from "./fixtures/bulk-check-mixed.json";

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
    const instructions = (res?.result as { instructions: string }).instructions;
    expect(instructions).toContain("check_indicator");
    expect(instructions).toContain("scan_email");
  });

  it("tells an agent to re-check pending facets once, never in a loop", async () => {
    // Every re-check is a billed request; "a re-check in a few seconds" read
    // as an invitation to poll a facet the API may never fill.
    const init = await make().handle({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
    });
    const list = await make().handle({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
    });
    const tools = (
      list?.result as {
        tools: Array<{
          name: string;
          description: string;
          inputSchema: unknown;
        }>;
      }
    ).tools.filter((t) => t.name.startsWith("check_indicator"));
    expect(tools).toHaveLength(2);
    const texts = [
      (init?.result as { instructions: string }).instructions,
      ...tools.flatMap((t) => [t.description, JSON.stringify(t.inputSchema)]),
    ].filter((t) => /pending/.test(t));
    expect(texts.length).toBeGreaterThanOrEqual(3);
    for (const t of texts) {
      expect(t).toMatch(/one re-check|re-check it once/);
      expect(t).not.toMatch(
        /re-check (?:it |them )?in a few seconds|a re-check a few seconds later|the next call is complete/,
      );
    }
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
      "check_password_exposure",
      "scan_email",
    ]);
  });

  it("gives every tool a title and MCP annotations, and nothing else new", async () => {
    const keyed = await make().handle({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
    });
    const bootstrap = await make(stubHttp(), { apiKeyHeader: null }).handle({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/list",
    });
    const tools = [
      ...(keyed?.result as { tools: Record<string, unknown>[] }).tools,
      ...(bootstrap?.result as { tools: Record<string, unknown>[] }).tools,
    ];
    const readOnly = {
      readOnlyHint: true,
      idempotentHint: true,
      openWorldHint: true,
    };
    expect(
      tools.map(({ name, title, annotations }) => ({
        name,
        title,
        annotations,
      })),
    ).toEqual([
      {
        name: "scan_before_use",
        title: "Scan untrusted content before use",
        annotations: readOnly,
      },
      {
        name: "check_url",
        title: "Check a link before fetching it",
        annotations: readOnly,
      },
      {
        name: "check_indicator",
        title: "Check indicator reputation",
        annotations: readOnly,
      },
      { name: "get_cve", title: "Look up a CVE", annotations: readOnly },
      {
        name: "recent_cves",
        title: "Latest published CVEs",
        annotations: readOnly,
      },
      {
        name: "search_indicators",
        title: "Find lookalike domains",
        annotations: readOnly,
      },
      {
        name: "check_indicators",
        title: "Check indicators in bulk",
        annotations: readOnly,
      },
      {
        name: "check_password_exposure",
        title: "Check password breach exposure",
        annotations: readOnly,
      },
      {
        name: "scan_email",
        title: "Scan an email for phishing and malware",
        annotations: readOnly,
      },
      {
        name: "bootstrap_key",
        title: "Mint a free API key",
        annotations: {
          readOnlyHint: false,
          destructiveHint: false,
          idempotentHint: false,
          openWorldHint: true,
        },
      },
    ]);
    for (const tool of tools) {
      expect(Object.keys(tool)).toEqual([
        "name",
        "title",
        "description",
        "inputSchema",
        "annotations",
      ]);
    }
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
  it("GETs /check with fast enrichment by default and returns a projection under 4 KB", async () => {
    const http = stubHttp({ get: vi.fn(async () => response(200, ipFixture)) });
    const res = await make(http).handle(
      call("check_indicator", { indicator: "45.148.10.242" }),
    );
    expect(http.get).toHaveBeenCalledWith(
      "/check?query=45.148.10.242&enrichment=fast",
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

  it("passes enrichment=basic and standard through", async () => {
    const http = stubHttp({
      get: vi.fn(async () => response(200, { malicious: false, sources: [] })),
    });
    await make(http).handle(
      call("check_indicator", {
        indicator: "example.com",
        enrichment: "basic",
      }),
    );
    await make(http).handle(
      call("check_indicator", {
        indicator: "example.com",
        enrichment: "standard",
      }),
    );
    expect(http.get).toHaveBeenNthCalledWith(
      1,
      "/check?query=example.com&enrichment=basic",
      expect.anything(),
    );
    expect(http.get).toHaveBeenNthCalledWith(
      2,
      "/check?query=example.com&enrichment=standard",
      expect.anything(),
    );
  });

  it("sends the refanged value, and says what it was given", async () => {
    const http = stubHttp({ get: vi.fn(async () => response(200, ipFixture)) });
    const res = await make(http).handle(
      call("check_indicator", { indicator: "hxxps://evil[.]example/login" }),
    );
    expect(http.get).toHaveBeenCalledWith(
      `/check?query=${encodeURIComponent("https://evil.example/login")}&enrichment=fast`,
      expect.anything(),
    );
    const body = parsed<{ indicator: string; input: string; type: string }>(
      res,
    );
    expect(body.indicator).toBe("https://evil.example/login");
    expect(body.input).toBe("hxxps://evil[.]example/login");
    expect(body.type).toBe("url");
  });

  it("sends a URL with its scheme and host lowercased, and keeps what it was given", async () => {
    const http = stubHttp({ get: vi.fn(async () => response(200, ipFixture)) });
    const res = await make(http).handle(
      call("check_indicator", { indicator: "HXXPS://PHISH[.]EXAMPLE/login" }),
    );
    // `httpS://PHISH.EXAMPLE/login` was sent: the API looked up the host
    // `https`, missed, and the answer was clean / allow.
    expect(http.get).toHaveBeenCalledWith(
      `/check?query=${encodeURIComponent("https://phish.example/login")}&enrichment=fast`,
      expect.anything(),
    );
    const body = parsed<{ indicator: string; input: string }>(res);
    expect(body.indicator).toBe("https://phish.example/login");
    expect(body.input).toBe("HXXPS://PHISH[.]EXAMPLE/login");
  });

  it("sends a host with a hyphen-edged label, and a URL without its host's root dot", async () => {
    // The first three were refused as invalid_params although ingestion
    // stores such hosts; the root-dot URL too, where `evil.com.` alone was
    // sent as `evil.com`.
    const cases: Array<[string, string]> = [
      ["secure-login-.blogspot.com", "secure-login-.blogspot.com"],
      ["https://foo-.tumblr.com/post/1", "https://foo-.tumblr.com/post/1"],
      ["-foo.example.com", "-foo.example.com"],
      ["http://evil.com./login", "http://evil.com/login"],
      ["www.evil.com./", "www.evil.com/"],
    ];
    for (const [indicator, query] of cases) {
      const http = stubHttp({
        get: vi.fn(async () => response(200, ipFixture)),
      });
      const res = await make(http).handle(
        call("check_indicator", { indicator }),
      );
      expect(isError(res), indicator).toBe(false);
      expect(http.get, indicator).toHaveBeenCalledWith(
        `/check?${new URLSearchParams({ query, enrichment: "fast" })}`,
        expect.anything(),
      );
    }
  });

  it("sends contact values in URI, full-width and spreadsheet forms as the address or the number", async () => {
    const cases: Array<[string, string]> = [
      ["sms:+14155552671", "+14155552671"],
      ["callto:+14155552671", "+14155552671"],
      ["tel://+14155552671", "+14155552671"],
      ["=+14155552671", "+14155552671"],
      ["user＠evil.com", "user@evil.com"],
      ["mailto://user@evil.com", "user@evil.com"],
    ];
    for (const [indicator, sent] of cases) {
      const http = stubHttp({
        get: vi.fn(async () => response(200, phoneUnknown)),
      });
      await make(http).handle(call("check_indicator", { indicator }));
      expect(http.get, indicator).toHaveBeenCalledWith(
        `/check?${new URLSearchParams({ query: sent, enrichment: "fast" })}`,
        expect.anything(),
      );
    }
  });

  it("refuses a vanity number, a one-label host and a hostless URL without a request", async () => {
    const http = stubHttp();
    for (const indicator of [
      "+1-800-FLOWERS",
      "evil",
      "https://evil/login",
      "*.evil.com",
    ]) {
      const res = await make(http).handle(
        call("check_indicator", { indicator }),
      );
      expect(isError(res), indicator).toBe(true);
      const body = parsed<{ error: string; message: string }>(res);
      expect(body.error).toBe("invalid_params");
      expect(body.message).toContain("no request was charged");
    }
    expect(http.get).not.toHaveBeenCalled();
  });

  it("sends a bare host without a soft hyphen or another code point IDNA ignores", async () => {
    // Validated as evil.com and sent as typed, the host missed and came back
    // clean / allow; https://ev­il.com/ was already sent as evil.com.
    const http = stubHttp({ get: vi.fn(async () => response(200, ipFixture)) });
    for (const indicator of ["ev­il.com", "evil️.com", "e\u{E0100}vil.com"]) {
      const body = parsed<{ indicator: string; input?: string }>(
        await make(http).handle(call("check_indicator", { indicator })),
      );
      expect(body.indicator).toBe("evil.com");
      expect(body.input).toBe(indicator);
    }
    for (const [path] of (http.get as ReturnType<typeof vi.fn>).mock.calls) {
      expect(new URLSearchParams(String(path).split("?")[1]).get("query")).toBe(
        "evil.com",
      );
    }
    expect(http.get).toHaveBeenCalledTimes(3);
  });

  it("refuses a callto:, sms: or tel: link to a user name or a host without a request", async () => {
    const http = stubHttp();
    for (const indicator of [
      "callto:john.doe",
      "callto://john.doe",
      "sms:hello",
      "tel://evil.com",
    ]) {
      const res = await make(http).handle(
        call("check_indicator", { indicator }),
      );
      expect(isError(res), indicator).toBe(true);
      const body = parsed<{ error: string; message: string }>(res);
      expect(body.error).toBe("invalid_params");
      expect(body.message).toContain("no request was charged");
    }
    expect(http.get).not.toHaveBeenCalled();
  });

  it("checks a labelled number as the number, and refuses an alphanumeric ID without keypad advice", async () => {
    const http = stubHttp({
      get: vi.fn(async () => response(200, phoneUnknown)),
    });
    await make(http).handle(
      call("check_indicator", { indicator: "415-555-2671 (mob)" }),
    );
    const [path] = (http.get as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(new URLSearchParams(String(path).split("?")[1]).get("query")).toBe(
      "415-555-2671",
    );
    const res = await make(http).handle(
      call("check_indicator", { indicator: "2FA-TOKEN-123" }),
    );
    expect(isError(res)).toBe(true);
    expect(parsed<{ message: string }>(res).message).not.toContain("keypad");
    expect(http.get).toHaveBeenCalledTimes(1);
  });

  it("refuses a SHA-512, a TLSH and an ssdeep without a request", async () => {
    const http = stubHttp();
    for (const indicator of [
      "f".repeat(128),
      `T1${"A".repeat(70)}`,
      "3072:C3JkrZsKoLLBSmvZ7GNu8YJ5/eH9MSu:C3JkrZsKoLl0dnJ1eH9M",
    ]) {
      const res = await make(http).handle(
        call("check_indicator", { indicator }),
      );
      expect(isError(res)).toBe(true);
      const body = parsed<{ error: string; message: string }>(res);
      expect(body.error).toBe("invalid_params");
      expect(body.message).toContain("MD5, SHA-1 or SHA-256");
    }
    expect(http.get).not.toHaveBeenCalled();
  });

  it("checks an email address as one, lowercased, and relays the API's verdict", async () => {
    const http = stubHttp({
      get: vi.fn(async () => response(200, emailListed)),
    });
    const res = await make(http).handle(
      call("check_indicator", {
        indicator: "Billing@Invoices-Portal.example",
      }),
    );
    expect(http.get).toHaveBeenCalledWith(
      `/check?query=${encodeURIComponent("billing@invoices-portal.example")}&enrichment=fast`,
      expect.objectContaining({ timeoutMs: 25_000 }),
    );
    expect(Buffer.byteLength(text(res))).toBeLessThanOrEqual(4096);
    const body = parsed<Record<string, unknown>>(res);
    expect(body).toMatchObject({
      indicator: "billing@invoices-portal.example",
      type: "email",
      verdict: "suspicious",
      recommendedAction: "review",
      lookupStatus: "found",
      email: { domain: "invoices-portal.example", mx: true },
      meta: { enrichment: "fast" },
    });
    expect(body.headline).toContain("is listed by 1 threat source");
  });

  it("forwards country for a national-format phone number", async () => {
    const http = stubHttp({
      get: vi.fn(async () => response(200, phoneUnknown)),
    });
    const res = await make(http).handle(
      call("check_indicator", { indicator: "06 12 34 56 78", country: "fr" }),
    );
    expect(http.get).toHaveBeenCalledWith(
      "/check?query=06+12+34+56+78&enrichment=fast&country=FR",
      expect.anything(),
    );
    const body = parsed<Record<string, unknown>>(res);
    expect(body).toMatchObject({
      indicator: "+33612345678",
      input: "06 12 34 56 78",
      type: "phone",
      verdict: "unknown",
      recommendedAction: "unverified",
      phone: { e164: "+33612345678", resolvedWith: "country" },
    });
  });

  it("refuses a malformed country without a request", async () => {
    const http = stubHttp();
    const res = await make(http).handle(
      call("check_indicator", { indicator: "0612345678", country: "France" }),
    );
    expect(parsed(res).error).toBe("invalid_params");
    expect(http.get).not.toHaveBeenCalled();
  });

  it("never sends an address or a number the API cannot read as a domain", async () => {
    // Each of these went down the domain path, missed, and came back
    // clean / allow. Now they are unwrapped into what the API reads, or
    // refused without a request.
    const http = stubHttp({
      get: vi.fn(async () => response(200, emailListed)),
    });
    // Uncached: the display name and the mailto: link are one call.
    const server = make(http, { cache: false });
    const sent: Array<[string, string]> = [
      ["Billing <billing@evil.com>", "billing@evil.com"],
      ["mailto:billing@evil.com?subject=Invoice", "billing@evil.com"],
      ["+33\u00a06\u00a012\u00a034\u00a056\u00a078", "+33 6 12 34 56 78"],
      ["(+33) 6 12 34 56 78", "+33 6 12 34 56 78"],
      ["tel:+1-415-555-2671;ext=12", "+1-415-555-2671"],
      [`sha256:${"a".repeat(64)}`, "a".repeat(64)],
    ];
    for (const [indicator, query] of sent) {
      (http.get as ReturnType<typeof vi.fn>).mockClear();
      await server.handle(call("check_indicator", { indicator }));
      expect(http.get, indicator).toHaveBeenCalledWith(
        `/check?${new URLSearchParams({ query, enrichment: "fast" })}`,
        expect.anything(),
      );
    }
    (http.get as ReturnType<typeof vi.fn>).mockClear();
    for (const indicator of [
      '"john doe"@example.com',
      "user@localhost",
      "user@evil.com/",
      "12345",
      `sha256:${"a".repeat(40)}`,
    ]) {
      const res = await server.handle(call("check_indicator", { indicator }));
      expect(isError(res), indicator).toBe(true);
      expect(parsed(res).error).toBe("invalid_params");
      expect(String(parsed(res).message)).toContain("no request was charged");
    }
    expect(http.get).not.toHaveBeenCalled();
  });

  it("refuses an oversized indicator before typing it", async () => {
    const http = stubHttp();
    const started = performance.now();
    const res = await make(http).handle(
      call("check_indicator", { indicator: `a${")".repeat(20_000)}` }),
    );
    expect(performance.now() - started).toBeLessThan(100);
    expect(parsed(res)).toMatchObject({
      error: "invalid_params",
      message: "indicator is longer than 2048 characters.",
    });
    expect(http.get).not.toHaveBeenCalled();
  });

  it("answers unknown / unverified when an older API looks an address up as a domain", async () => {
    // The body a server from before email support answers: a domain miss.
    const http = stubHttp({
      get: vi.fn(async () =>
        response(200, {
          malicious: false,
          apiVersion: "v2",
          enrichmentLevel: "standard",
          reputation: null,
          sources: [],
          blocklistHits: 0,
        }),
      ),
    });
    for (const indicator of ["user@evil.example", "+33612345678"]) {
      const body = parsed<Record<string, unknown>>(
        await make(http).handle(call("check_indicator", { indicator })),
      );
      expect(body.verdict).toBe("unknown");
      expect(body.recommendedAction).toBe("unverified");
      expect(body.malicious).toBe(false);
      expect(String(body.note)).toContain("predates email and phone support");
    }
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

  it("returns all 500 hits a limit of 500 asks for", async () => {
    const hits = Array.from({ length: 500 }, (_, i) => `domain:p${i}.example`);
    const http = stubHttp({
      post: vi.fn(async () => response(200, { hits, total_hits: 500 })),
    });
    const res = await make(http).handle(
      call("search_indicators", { keywords: "paypal", limit: 500 }),
    );
    const body = parsed<{ returned: number; indicators: unknown[] }>(res);
    expect(body.indicators).toHaveLength(500);
    expect(body.returned).toBe(500);
  });

  it("drops tail hits to fit, never clipping the list to five", async () => {
    // 500 hostnames of ~70 characters: ~43 KB, over the 32 KB ceiling.
    const hits = Array.from(
      { length: 500 },
      (_, i) =>
        `domain:paypal-account-verification-secure-login-${String(i).padStart(4, "0")}.example-phish.com`,
    );
    const http = stubHttp({
      post: vi.fn(async () => response(200, { hits, total_hits: 500 })),
    });
    const res = await make(http).handle(
      call("search_indicators", { keywords: "paypal", limit: 500 }),
    );
    expect(Buffer.byteLength(text(res))).toBeLessThanOrEqual(32_768);
    const body = parsed<{
      total_hits: number;
      returned: number;
      omitted: number;
      truncated: boolean;
      note: string;
      indicators: { value: string }[];
    }>(res);
    expect(body.indicators.length).toBeGreaterThan(300);
    expect(body.returned).toBe(body.indicators.length);
    expect(body.returned + body.omitted).toBe(500);
    expect(body.total_hits).toBe(500);
    expect(body.truncated).toBe(true);
    expect(body.note).toContain("dropped from the end");
    // Head kept, tail dropped: the API sorts most dangerous first.
    expect(body.indicators[0].value).toBe(hits[0].slice("domain:".length));
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

  it("keeps 100 SHA-256 rows with three categories each (was cut to 5)", async () => {
    const results = Array.from({ length: 100 }, (_, i) => ({
      entity: i.toString(16).padStart(64, "a"),
      type: "hash",
      isMalicious: i % 2 === 0,
      sources: 3,
      categories: ["malware", "trojan", "ransomware"],
      riskScore: 91,
      riskLevel: "critical",
      lookupStatus: "found",
      recommendedAction: "block",
    }));
    const http = stubHttp({
      post: vi.fn(async () =>
        response(200, { success: true, total: 100, processed: 100, results }),
      ),
    });
    const res = await make(http).handle(
      call("check_indicators", { indicators: results.map((r) => r.entity) }),
    );
    const body = parsed<{
      malicious: number;
      results: unknown[];
      truncated?: boolean;
    }>(res);
    expect(Buffer.byteLength(text(res))).toBeGreaterThan(24_576);
    expect(body.results).toHaveLength(100);
    expect(body.malicious).toBe(50);
    expect(body.truncated).toBeUndefined();
  });

  it("keeps 100 URLs of ~150 characters (was cut to 5)", async () => {
    const results = Array.from({ length: 100 }, (_, i) => ({
      ...row(
        `https://login-secure-account.example-${i}.com/${"verify/".repeat(16)}${i}`,
        i % 4 === 0,
      ),
      type: "url",
    }));
    expect(results[0].entity.length).toBeGreaterThanOrEqual(140);
    const http = stubHttp({
      post: vi.fn(async () =>
        response(200, { success: true, total: 100, processed: 100, results }),
      ),
    });
    const res = await make(http).handle(
      call("check_indicators", { indicators: results.map((r) => r.entity) }),
    );
    const body = parsed<{ results: unknown[]; truncated?: boolean }>(res);
    expect(Buffer.byteLength(text(res))).toBeGreaterThan(24_576);
    expect(body.results).toHaveLength(100);
    expect(body.truncated).toBeUndefined();
  });

  it("past 48 KB drops tail rows, and says what the counts cover", async () => {
    // 100 URLs of ~1,000 characters: ~110 KB of rows.
    const results = Array.from({ length: 100 }, (_, i) => ({
      ...row(`https://e${i}.example/${"a".repeat(1_000)}`, i % 3 === 0),
      type: "url",
    }));
    const http = stubHttp({
      post: vi.fn(async () =>
        response(200, { success: true, total: 100, processed: 100, results }),
      ),
    });
    const res = await make(http).handle(
      call("check_indicators", { indicators: results.map((r) => r.entity) }),
    );
    expect(Buffer.byteLength(text(res))).toBeLessThanOrEqual(49_152);
    const body = parsed<{
      submitted: number;
      malicious: number;
      maliciousReturned: number;
      maliciousOmitted: number;
      returned: number;
      omitted: number;
      truncated: boolean;
      note: string;
      results: { entity: string }[];
    }>(res);
    expect(body.results.length).toBeGreaterThan(5);
    expect(body.results.length).toBeLessThan(100);
    expect(body.returned).toBe(body.results.length);
    expect(body.returned + body.omitted).toBe(100);
    // Whole rows: no entity is clipped.
    expect(body.results.at(-1)?.entity).toBe(results[body.returned - 1].entity);
    expect(body.submitted).toBe(100);
    expect(body.malicious).toBe(34);
    expect(body.maliciousReturned + body.maliciousOmitted).toBe(34);
    expect(body.maliciousReturned).toBe(
      results.slice(0, body.returned).filter((r) => r.isMalicious).length,
    );
    expect(body.truncated).toBe(true);
    expect(body.note).toContain("cover all 100");
  });

  it("types a mixed batch locally: refanged values sent, unsupported hashes refused and not sent", async () => {
    const sha512 = "f".repeat(128);
    const http = stubHttp({
      post: vi.fn(async () =>
        response(200, {
          success: true,
          total: 5,
          processed: 5,
          results: [
            {
              entity: "evil.example",
              type: "domain",
              isMalicious: true,
              sources: 3,
              riskScore: 81,
              riskLevel: "high",
              recommendedAction: "escalate",
            },
            {
              entity: "1.2.3.4",
              type: "ip",
              isMalicious: false,
              sources: 0,
              recommendedAction: "monitor",
            },
            {
              entity: "scam@evil.example",
              type: "email",
              isMalicious: true,
              sources: 1,
              categories: ["phishing"],
              riskScore: 75,
              riskLevel: "high",
              lookupStatus: "found",
              recommendedAction: "block",
            },
            {
              entity: "+14155552671",
              type: "phone",
              isMalicious: false,
              sources: 0,
              lookupStatus: "unknown",
              recommendedAction: "unverified",
            },
            {
              entity: "d41d8cd98f00b204e9800998ecf8427e",
              type: "hash",
              isMalicious: false,
              sources: 0,
              lookupStatus: "unknown",
              recommendedAction: "review",
            },
          ],
        }),
      ),
    });
    const res = await make(http).handle(
      call("check_indicators", {
        indicators: [
          "evil[.]example",
          sha512,
          "1.2.3.4",
          "Scam[@]Evil.example",
          "+14155552671",
          "d41d8cd98f00b204e9800998ecf8427e",
        ],
        country: "us",
      }),
    );
    expect(http.post).toHaveBeenCalledWith(
      "/bulk/check",
      {
        entities: [
          "evil.example",
          "1.2.3.4",
          "scam@evil.example",
          "+14155552671",
          "d41d8cd98f00b204e9800998ecf8427e",
        ],
        enrichment: "standard",
        format: "json",
        country: "US",
      },
      expect.anything(),
    );
    const body = parsed<{
      submitted: number;
      processed: number;
      refused: number;
      malicious: number;
      notes: string[];
      results: Record<string, unknown>[];
    }>(res);
    expect(body).toMatchObject({
      submitted: 6,
      processed: 5,
      refused: 1,
      malicious: 2,
    });
    expect(body.notes[0]).toContain("1 indicator was refused before sending");
    // Input order, the refused row in its place.
    expect(body.results.map((r) => r.entity)).toEqual([
      "evil.example",
      sha512,
      "1.2.3.4",
      "scam@evil.example",
      "+14155552671",
      "d41d8cd98f00b204e9800998ecf8427e",
    ]);
    expect(body.results[0]).toMatchObject({
      input: "evil[.]example",
      recommendedAction: "escalate",
    });
    expect(body.results[1]).toMatchObject({
      type: "hash",
      hashType: "sha512",
      malicious: false,
      recommendedAction: "unverified",
    });
    expect(String(body.results[1].error)).toContain("SHA-512");
    expect(body.results[2].recommendedAction).toBe("monitor");
    expect(body.results[3]).toMatchObject({
      type: "email",
      malicious: true,
      recommendedAction: "block",
      lookupStatus: "found",
      input: "Scam[@]Evil.example",
    });
    expect(body.results[4]).toMatchObject({
      type: "phone",
      recommendedAction: "unverified",
      lookupStatus: "unknown",
    });
  });

  it("maps the API's real rows for a mixed batch back to the inputs, contact rows never clean", async () => {
    // What /bulk/check answered for this batch (bulk-check-mixed.json): the
    // rows echo the entity as sent, which is how they find their input.
    const entities = [
      "cold.example",
      "billing@invoices-portal.example",
      "nobody@example.org",
      "+1 415 555 2671",
      "(202) 555-0143",
      "06 12 34 56 78",
    ];
    const http = stubHttp({
      post: vi.fn(async () => response(200, bulkMixed)),
    });
    const res = await make(http).handle(
      call("check_indicators", { indicators: entities, country: "fr" }),
    );
    expect(http.post).toHaveBeenCalledWith(
      "/bulk/check",
      { entities, enrichment: "standard", format: "json", country: "FR" },
      expect.anything(),
    );
    const body = parsed<{
      submitted: number;
      processed: number;
      malicious: number;
      results: Record<string, unknown>[];
    }>(res);
    expect(body).toMatchObject({ submitted: 6, processed: 6, malicious: 1 });
    expect(
      body.results.map((r) => [
        r.entity,
        r.type,
        r.malicious,
        r.recommendedAction,
        r.lookupStatus,
      ]),
    ).toEqual([
      ["cold.example", "domain", false, "review", undefined],
      ["billing@invoices-portal.example", "email", false, "review", "found"],
      ["nobody@example.org", "email", false, "unverified", "unknown"],
      ["+1 415 555 2671", "phone", true, "block", "found"],
      ["(202) 555-0143", "phone", false, "review", "found"],
      ["06 12 34 56 78", "phone", false, "unverified", "unknown"],
    ]);
    // An unknown contact row has no score to show: none is invented.
    expect(body.results[2]).not.toHaveProperty("riskScore");
    expect(body.results[1]).toMatchObject({ riskScore: 50, sources: 1 });
    expect(text(res)).not.toMatch(/"allow"|"clean"/);
  });

  it("sends nothing, and charges nothing, when no row can be looked up", async () => {
    const http = stubHttp();
    const res = await make(http).handle(
      call("check_indicators", {
        indicators: ["f".repeat(128), `T1${"B".repeat(70)}`, "[.]"],
      }),
    );
    expect(http.post).not.toHaveBeenCalled();
    expect(isError(res)).toBe(false);
    const body = parsed<{
      submitted: number;
      processed: number;
      refused: number;
      results: unknown[];
    }>(res);
    expect(body).toMatchObject({ submitted: 3, processed: 0, refused: 3 });
    expect(body.results).toMatchObject([
      { type: "hash", hashType: "sha512" },
      { type: "hash", hashType: "tlsh" },
      {
        type: "unknown",
        error: expect.stringContaining("indicator is empty."),
      },
    ]);
  });

  it("refuses entries under 3 characters instead of sending rows the API drops", async () => {
    const http = stubHttp({
      post: vi.fn(async () =>
        response(200, {
          processed: 1,
          results: [
            { entity: "evil.example", type: "domain", isMalicious: true },
          ],
        }),
      ),
    });
    const server = make(http);
    const body = parsed<{
      refused: number;
      results: Record<string, unknown>[];
    }>(
      await server.handle(
        call("check_indicators", { indicators: ["ab", "evil.example", " x "] }),
      ),
    );
    expect(http.post).toHaveBeenCalledWith(
      "/bulk/check",
      expect.objectContaining({ entities: ["evil.example"] }),
      expect.anything(),
    );
    expect(body.refused).toBe(2);
    // Every input has a row: the short ones were not silently lost.
    expect(body.results.map((r) => r.entity)).toEqual([
      "ab",
      "evil.example",
      "x",
    ]);
    expect(String(body.results[0].error)).toContain(
      "shorter than 3 characters",
    );
    // A batch of nothing else costs no request at all (the gate charged one).
    (http.post as ReturnType<typeof vi.fn>).mockClear();
    await server.handle(call("check_indicators", { indicators: ["ab", "c"] }));
    expect(http.post).not.toHaveBeenCalled();
  });

  it("types the forms people paste in a batch, and refuses the unreadable ones", async () => {
    const http = stubHttp({
      post: vi.fn(async () => response(200, { processed: 0, results: [] })),
    });
    const body = parsed<{
      refused: number;
      results: Record<string, unknown>[];
    }>(
      await make(http).handle(
        call("check_indicators", {
          indicators: [
            "Billing <billing@evil.com>",
            "+33\u202f6\u202f12\u202f34\u202f56\u202f78",
            `SHA256: ${"b".repeat(64)}`,
            '"john doe"@example.com',
            "1234",
          ],
        }),
      ),
    );
    expect(http.post).toHaveBeenCalledWith(
      "/bulk/check",
      expect.objectContaining({
        entities: ["billing@evil.com", "+33 6 12 34 56 78", "b".repeat(64)],
      }),
      expect.anything(),
    );
    expect(body.refused).toBe(2);
    expect(body.results).toMatchObject([
      {
        entity: '"john doe"@example.com',
        type: "email",
        recommendedAction: "unverified",
      },
      { entity: "1234", type: "phone", recommendedAction: "unverified" },
    ]);
  });

  it("sends contact values and URLs in the form the API reads, and refuses a vanity number as an unsent row", async () => {
    const http = stubHttp({
      post: vi.fn(async () => response(200, { processed: 0, results: [] })),
    });
    const body = parsed<{
      refused: number;
      results: Record<string, unknown>[];
    }>(
      await make(http).handle(
        call("check_indicators", {
          indicators: [
            "０９０−１２３４−５６７８",
            "user＠evil.com",
            "+1-800-FLOWERS",
            "HTTPS://PHISH.EXAMPLE/login",
            "callto:+14155552671",
            "sms",
          ],
        }),
      ),
    );
    expect(http.post).toHaveBeenCalledWith(
      "/bulk/check",
      expect.objectContaining({
        entities: [
          "090-1234-5678",
          "user@evil.com",
          "https://phish.example/login",
          "+14155552671",
        ],
      }),
      expect.anything(),
    );
    expect(body.refused).toBe(2);
    expect(body.results).toMatchObject([
      {
        entity: "+1-800-FLOWERS",
        type: "phone",
        malicious: false,
        recommendedAction: "unverified",
      },
      { entity: "sms", type: "unknown", recommendedAction: "unverified" },
    ]);
    expect(String(body.results[0].error)).toContain("written with letters");
  });

  it("sends hosts with hyphen-edged labels and root-dot URLs instead of refusing them as rows", async () => {
    const http = stubHttp({
      post: vi.fn(async () => response(200, { processed: 0, results: [] })),
    });
    const body = parsed<{ refused?: number }>(
      await make(http).handle(
        call("check_indicators", {
          indicators: [
            "secure-login-.blogspot.com",
            "https://foo-.tumblr.com/post/1",
            "-foo.example.com",
            "evil.com",
            "http://evil.com./login",
          ],
        }),
      ),
    );
    expect(http.post).toHaveBeenCalledWith(
      "/bulk/check",
      expect.objectContaining({
        entities: [
          "secure-login-.blogspot.com",
          "https://foo-.tumblr.com/post/1",
          "-foo.example.com",
          "evil.com",
          "http://evil.com/login",
        ],
      }),
      expect.anything(),
    );
    expect(body.refused ?? 0).toBe(0);
  });

  it("refuses contact links to user names as unsent rows, and sends normalised hosts and labelled numbers", async () => {
    const http = stubHttp({
      post: vi.fn(async () => response(200, { processed: 0, results: [] })),
    });
    const body = parsed<{
      refused: number;
      results: Record<string, unknown>[];
    }>(
      await make(http).handle(
        call("check_indicators", {
          indicators: [
            "callto:john.doe",
            "callto://john.doe",
            "sms:hello",
            "ev­il.com",
            "+1 415 555 2671 cell",
            "5G-ROUTER-01",
          ],
        }),
      ),
    );
    expect(http.post).toHaveBeenCalledWith(
      "/bulk/check",
      expect.objectContaining({ entities: ["evil.com", "+1 415 555 2671"] }),
      expect.anything(),
    );
    expect(body.refused).toBe(4);
    expect(body.results).toMatchObject([
      {
        entity: "callto:john.doe",
        type: "phone",
        recommendedAction: "unverified",
      },
      {
        entity: "callto://john.doe",
        type: "phone",
        recommendedAction: "unverified",
      },
      { entity: "sms:hello", type: "phone", recommendedAction: "unverified" },
      {
        entity: "5G-ROUTER-01",
        type: "unknown",
        recommendedAction: "unverified",
      },
    ]);
    expect(String(body.results[3].error)).not.toContain("keypad");
  });

  it("types a hostile 100-item batch without holding the event loop (was ~2 s)", async () => {
    // `<` + 2,047 `@`: the display-name pattern backtracked quadratically,
    // and the batch was typed three times per call (cacheArgs, call, rebind).
    const http = stubHttp();
    const indicators = Array.from(
      { length: 100 },
      (_, i) => `<${"@".repeat(2_040)}${i}`,
    );
    const started = performance.now();
    const body = parsed<{ refused: number }>(
      await make(http).handle(call("check_indicators", { indicators })),
    );
    expect(performance.now() - started).toBeLessThan(400);
    expect(body.refused).toBe(100);
    expect(http.post).not.toHaveBeenCalled();
  });

  it("keeps a row's pending facets and says the row is not settled", async () => {
    const sha = "e".repeat(64);
    const http = stubHttp({
      post: vi.fn(async () =>
        response(200, {
          processed: 2,
          results: [
            {
              entity: sha,
              type: "hash",
              isMalicious: false,
              sources: 0,
              lookupStatus: "unknown",
              recommendedAction: "review",
              pending: ["circl"],
            },
            {
              entity: "evil.example",
              type: "domain",
              isMalicious: true,
              sources: 2,
            },
          ],
        }),
      ),
    });
    const body = parsed<{
      pendingRows: number;
      notes: string[];
      results: Record<string, unknown>[];
    }>(
      await make(http).handle(
        call("check_indicators", { indicators: [sha, "evil.example"] }),
      ),
    );
    expect(body.results[0]).toMatchObject({
      lookupStatus: "unknown",
      pending: ["circl"],
    });
    expect(body.results[1]).not.toHaveProperty("pending");
    expect(body.pendingRows).toBe(1);
    expect(body.notes.join(" ")).toMatch(/1 row is not settled.*Re-check it/);
  });

  it("marks email and phone rows an older API typed otherwise as unverified, never clean", async () => {
    const http = stubHttp({
      post: vi.fn(async () =>
        response(200, {
          success: true,
          total: 2,
          processed: 2,
          results: [
            // Before email support: the address was looked up as a domain.
            {
              entity: "user@evil.example",
              type: "domain",
              isMalicious: false,
              sources: 0,
              riskScore: 5,
              riskLevel: "safe",
              recommendedAction: "allow",
            },
            // And a +E.164 number was an unsupported row.
            {
              entity: "+14155552671",
              type: "unknown",
              isMalicious: false,
              sources: 0,
              recommendedAction: "review",
              error: "Unsupported entity type",
            },
          ],
        }),
      ),
    });
    const body = parsed<{
      malicious: number;
      results: Record<string, unknown>[];
    }>(
      await make(http).handle(
        call("check_indicators", {
          indicators: ["user@evil.example", "+14155552671"],
        }),
      ),
    );
    expect(body.malicious).toBe(0);
    for (const [row, type] of [
      [body.results[0], "email"],
      [body.results[1], "phone"],
    ] as const) {
      expect(row).toMatchObject({
        type,
        malicious: false,
        recommendedAction: "unverified",
        lookupStatus: "unknown",
        sources: 0,
      });
      expect(row).not.toHaveProperty("riskScore");
      expect(String(row.error)).toContain("did not evaluate");
    }
  });

  it("refuses a malformed country without a request", async () => {
    const http = stubHttp();
    const res = await make(http).handle(
      call("check_indicators", { indicators: ["0612345678"], country: "FRA" }),
    );
    expect(parsed(res).error).toBe("invalid_params");
    expect(http.post).not.toHaveBeenCalled();
  });

  it("states the billing rule and every recommendedAction value in its description", async () => {
    const res = await make().handle({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
    });
    const tools = (
      res?.result as { tools: { name: string; description: string }[] }
    ).tools;
    const bulk =
      tools.find((t) => t.name === "check_indicators")?.description ?? "";
    for (const action of [
      "block",
      "escalate",
      "review",
      "monitor",
      "allow",
      "unverified",
    ]) {
      expect(bulk).toContain(action);
    }
    expect(bulk).toContain(
      "every unique indicator the API receives charges one request",
    );
    expect(bulk).toContain("including rows the API cannot type");
    expect(bulk).toContain("entries under 3 characters");
    expect(bulk).not.toMatch(/under 3 characters are free/);
    expect(bulk).toContain("pending");
    const single =
      tools.find((t) => t.name === "check_indicator")?.description ?? "";
    for (const kind of [
      "IP",
      "domain",
      "URL",
      "file hash",
      "email address",
      "phone number",
    ]) {
      expect(single).toContain(kind);
    }
    // A cold hash at fast may wait on CIRCL: "cached only" was not true.
    expect(single).not.toMatch(/cached intelligence only/);
    expect(single).toContain("CIRCL");
    for (const t of tools) {
      expect(t.description, t.name).not.toMatch(/real-time|instant/i);
    }
    const search =
      tools.find((t) => t.name === "search_indicators")?.description ?? "";
    expect(search).toContain("not charged on the monthly quota");
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
    expect((list?.result as { tools: unknown[] }).tools).toHaveLength(9);
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

describe("check_password_exposure", () => {
  /** SHA-1("password") and NTLM("password"), uppercase. */
  const SHA1 = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8";
  const NTLM = "8846F7EAEE8FB117AD06BDD830B7586C";
  const range = (entries: Array<{ suffix: string; count: number }>) =>
    response(200, {
      prefix: "5BAA6",
      mode: "sha1",
      suffixLength: 12,
      entries,
      source: "Have I Been Pwned — Pwned Passwords",
      corpusUpdatedAt: "2026-09-30T18:00:00+00:00",
    });

  it("hashes a password locally and sends only the 5-digit prefix", async () => {
    const http = stubHttp({
      get: vi.fn(async () =>
        range([
          { suffix: "000000000001", count: 2 },
          { suffix: SHA1.slice(5, 17), count: 10434004 },
        ]),
      ),
    });
    const res = await make(http).handle(
      call("check_password_exposure", { password: "password" }),
    );
    expect(http.get).toHaveBeenCalledWith(
      "/pwned-passwords/range/5BAA6?mode=sha1",
      expect.objectContaining({ timeoutMs: 10_000 }),
    );
    const sent = JSON.stringify(vi.mocked(http.get).mock.calls);
    expect(sent).not.toContain('password"');
    expect(sent).not.toContain(SHA1.slice(5));
    expect(isError(res)).toBe(false);
    expect(parsed(res)).toMatchObject({
      exposed: true,
      count: 10434004,
      hashType: "sha1",
      corpusUpdatedAt: "2026-09-30T18:00:00+00:00",
    });
    expect(text(res)).not.toContain(SHA1);
  });

  it("looks an NTLM hash up in ntlm mode, case-insensitively", async () => {
    const http = stubHttp({
      get: vi.fn(async () =>
        range([{ suffix: NTLM.slice(5, 17).toLowerCase(), count: 7 }]),
      ),
    });
    const res = await make(http).handle(
      call("check_password_exposure", { ntlm: NTLM.toLowerCase() }),
    );
    expect(http.get).toHaveBeenCalledWith(
      "/pwned-passwords/range/8846F?mode=ntlm",
      expect.anything(),
    );
    expect(parsed(res)).toMatchObject({
      exposed: true,
      count: 7,
      hashType: "ntlm",
    });
  });

  it("reports a hash absent from its range as not exposed", async () => {
    const http = stubHttp({
      get: vi.fn(async () => range([{ suffix: "000000000001", count: 2 }])),
    });
    const res = await make(http).handle(
      call("check_password_exposure", { sha1: SHA1 }),
    );
    expect(parsed(res)).toMatchObject({ exposed: false, count: 0 });
  });

  it.each([
    [{}],
    [{ password: "a", sha1: SHA1 }],
    [{ sha1: "abc" }],
    [{ ntlm: SHA1 }],
    [{ sha1: "Z".repeat(40) }],
  ])("refuses %j without calling the API", async (args) => {
    const http = stubHttp();
    const res = await make(http).handle(call("check_password_exposure", args));
    expect(isError(res)).toBe(true);
    expect(http.get).not.toHaveBeenCalled();
  });

  it("relays an unavailable corpus as a tool error", async () => {
    const http = stubHttp({
      get: vi.fn(async () =>
        response(503, {
          error: "Service unavailable",
          message:
            "The Pwned Passwords corpus is not loaded on this server yet.",
        }),
      ),
    });
    const res = await make(http).handle(
      call("check_password_exposure", { sha1: SHA1 }),
    );
    expect(isError(res)).toBe(true);
  });
});
