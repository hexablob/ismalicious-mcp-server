/**
 * `scan_email`: the request it builds, what it refuses before any call, and the
 * projection of the API's answer. The bodies are real: they are held to what
 * `POST /mail/scan` answers by apps/rust-api/tests/mail_scan.rs
 * (`UPDATE_MCP_FIXTURES=1 cargo test --test mail_scan` rewrites them).
 */
import { describe, expect, it, vi } from "vitest";
import { projectScanEmail } from "../projections/scan-email.js";
import { createServer } from "../server.js";
import { MAX_EML_CHARS } from "../tools/scan-email.js";
import clean from "./fixtures/scan-email-clean.json";
import inconclusive from "./fixtures/scan-email-inconclusive.json";
import malicious from "./fixtures/scan-email-malicious.json";
import structure from "./fixtures/scan-email-structure.json";
import suspicious from "./fixtures/scan-email-suspicious.json";
import { isError, parsed, response, stubHttp } from "./helpers.js";

function make(http = stubHttp()) {
  return createServer({
    baseUrl: "https://x/api",
    apiKeyHeader: "abc",
    http,
  });
}

function call(args: Record<string, unknown>, id = 9) {
  return {
    jsonrpc: "2.0" as const,
    id,
    method: "tools/call",
    params: { name: "scan_email", arguments: args },
  };
}

const bytes = (value: unknown) =>
  Buffer.byteLength(JSON.stringify(value), "utf8");

const EML = "From: a@b.test\r\nSubject: hi\r\n\r\nhello";

describe("scan_email request", () => {
  it("POSTs the raw message to /mail/scan and projects the answer under 4 KB", async () => {
    const http = stubHttp({
      post: vi.fn(async () => response(200, malicious)),
    });
    const res = await make(http).handle(call({ eml: EML }));
    expect(http.post).toHaveBeenCalledWith(
      "/mail/scan",
      { eml: EML },
      expect.objectContaining({ timeoutMs: 20_000 }),
    );
    expect(isError(res)).toBe(false);
    const body = parsed<Record<string, unknown>>(res);
    expect(body.verdict).toBe("malicious");
    expect(body.recommendedAction).toBe("quarantine");
    expect(bytes(body)).toBeLessThan(4096);
    // The client-measured round trip is added by the dispatch.
    expect((body.meta as Record<string, unknown>).latencyMs).toBeTypeOf(
      "number",
    );
  });

  it("sends a parsed message and the context, and drops what the API does not read", async () => {
    const http = stubHttp({
      post: vi.fn(async () => response(200, clean)),
    });
    await make(http).handle(
      call({
        message: {
          headers: [{ name: "From", value: "News <news@brand.com>" }],
          html: "<p>hi</p>",
          attachments: [
            { filename: "a.pdf", sha256: "a".repeat(64), inline: false },
          ],
          surprise: "dropped",
        },
        authservId: " mx.corp.test ",
        trustAuthenticationResults: true,
        trustedHops: 2,
        connectingIp: "8.8.8.8",
      }),
    );
    expect(http.post).toHaveBeenCalledWith(
      "/mail/scan",
      {
        message: {
          headers: [{ name: "From", value: "News <news@brand.com>" }],
          html: "<p>hi</p>",
          attachments: [
            { filename: "a.pdf", sha256: "a".repeat(64), inline: false },
          ],
        },
        context: {
          authservId: "mx.corp.test",
          trustAuthenticationResults: true,
          trustedHops: 2,
          connectingIp: "8.8.8.8",
        },
      },
      expect.anything(),
    );
  });

  it("sends no context when none was given", async () => {
    const http = stubHttp({
      post: vi.fn(async () => response(200, inconclusive)),
    });
    await make(http).handle(call({ eml: EML }));
    const sent = (http.post as ReturnType<typeof vi.fn>).mock.calls[0][1];
    expect(sent).not.toHaveProperty("context");
  });

  it.each([
    ["neither input", {}],
    ["both inputs", { eml: EML, message: { text: "x" } }],
    ["an empty eml", { eml: "  " }],
    ["a non-string eml", { eml: 7 }],
    ["an oversized eml", { eml: "x".repeat(MAX_EML_CHARS + 1) }],
    ["a message that is not an object", { message: "From: a@b.test" }],
    ["an empty message", { message: {} }],
    ["a header list of strings", { message: { headers: ["From: a@b.test"] } }],
    ["a non-string body", { message: { text: 5 } }],
    ["attachments that are not objects", { message: { attachments: ["a"] } }],
    ["trustedHops 0", { eml: EML, trustedHops: 0 }],
    ["trustedHops 11", { eml: EML, trustedHops: 11 }],
    ["a fractional trustedHops", { eml: EML, trustedHops: 1.5 }],
    [
      "a non-boolean trust flag",
      { eml: EML, trustAuthenticationResults: "yes" },
    ],
    ["a non-string connectingIp", { eml: EML, connectingIp: 8 }],
  ])("refuses %s before any request", async (_label, args) => {
    const http = stubHttp();
    const res = await make(http).handle(call(args as Record<string, unknown>));
    expect(http.post).not.toHaveBeenCalled();
    expect(isError(res)).toBe(true);
    expect(parsed(res).error).toBe("invalid_params");
  });

  it("explains a spent scan allowance with the scans quota block", async () => {
    const http = stubHttp({
      post: vi.fn(async () =>
        response(429, {
          error: "Scan quota exceeded",
          usage: 250_001,
          limit: 250_000,
        }),
      ),
    });
    const res = await make(http).handle(call({ eml: EML }));
    expect(isError(res)).toBe(true);
    const body = parsed<{
      error: string;
      quota: { kind: string; used: number; limit: number };
    }>(res);
    expect(body.error).toBe("rate_limited");
    expect(body.quota).toMatchObject({
      kind: "scans",
      used: 250_001,
      limit: 250_000,
    });
  });

  it("is listed with a key and not without one", async () => {
    const withKey = await make().handle({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
    });
    const names = (withKey?.result as { tools: { name: string }[] }).tools.map(
      (t) => t.name,
    );
    expect(names).toContain("scan_email");
    const without = await createServer({
      baseUrl: "https://x/api",
      apiKeyHeader: null,
      http: stubHttp(),
    }).handle({ jsonrpc: "2.0", id: 2, method: "tools/list" });
    expect(
      (without?.result as { tools: { name: string }[] }).tools.map(
        (t) => t.name,
      ),
    ).toEqual(["bootstrap_key"]);
  });
});

describe("scan_email projection", () => {
  it("keeps the API's verdict, action, score and headline and puts the strongest reasons first", () => {
    const p = projectScanEmail(malicious);
    expect(p.verdict).toBe("malicious");
    expect(p.recommendedAction).toBe("quarantine");
    expect(p.riskScore).toBeGreaterThanOrEqual(90);
    expect(p.headline).toBe(malicious.headline);
    expect(p.reasons.length).toBeLessThanOrEqual(6);
    expect(p.reasons[0].code).toBe("attachment.known_malware");
    expect(p.reasons.map((r) => r.code)).toContain("link.listed");
    expect(bytes(p)).toBeLessThan(4096);
  });

  it("defangs hosts and lists the links and files that carry a signal", () => {
    const p = projectScanEmail(malicious);
    expect(p.links.total).toBe(1);
    expect(p.links.flagged).toEqual([
      {
        host: "evil[.]example",
        verdict: "malicious",
        flags: ["anchor_mismatch"],
        shownDomain: "paypal.com",
      },
    ]);
    expect(JSON.stringify(p)).not.toContain("https://evil.example");
    expect(p.attachments.total).toBe(1);
    expect(p.attachments.unknown).toBe(0);
    expect(p.attachments.flagged[0]).toMatchObject({
      filename: "invoice.pdf.exe",
      verdict: "malicious",
      family: "AgentTesla",
    });
    expect(p.connectingIp).toEqual({
      address: "45.83.64.1",
      verdict: "malicious",
    });
  });

  it("says where a link or a file was found and what the bytes are", () => {
    const p = projectScanEmail(structure);
    expect(p.verdict).toBe("malicious");
    // The template address read out of an Office file is a link of its own.
    expect(p.links.flagged[0]).toMatchObject({
      host: "evil[.]example",
      verdict: "malicious",
      origin: "attachment",
      from: "offer.docx",
    });
    const byName = Object.fromEntries(
      p.attachments.flagged.map((file) => [file.filename, file]),
    );
    expect(byName["report.pdf"]).toMatchObject({
      detectedType: "pe",
      flags: expect.arrayContaining(["disguised_program"]),
    });
    expect(byName["offer.docx"]).toMatchObject({
      detectedType: "ooxml",
      flags: expect.arrayContaining(["macro_project", "remote_template"]),
    });
    // A plain image carries no signal: counted, not listed.
    expect(byName["photo.png"]).toBeUndefined();
    expect(p.attachments.total).toBe(3);
    expect(p.reasons.map((r) => r.code)).toEqual(
      expect.arrayContaining([
        "attachment.disguised_program",
        "attachment.macro_project",
        "attachment.remote_template",
      ]),
    );
    expect(bytes(p)).toBeLessThan(4096);
  });

  it("does not count a picture, judged by its bytes, among the files it lacks a verdict on", () => {
    const body = {
      ...inconclusive,
      attachments: [
        {
          filename: "banner.png",
          inline: false,
          verdict: "unknown",
          knownGood: false,
          flags: [],
          detectedType: "image",
          digests: {},
        },
        {
          filename: "offer.bin",
          inline: false,
          verdict: "unknown",
          knownGood: false,
          flags: [],
          detectedType: "unknown",
          digests: {},
        },
        // A message sent as fields has no bytes: nothing says it is a picture.
        {
          filename: "photo.png",
          inline: false,
          verdict: "unknown",
          knownGood: false,
          flags: [],
          digests: {},
        },
      ],
    };
    const p = projectScanEmail(body);
    expect(p.attachments.total).toBe(3);
    expect(p.attachments.unknown).toBe(2);
  });

  it("passes on that the sender's domain can be forged, and the brand it imitates", () => {
    const body = {
      ...suspicious,
      sender: {
        ...suspicious.sender,
        posture: { grade: "B", dmarcPolicy: "none", spoofable: true },
      },
    };
    const p = projectScanEmail(body);
    expect(p.sender.posture).toBe("B");
    expect(p.sender.spoofable).toBe(true);
    // The suspicious fixture's sender publishes neither SPF nor DMARC.
    expect(projectScanEmail(suspicious).sender.spoofable).toBe(true);
    // A policy the DNS answer does not show is not a claim either way.
    expect(projectScanEmail(clean).sender.spoofable).toBeUndefined();
    const brand = p.reasons.find((r) => r.code === "sender.brand_lookalike");
    expect(brand?.evidence).toContain("PayPal");
    expect(brand?.evidence).toContain("paypal[.]com");
  });

  it("says how to let a DMARC pass count only when none could", () => {
    expect(projectScanEmail(inconclusive).authentication.hint).toContain(
      "authservId",
    );
    expect(projectScanEmail(malicious).authentication).toEqual({
      status: "trusted",
      spf: "fail",
      dmarc: "fail",
    });
    const trustedClean = projectScanEmail(clean);
    expect(trustedClean.authentication.status).toBe("trusted");
    expect(trustedClean.authentication.hint).toBeUndefined();
  });

  it("carries inconclusive and clean through untouched, with what was not checked", () => {
    const i = projectScanEmail(inconclusive);
    expect(i.verdict).toBe("inconclusive");
    expect(i.recommendedAction).toBe("deliver");
    expect(i.coverage.skipped.map((s) => s.check)).toContain("authentication");
    const c = projectScanEmail(clean);
    expect(c.verdict).toBe("clean");
    expect(c.recommendedAction).toBe("deliver");
    // A tracking redirect on a popular domain is not a finding worth a list.
    expect(c.links.flagged).toEqual([
      expect.objectContaining({ host: "click[.]mailer[.]test" }),
    ]);
  });

  it("asks for a review when the shape alone is suspicious", () => {
    const p = projectScanEmail(suspicious);
    expect(p.verdict).toBe("suspicious");
    expect(p.recommendedAction).toBe("review");
    expect(p.riskScore).toBeLessThan(90);
    expect(p.reasons.map((r) => r.code)).toContain(
      "headers.display_name_address",
    );
    expect(p.sender.displayName).toBe("support@paypal.com");
  });

  it("never reads a body it cannot understand as an all-clear", () => {
    for (const raw of [null, undefined, {}, "ok", { verdict: "allow" }]) {
      const p = projectScanEmail(raw);
      expect(p.verdict).toBe("inconclusive");
      expect(p.recommendedAction).toBe("review");
      expect(p.headline).toContain("cannot read");
    }
    // A verdict it understands with an action it does not follows the verdict.
    expect(
      projectScanEmail({ verdict: "malicious", recommendedAction: "??" })
        .recommendedAction,
    ).toBe("quarantine");
    expect(
      projectScanEmail({ verdict: "clean", recommendedAction: "??" })
        .recommendedAction,
    ).toBe("review");
  });

  it("keeps the lists short and the result under 4 KB, through the server, for a message carrying a signal on everything", async () => {
    const links = Array.from({ length: 200 }, (_, i) => ({
      url: `https://h${i}.example.com/${"a".repeat(200)}`,
      host: `h${i}.example.com`,
      verdict: i % 2 ? "malicious" : "suspicious",
      sources: 3,
      flags: ["anchor_mismatch", "ip_host", "userinfo", "shortener"],
      shownDomain: "paypal.com",
    }));
    const files = Array.from({ length: 20 }, (_, i) => ({
      filename: `invoice-${i}-${"x".repeat(150)}.pdf.exe`,
      verdict: "malicious",
      family: "AgentTesla".repeat(10),
      flags: ["risky_extension", "double_extension", "type_mismatch"],
    }));
    const reasons = Array.from({ length: 12 }, (_, i) => ({
      code: `link.code_${i}`,
      severity: "high",
      summary: "s".repeat(300),
      evidence: "e".repeat(300),
    }));
    const hostile = { ...malicious, links, attachments: files, reasons };

    const p = projectScanEmail(hostile);
    expect(p.reasons).toHaveLength(6);
    expect(p.links.total).toBe(200);
    expect(p.links.flagged).toHaveLength(6);
    expect(p.attachments.flagged).toHaveLength(6);

    // The projection is written to stay well under the limit on real answers;
    // the dispatch's cap is the guarantee for the day a field grows.
    const http = stubHttp({ post: vi.fn(async () => response(200, hostile)) });
    const res = await make(http).handle(call({ eml: EML }));
    const sent = (res?.result as { content: { text: string }[] }).content[0]
      .text;
    expect(Buffer.byteLength(sent, "utf8")).toBeLessThanOrEqual(4096);
    const body = JSON.parse(sent) as Record<string, unknown>;
    expect(body.verdict).toBe("malicious");
    expect(body.recommendedAction).toBe("quarantine");
  });
});
