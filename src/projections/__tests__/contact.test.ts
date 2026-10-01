/**
 * Tests for the email / phone projection of `check_indicator`, and for the
 * answer to a server that predates email and phone support.
 *
 * The fixtures are the real `/check` bodies: `apps/rust-api/tests/
 * fast_check.rs` (`mcp_contract_fixtures_are_the_real_fast_bodies`) runs the
 * API's handler at `enrichment=fast` over a scripted corpus and fails when a
 * body no longer matches its file here, so these tests read what the API
 * answers, not a copy of the contract written by hand. Rewrite them with
 * `UPDATE_MCP_FIXTURES=1 cargo test --test fast_check` in `apps/rust-api`.
 */
import { describe, expect, it } from "vitest";
import { MAX_RESULT_BYTES } from "../cap.js";
import { projectCheckResult } from "../check-result.js";
import {
  buildContactHeadline,
  projectContact,
  projectUnevaluated,
} from "../contact.js";
import emailListed from "../../__tests__/fixtures/check-email-listed.json";
import emailSenderDomain from "../../__tests__/fixtures/check-email-sender-domain.json";
import emailUnknown from "../../__tests__/fixtures/check-email-unknown.json";
import emailDisposable from "../../__tests__/fixtures/check-email-disposable.json";
import emailFreeProvider from "../../__tests__/fixtures/check-email-free-provider.json";
import phoneListed from "../../__tests__/fixtures/check-phone-listed.json";
import phoneComplaints from "../../__tests__/fixtures/check-phone-complaints.json";
import phoneUnknown from "../../__tests__/fixtures/check-phone-unknown.json";

const size = (v: unknown) => Buffer.byteLength(JSON.stringify(v));

/**
 * What a server from before the contract answers for `user@evil.example`:
 * the IP/domain body of a miss on the key `domain:user@evil.example`.
 */
const legacyDomainMiss = {
  malicious: false,
  apiVersion: "v2",
  enrichmentLevel: "standard",
  processingTime: 2,
  reputation: null,
  blocklistHits: 0,
  blocklistListed: false,
  sources: [],
  riskScore: {
    score: 8,
    level: "safe",
    summary: "No threat source lists this domain.",
  },
};

const ALL = [
  ["check-email-listed", emailListed],
  ["check-email-sender-domain", emailSenderDomain],
  ["check-email-unknown", emailUnknown],
  ["check-email-disposable", emailDisposable],
  ["check-email-free-provider", emailFreeProvider],
  ["check-phone-listed", phoneListed],
  ["check-phone-complaints", phoneComplaints],
  ["check-phone-unknown", phoneUnknown],
] as const;

describe("the API's email and phone bodies", () => {
  it.each(ALL)(
    "%s: relays the API's verdict and action, never clean / allow, under the cap",
    (_name, body) => {
      const p = projectContact(body.entity, body);
      expect(size(p)).toBeLessThanOrEqual(MAX_RESULT_BYTES);
      expect(p.type).toBe(body.type);
      expect(p.indicator).toBe(body.entity);
      expect(p.verdict).toBe(body.verdict);
      expect(p.recommendedAction).toBe(body.recommendedAction);
      expect(p.malicious).toBe(body.malicious);
      expect(p.lookupStatus).toBe(body.lookupStatus);
      expect(p.blocklist.hits).toBe(body.blocklistHits);
      expect(p.meta).toEqual({ enrichment: "fast", processingMs: 2 });
      expect(JSON.stringify(p)).not.toMatch(/"clean"|"allow"/);
    },
  );
});

describe("projectContact (email)", () => {
  it("relays one low-confidence listing as suspicious, with the domain's standing", () => {
    const p = projectContact("billing@invoices-portal.example", emailListed);
    expect(p).toMatchObject({
      indicator: "billing@invoices-portal.example",
      type: "email",
      verdict: "suspicious",
      recommendedAction: "review",
      malicious: false,
      lookupStatus: "found",
      risk: { score: 50, level: "medium" },
      blocklist: { hits: 1, listed: true },
      categories: ["spam", "scam", "abuse"],
      timeline: { firstSeen: "2026-09-01", lastSeen: "2026-09-29" },
      email: {
        domain: "invoices-portal.example",
        disposable: false,
        freeProvider: false,
        mx: true,
        domainReputation: {
          lookupStatus: "unknown",
          malicious: false,
          blocklistHits: 0,
          sources: [],
        },
      },
      flags: { delisted: false },
    });
    expect(p.blocklist.sources).toEqual([
      { name: "Sefinek - Blacklisted Emails", category: "spam" },
    ]);
    expect(p.reasons).toEqual([
      "Address listed by 1 threat feed: Sefinek - Blacklisted Emails (spam, scam, abuse)",
      "Highest source confidence 55/100: below 70, one list is not enough for a malicious verdict",
    ]);
    expect(p.headline).toBe(
      "billing@invoices-portal.example is listed by 1 threat source (spam, scam); the domain invoices-portal.example is not in our dataset; risk 50/100.",
    );
    expect(p).not.toHaveProperty("reportUrl");
  });

  it("calls an unlisted address at a malicious domain malicious, and says why", () => {
    const p = projectContact("ceo@evil.example", emailSenderDomain);
    expect(p).toMatchObject({
      verdict: "malicious",
      recommendedAction: "block",
      lookupStatus: "unknown",
      blocklist: { hits: 0, listed: false, sources: [] },
      email: {
        mx: null,
        domainReputation: {
          lookupStatus: "found",
          malicious: true,
          blocklistHits: 2,
          sources: ["OpenPhish - Community Feed", "PhishTank - Online Valid"],
        },
      },
    });
    expect(p.headline).toBe(
      "ceo@evil.example is not listed itself; the domain evil.example is malicious (2 threat listings); risk 75/100.",
    );
    expect(p.reasons?.[0]).toContain("Sender domain evil.example is malicious");
  });

  it("calls an address no source holds unknown / unverified, never clean", () => {
    const p = projectContact("nobody@example.org", emailUnknown);
    expect(p.verdict).toBe("unknown");
    expect(p.recommendedAction).toBe("unverified");
    expect(p.malicious).toBe(false);
    expect(p.lookupStatus).toBe("unknown");
    // A 0 "inconclusive" score measured nothing: only the summary is kept.
    expect(p.risk).toEqual({
      summary:
        "No evidence about nobody@example.org: unverified, not a clean verdict",
    });
    // Cache-only: no DNS answer cached is `null`, not `false`.
    expect(p.email?.mx).toBeNull();
    expect(p.reasons).toHaveLength(4);
    expect(p).not.toHaveProperty("timeline");
    expect(p.headline).toBe(
      "nobody@example.org is not in any source we hold; the domain example.org is not in our dataset; absence is not evidence of safety.",
    );
  });

  it("names a disposable domain and its null MX, not a missing listing", () => {
    const p = projectContact("signup@tempinbox.example", emailDisposable);
    expect(p).toMatchObject({
      verdict: "suspicious",
      recommendedAction: "review",
      risk: { score: 50, level: "medium" },
      email: {
        disposable: true,
        mx: false,
        domainReputation: {
          lookupStatus: "found",
          blocklistHits: 0,
          infrastructure: ["disposable-email"],
        },
      },
    });
    expect(p.headline).toBe(
      "signup@tempinbox.example is not listed itself; tempinbox.example is a disposable mail provider; tempinbox.example publishes a null MX (it accepts no mail); risk 50/100.",
    );
  });

  it("does not hold a shared provider's listings against the address", () => {
    // gmx.com sits on the two aggregate disposable lists: an attribute of
    // the provider, never a verdict on one of its mailboxes.
    const p = projectContact("someone@gmx.com", emailFreeProvider);
    expect(p).toMatchObject({
      verdict: "unknown",
      recommendedAction: "unverified",
      email: {
        freeProvider: true,
        disposable: false,
        domainReputation: { infrastructure: ["disposable-email"] },
      },
    });
    expect(p.headline).toBe(
      "someone@gmx.com is not in any source we hold; gmx.com is a shared mail provider, whose reputation is not the address's; absence is not evidence of safety.",
    );
  });

  it("names threat listings on a domain that is short of malicious", () => {
    const p = projectContact("a@listed.example", {
      ...emailSenderDomain,
      entity: "a@listed.example",
      verdict: "suspicious",
      recommendedAction: "review",
      malicious: false,
      riskScore: { score: 50, level: "medium", factors: [] },
      email: {
        ...emailSenderDomain.email,
        domain: "listed.example",
        domainReputation: {
          ...emailSenderDomain.email.domainReputation,
          malicious: false,
        },
      },
    });
    expect(p.headline).toBe(
      "a@listed.example is not listed itself; the domain listed.example has 2 threat listings; risk 50/100.",
    );
  });

  it("keeps only the verdicts and actions the contract allows", () => {
    // `clean` is not a value these types may take: absence is not safety.
    const clean = projectContact("a@b.example", {
      ...emailUnknown,
      verdict: "clean",
      recommendedAction: "allow",
    });
    expect(clean.verdict).toBe("unknown");
    expect(clean.recommendedAction).toBe("unverified");
    // A valid verdict with an unknown action gets the verdict's action.
    const odd = projectContact("a@b.example", {
      ...emailSenderDomain,
      recommendedAction: "allow",
    });
    expect(odd.verdict).toBe("malicious");
    expect(odd.recommendedAction).toBe("block");
    const missing = projectContact("a@b.example", { type: "email" });
    expect(missing.verdict).toBe("unknown");
    expect(missing.recommendedAction).toBe("unverified");
    expect(missing.email).toBeUndefined();
  });

  it("says a delisting removed the listings", () => {
    const p = projectContact("a@b.example", {
      ...emailUnknown,
      entity: "a@b.example",
      delisted: true,
      lookupStatus: "found",
    });
    expect(p.flags.delisted).toBe(true);
    expect(p.headline).toContain("a delisting removed its listings");
  });
});

describe("projectContact (phone)", () => {
  it("relays a number a curated list corroborates as malicious", () => {
    const p = projectContact("+14155552671", phoneListed, {
      input: "+1 415 555 2671",
    });
    expect(p).toMatchObject({
      indicator: "+14155552671",
      input: "+1 415 555 2671",
      type: "phone",
      verdict: "malicious",
      recommendedAction: "block",
      lookupStatus: "found",
      categories: ["robocall", "scam", "spam"],
      phone: {
        e164: "+14155552671",
        countryCallingCode: "1",
        resolvedWith: "e164",
      },
    });
    expect(p.blocklist.sources.map((s) => s.name)).toEqual([
      "CallShield - Hot Spam Numbers",
      "FTC - Do Not Call Reported Numbers",
    ]);
    expect(p.headline).toBe(
      "+14155552671 is listed by 2 threat sources (robocall, scam); risk 75/100.",
    );
    expect(p).not.toHaveProperty("email");
  });

  it("relays two complaint feeds as suspicious / review, and how the number was read", () => {
    const p = projectContact("(202) 555-0143", phoneComplaints, {
      input: "(202) 555-0143",
    });
    expect(p).toMatchObject({
      indicator: "+12025550143",
      input: "(202) 555-0143",
      verdict: "suspicious",
      recommendedAction: "review",
      malicious: false,
      risk: { score: 55, level: "medium" },
      blocklist: { hits: 2, listed: true },
      phone: { e164: "+12025550143", resolvedWith: "nanp-guess" },
    });
    expect(p.reasons).toHaveLength(3);
    expect(p.headline).toBe(
      "+12025550143 is listed by 2 threat sources (robocall, scam); read as a North American number (pass an E.164 number or country for another country); risk 55/100.",
    );
  });

  it("headlines an unknown number with the absence caveat, in E.164", () => {
    const p = projectContact("06 12 34 56 78", phoneUnknown, {
      input: "06 12 34 56 78",
    });
    expect(p.indicator).toBe("+33612345678");
    expect(p.input).toBe("06 12 34 56 78");
    expect(p.verdict).toBe("unknown");
    expect(p.recommendedAction).toBe("unverified");
    expect(p.phone).toEqual({
      e164: "+33612345678",
      countryCallingCode: "33",
      resolvedWith: "country",
    });
    expect(p.headline).toBe(
      "+33612345678 is not in any source we hold; absence is not evidence of safety.",
    );
  });

  it("says when a number's country could not be told", () => {
    const guess = buildContactHeadline({
      indicator: "+14155552671",
      type: "phone",
      verdict: "unknown",
      hits: 0,
      categories: [],
      delisted: false,
      phone: {
        e164: "+14155552671",
        countryCallingCode: "1",
        resolvedWith: "nanp-guess",
      },
    });
    expect(guess).toContain("read as a North American number");
    const digits = projectContact("12345678", {
      ...phoneUnknown,
      entity: "12345678",
      phone: {
        input: "12345678",
        e164: null,
        countryCallingCode: null,
        resolvedWith: "digits",
      },
    });
    expect(digits.phone).toEqual({
      e164: null,
      countryCallingCode: null,
      resolvedWith: "digits",
    });
    expect(digits.headline).toContain("its country could not be told");
  });
});

describe("projectCheckResult", () => {
  it("routes by the API's declared type", () => {
    const p = projectCheckResult(
      "billing@invoices-portal.example",
      emailListed,
      { localType: "email" },
    );
    expect(p.type).toBe("email");
    expect(p.verdict).toBe("suspicious");
    // The API is the authority when the local typing disagreed.
    const q = projectCheckResult("odd-input", phoneListed, {
      localType: "domain",
    });
    expect(q.type).toBe("phone");
  });

  it("never turns an old server's domain miss for an address into clean / allow", () => {
    for (const [indicator, localType] of [
      ["user@evil.example", "email"],
      ["+33612345678", "phone"],
    ] as const) {
      const p = projectCheckResult(indicator, legacyDomainMiss, {
        localType,
        requestedEnrichment: "fast",
      });
      expect(p.verdict).toBe("unknown");
      expect(p.recommendedAction).toBe("unverified");
      expect(p.malicious).toBe(false);
      expect(p.type).toBe(localType);
      expect(p).toHaveProperty("note");
      expect(JSON.stringify(p)).not.toMatch(/"clean"|"allow"/);
    }
    const p = projectUnevaluated("user@evil.example", "email", {
      ...legacyDomainMiss,
      type: "domain",
    });
    expect(p.headline).toBe(
      "user@evil.example was not evaluated as an email address: no verdict either way, which is not a clean verdict.",
    );
    expect(p.note).toContain("it answered as domain");
    expect(p.meta).toEqual({ enrichment: "standard", processingMs: 2 });
  });

  it("leaves IP, domain, URL and hash bodies to the historical projection", () => {
    const p = projectCheckResult("example.com", legacyDomainMiss, {
      localType: "domain",
    });
    expect(p.type).toBe("domain");
    expect(p.verdict).toBe("clean");
  });
});
