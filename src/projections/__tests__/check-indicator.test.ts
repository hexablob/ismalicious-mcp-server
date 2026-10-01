import { describe, expect, it } from "vitest";
import { capResult, MAX_RESULT_BYTES } from "../cap.js";
import {
  buildHeadline,
  detectIndicatorType,
  projectCheckIndicator,
  verdictFromCheck,
} from "../check-indicator.js";
import domainFixture from "../../__tests__/fixtures/check-domain.json";
import cloudOnlyFixture from "../../__tests__/fixtures/check-ip-cloud-only.json";
import ipFixture from "../../__tests__/fixtures/check-ip-malicious.json";
import mixedFixture from "../../__tests__/fixtures/check-ip-mixed.json";
import hashFixture from "../../__tests__/fixtures/check-hash-malware.json";
// Real `enrichment=fast` bodies, written and held to the handler's output by
// `apps/rust-api/tests/fast_check.rs`.
import domainFastPending from "../../__tests__/fixtures/check-domain-fast-pending.json";
import hashFastPending from "../../__tests__/fixtures/check-hash-fast-pending.json";

const size = (v: unknown) => Buffer.byteLength(JSON.stringify(v));

describe("projectCheckIndicator", () => {
  it("reduces a 37 KB malicious IP document to under the cap, keeping the decision fields", () => {
    expect(size(ipFixture)).toBeGreaterThan(30_000);
    const p = projectCheckIndicator("45.148.10.242", ipFixture);
    expect(size(p)).toBeLessThanOrEqual(MAX_RESULT_BYTES);
    expect(p.type).toBe("ip");
    expect(p.verdict).toBe("malicious");
    expect(p.recommendedAction).toBe("block");
    expect(p.malicious).toBe(true);
    expect(p.blocklist.listed).toBe(true);
    expect(p.blocklist.sources.length).toBeLessThanOrEqual(10);
    expect(p.blocklist.hits).toBeGreaterThanOrEqual(p.blocklist.sources.length);
    expect(p.network?.countryCode).toBeDefined();
    expect(p.headline).toMatch(/flagged malicious by \d+ sources?/);
    expect(p.reportUrl).toBe(
      "https://ismalicious.com/report?query=45.148.10.242",
    );
    expect(p.risk?.score).toBeTypeOf("number");
  });

  it("projects a domain document with registration context", () => {
    const p = projectCheckIndicator("mo3i5n46.de", domainFixture);
    expect(size(p)).toBeLessThanOrEqual(MAX_RESULT_BYTES);
    expect(p.type).toBe("domain");
    expect(["malicious", "suspicious", "clean"]).toContain(p.verdict);
    expect(p.flags).toEqual(
      expect.objectContaining({
        delisted: expect.any(Boolean),
        knownGood: expect.any(Boolean),
      }),
    );
  });

  it("handles a clean, never-seen indicator", () => {
    const p = projectCheckIndicator("example.com", {
      malicious: false,
      reputation: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 },
      sources: [],
    });
    expect(p.verdict).toBe("clean");
    expect(p.recommendedAction).toBe("allow");
    expect(p.headline).toBe("example.com is not listed by any of our sources.");
    expect(p.blocklist).toEqual({ hits: 0, listed: false, sources: [] });
  });

  it("handles a known-good hash and a suspicious one", () => {
    const sha = "a".repeat(64);
    const good = projectCheckIndicator(sha, {
      malicious: false,
      sources: [],
      knownGood: true,
      hashInfo: { nsrl: true },
    });
    expect(good.type).toBe("hash");
    expect(good.verdict).toBe("clean");
    expect(good.headline).toContain("known-good");
    const sus = projectCheckIndicator(sha, {
      malicious: false,
      reputation: { malicious: 0, suspicious: 2 },
      sources: [{ name: "x", type: "hash" }, { name: "y" }],
    });
    expect(sus.verdict).toBe("suspicious");
    expect(sus.recommendedAction).toBe("review");
    expect(sus.blocklist.sources).toEqual([
      { name: "x", category: "hash" },
      { name: "y" },
    ]);
  });

  it("sends a hash NSRL knows and a feed lists to review, never to block", () => {
    // `/check?hash=` keeps `malicious: true` for the feed listing and adds
    // `knownGood` for NSRL: the two contradict, and the API leaves the call
    // to the reader.
    const sha = "b".repeat(64);
    const p = projectCheckIndicator(sha, {
      malicious: true,
      knownGood: true,
      lookupStatus: "known",
      reputation: { malicious: 2, suspicious: 0, harmless: 0, undetected: 0 },
      sources: [
        { name: "feed-a", type: "hash" },
        { name: "feed-b", type: "hash" },
      ],
      hashInfo: { hashType: "sha256", hash: sha, nsrl: true },
      riskScore: { score: 85, level: "critical" },
    });
    expect(p.type).toBe("hash");
    expect(p.verdict).toBe("suspicious");
    expect(p.recommendedAction).toBe("review");
    expect(p.malicious).toBe(false);
    expect(p.blocklist.listed).toBe(true);
    expect(p.blocklist.hits).toBe(2);
    expect(p.flags.knownGood).toBe(true);
    expect(p.headline).toBe(
      `${sha} is known software (NSRL), yet 2 sources list it; review before blocking; risk 85/100.`,
    );
  });

  it("surfaces a breached-password match beside an unknown file verdict", () => {
    const ntlm = "8846f7eaee8fb117ad06bdd830b7586c";
    const p = projectCheckIndicator(ntlm, {
      malicious: false,
      lookupStatus: "unknown",
      sources: [],
      pwnedPassword: {
        found: true,
        hashType: "ntlm",
        count: 52372427,
        source: "Have I Been Pwned — Pwned Passwords",
      },
    });
    expect(p.verdict).toBe("unknown");
    expect(p.pwnedPassword).toEqual({ hashType: "ntlm", count: 52372427 });
    expect(p.headline).toMatch(
      /It is also the NTLM hash of a password seen 52,372,427 times in data breaches\.$/,
    );
  });

  it("leaves pwnedPassword out when the API sent none", () => {
    const p = projectCheckIndicator("e".repeat(40), {
      malicious: false,
      lookupStatus: "unknown",
      sources: [],
    });
    expect(p).not.toHaveProperty("pwnedPassword");
    expect(p.headline).not.toMatch(/password/);
  });

  it("keeps blocking a listed hash NSRL does not know", () => {
    const sha = "c".repeat(64);
    const p = projectCheckIndicator(sha, {
      malicious: true,
      knownGood: false,
      reputation: { malicious: 1 },
      sources: [{ name: "feed-a", type: "hash" }],
    });
    expect(p.verdict).toBe("malicious");
    expect(p.recommendedAction).toBe("block");
    expect(p.malicious).toBe(true);
  });

  it("calls a hash no source has seen unknown, never clean", () => {
    // The shape `/check?hash=` returns for a miss: a full document with
    // zeroed counters, which the gate ladder alone reads as clean.
    const sha = "e".repeat(64);
    const summary =
      "Unknown hash: no malicious or trusted evidence is available. This score is not a safety verdict.";
    const p = projectCheckIndicator(sha, {
      malicious: false,
      lookupStatus: "unknown",
      reputation: {
        malicious: 0,
        suspicious: 0,
        harmless: 0,
        undetected: 0,
        timeout: 0,
      },
      sources: [],
      blocklistHits: 0,
      hashInfo: { hashType: "sha256", hash: sha },
      riskScore: { score: 5, level: "safe", summary },
    });
    expect(p.type).toBe("hash");
    expect(p.verdict).toBe("unknown");
    expect(p.recommendedAction).toBe("unverified");
    expect(p.risk).toEqual({ summary });
    expect(p.headline).toBe(
      `${sha} is unknown to our sources: no evidence either way, which is not a clean verdict.`,
    );
  });

  it("calls an IP listed only by cloud ranges clean, and says what it is", () => {
    // reputation is null on stored documents, so this is the fallback path
    // that used to send every Office 365 range hit to review.
    const p = projectCheckIndicator("13.107.6.152", cloudOnlyFixture);
    expect(size(p)).toBeLessThanOrEqual(MAX_RESULT_BYTES);
    expect(p.verdict).toBe("clean");
    expect(p.recommendedAction).toBe("allow");
    expect(p.malicious).toBe(false);
    expect(p.blocklist).toEqual({ hits: 0, listed: false, sources: [] });
    expect(p.infrastructure).toEqual({
      attributes: ["cloud", "saas"],
      sources: [
        {
          name: "Azure IP Ranges",
          category: "infrastructure",
          threatClass: "infrastructure",
        },
        {
          name: "Microsoft 365 endpoints",
          category: "infrastructure",
          threatClass: "infrastructure",
        },
      ],
    });
    expect(p.headline).toBe(
      "13.107.6.152 is not listed by any threat source; known infrastructure: cloud, saas; risk 12/100.",
    );
  });

  it("keeps the honeypot verdict when a threat listing and a cloud range coexist", () => {
    const p = projectCheckIndicator("20.55.12.9", mixedFixture);
    expect(p.verdict).toBe("malicious");
    expect(p.recommendedAction).toBe("block");
    expect(p.blocklist).toEqual({
      hits: 1,
      listed: true,
      sources: [{ name: "GreenSnow - Attackers", category: "attack" }],
    });
    expect(p.infrastructure?.attributes).toEqual(["cloud"]);
    expect(p.infrastructure?.sources).toEqual([
      {
        name: "Azure IP Ranges",
        category: "infrastructure",
        threatClass: "infrastructure",
      },
    ]);
    expect(p.headline).toBe(
      "20.55.12.9 is flagged malicious by 1 source (bruteforce); risk 72/100; seen from 2026-09-15 to 2026-09-17; known infrastructure: cloud.",
    );
  });

  it("derives attributes from listing categories when the server sends no infrastructure block", () => {
    const p = projectCheckIndicator("185.220.101.1", {
      malicious: false,
      sources: [
        {
          name: "Tor exit nodes",
          category: "tor",
          threatClass: "infrastructure",
        },
        {
          name: "Warninglist URL shorteners",
          category: "allowlist",
          threatClass: "allowlist",
        },
        { name: "Ad hosts", category: "ads", threatClass: "policy" },
      ],
      riskScore: { level: "high" },
    });
    expect(p.verdict).toBe("clean");
    expect(p.infrastructure?.attributes).toEqual(["allowlist", "tor-exit"]);
    expect(p.infrastructure?.sources.map((s) => s.threatClass)).toEqual([
      "infrastructure",
      "allowlist",
      "policy",
    ]);
    expect(p.headline).toBe(
      "185.220.101.1 is not listed by any threat source; known infrastructure: allowlist, tor-exit.",
    );
  });

  it("omits the infrastructure block when every listing is a threat listing", () => {
    const p = projectCheckIndicator("45.148.10.242", ipFixture);
    expect(p.infrastructure).toBeUndefined();
  });

  it("returns unknown for a body that is not a check document", () => {
    const p = projectCheckIndicator("1.2.3.4", { error: "weird" });
    expect(p.verdict).toBe("unknown");
    expect(p.recommendedAction).toBe("unverified");
  });

  it("truncates the source list and says so", () => {
    const sources = Array.from({ length: 30 }, (_, i) => ({
      name: `list-${i}`,
      type: "ip",
    }));
    const p = projectCheckIndicator("1.2.3.4", {
      malicious: true,
      sources,
      reputation: { malicious: 30 },
    });
    expect(p.blocklist.sources).toHaveLength(10);
    expect(p.blocklist.truncated).toBe(true);
    expect(p.blocklist.hits).toBe(30);
  });
});

describe("projectCheckIndicator: what an agent cites", () => {
  const sha = hashFixture.hashInfo.sha256;

  it("names a known hash's family, file and alias listing, under the cap", () => {
    const p = projectCheckIndicator(sha, hashFixture);
    expect(size(p)).toBeLessThanOrEqual(MAX_RESULT_BYTES);
    expect(p.type).toBe("hash");
    expect(p.verdict).toBe("malicious");
    expect(p.lookupStatus).toBe("known");
    expect(p.categories).toEqual(["malware", "stealer"]);
    expect(p.file).toEqual({
      family: "AgentTesla",
      fileType: "exe",
      mimeType: "application/x-dosexec",
      fileName: "Invoice_2026-09_payment_confirmation_scan.exe",
      sizeBytes: 734208,
      tags: ["AgentTesla", "exe", "RAT", "stealer"],
      // The queried SHA-256 is `indicator`; only the other digests are kept.
      digests: {
        md5: hashFixture.hashInfo.md5,
        sha1: hashFixture.hashInfo.sha1,
      },
    });
    expect(p.blocklist.sources).toContainEqual({
      name: "Hybrid Analysis - Malicious Samples",
      category: "malware",
      via: "alias",
    });
    expect(p.timeline).toEqual({
      firstSeen: "2026-09-27",
      lastSeen: "2026-09-29",
    });
    expect(p.headline).toBe(
      `${sha} is flagged malicious by 3 sources (AgentTesla); risk 92/100; seen from 2026-09-27 to 2026-09-29.`,
    );
  });

  it("never surfaces OTX pulse content", () => {
    const text = JSON.stringify(projectCheckIndicator(sha, hashFixture));
    expect(text).not.toContain("pulse");
    expect(text).not.toContain("logistics");
    expect(text).not.toContain("otx");
  });

  it("keeps the top three evidence reasons, without repeating the risk summary", () => {
    const ip = projectCheckIndicator("45.148.10.242", ipFixture);
    expect(ip.reasons).toEqual([
      "Primary classification: suspicious",
      "42 sources list this entity (weighted strength 23.10)",
      "Provider disagreement requires analyst review",
    ]);
    expect(ip.reasons).not.toContain(ip.risk?.summary);
    expect(projectCheckIndicator("20.55.12.9", mixedFixture).reasons).toEqual([
      "Listed by GreenSnow - Attackers (attack) in the last 48h",
    ]);
  });

  it("falls back to the score factors that raised the score, largest first", () => {
    const p = projectCheckIndicator("1.2.3.4", {
      malicious: true,
      sources: [{ name: "a" }],
      riskScore: {
        score: 70,
        level: "high",
        factors: [
          { description: "Small push", contribution: 3 },
          { description: "Held neutral", contribution: 0 },
          { description: "Big push", contribution: 40 },
          { contribution: 12 },
        ],
      },
    });
    expect(p.reasons).toEqual(["Big push", "Small push"]);
  });

  it("stays under the cap on every committed fixture", () => {
    for (const [indicator, fixture] of [
      ["45.148.10.242", ipFixture],
      ["mo3i5n46.de", domainFixture],
      ["13.107.6.152", cloudOnlyFixture],
      ["20.55.12.9", mixedFixture],
      [sha, hashFixture],
      ["cold.example", domainFastPending],
      [hashFastPending.hashInfo.hash, hashFastPending],
    ] as const) {
      expect(size(projectCheckIndicator(indicator, fixture))).toBeLessThan(
        MAX_RESULT_BYTES * 0.6,
      );
    }
  });

  it("reports pending facets from the fast level and asks for a re-check", () => {
    // A listed domain nothing had enriched: scored from its listings alone.
    const p = projectCheckIndicator("cold.example", domainFastPending);
    expect(p.meta).toMatchObject({
      enrichment: "fast",
      pending: ["dns", "whois", "geo", "certificates", "otx"],
    });
    expect(p.verdict).toBe("suspicious");
    expect(p.headline).toBe(
      "cold.example is flagged suspicious by 1 source; risk 24/100. Not cached yet: dns, whois, geo, certificates, otx; one re-check after a few seconds may complete them. If they are still pending then, this answer stands: do not re-check again.",
    );
    expect(
      projectCheckIndicator("1.2.3.4", ipFixture).meta?.pending,
    ).toBeUndefined();
  });

  it("promises a re-check only when something is pending, and only one", () => {
    // An empty `pending` (the API lists a facet only while a warm can fill
    // it) is a complete answer: no hint, no meta.pending.
    const settled = projectCheckIndicator("cold.example", {
      ...domainFastPending,
      pending: [],
    });
    expect(settled.meta?.pending).toBeUndefined();
    expect(settled.headline).not.toMatch(/re-check|Not cached/);
    // A pending answer asks for one re-check and says when to stop: every
    // re-check is a billed request.
    const pending = projectCheckIndicator("cold.example", domainFastPending);
    expect(pending.headline).toMatch(/one re-check after a few seconds/);
    expect(pending.headline).toMatch(/do not re-check again/);
    expect(pending.headline).not.toMatch(/re-check in a few seconds/);
  });

  it("calls a hash whose CIRCL lookup outran the deadline unknown and pending, never clean", () => {
    const hash = hashFastPending.hashInfo.hash;
    const p = projectCheckIndicator(hash, hashFastPending);
    expect(p).toMatchObject({
      type: "hash",
      verdict: "unknown",
      recommendedAction: "unverified",
      malicious: false,
      lookupStatus: "unknown",
      meta: { enrichment: "fast", pending: ["circl"] },
    });
    // The API still sends its 0-100 score; for an unseen hash it measures
    // nothing.
    expect(p.risk).not.toHaveProperty("score");
    expect(p.headline).toBe(
      `${hash} is unknown to our sources: no evidence either way, which is not a clean verdict. Not cached yet: circl; one re-check after a few seconds may complete it. If it is still pending then, this answer stands: do not re-check again.`,
    );
  });

  it("reports the input when refanging changed it", () => {
    expect(
      projectCheckIndicator("evil.com", ipFixture, { input: "evil[.]com" })
        .input,
    ).toBe("evil[.]com");
    expect(
      projectCheckIndicator("evil.com", ipFixture, { input: "Evil.com" }),
    ).not.toHaveProperty("input");
  });
});

describe("verdictFromCheck mirrors gate.rs", () => {
  it("five suspicious hits count as malicious, one as suspicious", () => {
    expect(verdictFromCheck({ reputation: { suspicious: 5 } })).toBe(
      "malicious",
    );
    expect(verdictFromCheck({ reputation: { suspicious: 1 } })).toBe(
      "suspicious",
    );
    expect(verdictFromCheck({ reputation: { suspicious: 0 } })).toBe("clean");
    expect(verdictFromCheck({})).toBe("unknown");
  });
  it("reads lookupStatus before the zeroed counters of an unseen hash", () => {
    const miss = {
      malicious: false,
      lookupStatus: "unknown",
      reputation: { malicious: 0, suspicious: 0 },
      sources: [],
    };
    expect(verdictFromCheck(miss)).toBe("unknown");
    // NSRL membership is evidence: a known-good file is clean.
    expect(verdictFromCheck({ ...miss, knownGood: true })).toBe("clean");
    expect(verdictFromCheck({ ...miss, lookupStatus: "known" })).toBe("clean");
  });
  it("never calls a cited indicator clean when reputation counts are missing", () => {
    expect(
      verdictFromCheck({
        malicious: false,
        sources: [{ name: "a" }],
        riskScore: { level: "high" },
      }),
    ).toBe("malicious");
    expect(
      verdictFromCheck({
        malicious: false,
        sources: [{ name: "a" }],
        riskScore: { level: "low" },
      }),
    ).toBe("suspicious");
    expect(verdictFromCheck({ malicious: false, sources: [] })).toBe("clean");
  });
  it("ignores infrastructure, policy and allowlist listings in the fallback", () => {
    for (const threatClass of ["infrastructure", "policy", "allowlist"]) {
      expect(
        verdictFromCheck({
          malicious: false,
          sources: [{ name: "a", threatClass }],
          riskScore: { level: "high" },
        }),
      ).toBe("clean");
    }
    expect(
      verdictFromCheck({
        malicious: false,
        sources: [
          { name: "a", threatClass: "infrastructure" },
          { name: "b", threatClass: "threat" },
        ],
        riskScore: { level: "low" },
      }),
    ).toBe("suspicious");
    // An explicit malicious flag or reputation counts still win.
    expect(
      verdictFromCheck({
        malicious: true,
        sources: [{ name: "a", threatClass: "infrastructure" }],
      }),
    ).toBe("malicious");
  });
});

describe("verdictFromCheck and NSRL", () => {
  const listed = {
    malicious: true,
    knownGood: true,
    lookupStatus: "known",
    sources: [{ name: "feed-a" }],
  };
  it("caps malicious at suspicious whichever rule reached it", () => {
    // The explicit flag, the reputation counts and the risk-level fallback.
    expect(verdictFromCheck(listed)).toBe("suspicious");
    expect(
      verdictFromCheck({
        knownGood: true,
        reputation: { malicious: 3, suspicious: 0 },
      }),
    ).toBe("suspicious");
    expect(
      verdictFromCheck({
        knownGood: true,
        reputation: { malicious: 0, suspicious: 5 },
      }),
    ).toBe("suspicious");
    expect(
      verdictFromCheck({
        malicious: false,
        knownGood: true,
        sources: [{ name: "a" }],
        riskScore: { level: "critical" },
      }),
    ).toBe("suspicious");
  });
  it("leaves the other verdicts alone", () => {
    expect(
      verdictFromCheck({
        knownGood: true,
        reputation: { malicious: 0, suspicious: 2 },
      }),
    ).toBe("suspicious");
    expect(
      verdictFromCheck({ malicious: false, knownGood: true, sources: [] }),
    ).toBe("clean");
    expect(
      verdictFromCheck({
        malicious: false,
        knownGood: true,
        sources: [{ name: "a", threatClass: "allowlist" }],
        riskScore: { level: "high" },
      }),
    ).toBe("clean");
  });
  it("only a true flag counts", () => {
    for (const knownGood of [false, undefined, "true", 1, null]) {
      expect(verdictFromCheck({ ...listed, knownGood })).toBe("malicious");
    }
  });
});

describe("detectIndicatorType", () => {
  it("classifies without a declared type", () => {
    expect(detectIndicatorType("8.8.8.8", {})).toBe("ip");
    expect(detectIndicatorType("2001:db8::1", {})).toBe("ip");
    // Was typed `domain` by the old /^[0-9a-f:]+$/ test.
    expect(detectIndicatorType("::ffff:1.2.3.4", {})).toBe("ip");
    expect(detectIndicatorType("user@example.com", {})).toBe("email");
    expect(detectIndicatorType("+14155552671", {})).toBe("phone");
    expect(detectIndicatorType("x", { type: "phone" })).toBe("phone");
    expect(detectIndicatorType("https://a.b/c", {})).toBe("url");
    expect(detectIndicatorType("a.b/c", {})).toBe("url");
    expect(detectIndicatorType("a.b", {})).toBe("domain");
    expect(detectIndicatorType("d41d8cd98f00b204e9800998ecf8427e", {})).toBe(
      "hash",
    );
  });
});

describe("buildHeadline", () => {
  it("formats dates and categories", () => {
    expect(
      buildHeadline("1.2.3.4", "malicious", {
        hits: 4,
        category: "botnet_cc",
        riskScore: 82,
        firstSeen: "2026-01-02",
        lastSeen: "2026-08-30",
        knownGood: false,
        delisted: false,
      }),
    ).toBe(
      "1.2.3.4 is flagged malicious by 4 sources (botnet_cc); risk 82/100; seen from 2026-01-02 to 2026-08-30.",
    );
    expect(
      buildHeadline("x", "suspicious", {
        hits: 1,
        knownGood: false,
        delisted: true,
      }),
    ).toBe(
      "x is flagged suspicious by 1 source (delisted since; treat as historical).",
    );
  });
});

describe("buildHeadline and NSRL", () => {
  it("names the conflict, and stays out of the way with no listing", () => {
    expect(
      buildHeadline("h", "suspicious", {
        hits: 1,
        knownGood: true,
        delisted: false,
      }),
    ).toBe(
      "h is known software (NSRL), yet 1 source lists it; review before blocking.",
    );
    expect(
      buildHeadline("h", "suspicious", {
        hits: 0,
        knownGood: true,
        delisted: false,
      }),
    ).toBe("h is flagged suspicious by 0 sources.");
  });
});

describe("capResult", () => {
  it("leaves small values alone and marks shrunk ones", () => {
    expect(capResult({ a: 1 })).toEqual({ a: 1 });
    const big = {
      list: Array.from({ length: 500 }, (_, i) => ({
        i,
        text: "x".repeat(200),
      })),
    };
    const capped = capResult(big) as { truncated: boolean };
    expect(Buffer.byteLength(JSON.stringify(capped))).toBeLessThanOrEqual(
      MAX_RESULT_BYTES,
    );
    expect(capped.truncated).toBe(true);
  });
});
