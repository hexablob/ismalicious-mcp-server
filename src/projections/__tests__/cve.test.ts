import { describe, expect, it } from "vitest";
import {
  deriveReferences,
  normalizeCveId,
  projectCve,
  projectRecentCves,
} from "../cve.js";

describe("normalizeCveId", () => {
  it("uppercases valid ids and rejects the rest", () => {
    expect(normalizeCveId(" cve-2021-44228 ")).toBe("CVE-2021-44228");
    expect(normalizeCveId("CVE-2021-1")).toBeNull();
    expect(normalizeCveId("log4shell")).toBeNull();
    expect(normalizeCveId(42)).toBeNull();
  });
});

describe("projectCve", () => {
  const enriched = {
    id: "CVE-2021-44228",
    description:
      "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP.",
    severity: "CRITICAL",
    cvssScore: 10,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    published: "2021-12-10T10:15:00+00:00",
    lastModified: "2025-01-01T00:00:00+00:00",
    opencveTitle: "Log4Shell",
    epssScore: 0.97565,
    epssPercent: 97.6,
    isKev: true,
    kev: {
      listed: true,
      dateAdded: "2021-12-10",
      dueDate: "2021-12-24",
      requiredAction: "Apply updates per vendor instructions.",
      ransomwareUse: "Known",
      shortDescription: "JNDI RCE",
    },
    ssvcExploitation: "active",
    zdcIsWeaponized: true,
    zdcIsZeroDay: true,
    zdcExploitCount: 12,
    msrcExploited: false,
    hasNucleiTemplate: true,
    exploitdbIds: "50592,50590,50593,50594,50595,50596",
    ghsaIds: ["GHSA-jfh8-c2jp-5v3q"],
    certfrLink: "https://www.cert.ssi.gouv.fr/alerte/CERTFR-2021-ALE-022/",
    references: [
      { source: "nvd", url: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" },
      { source: "cisa-kev", url: "https://www.cisa.gov/kev" },
    ],
  };

  it("projects the enriched Rust body", () => {
    const p = projectCve(enriched, "CVE-2021-44228");
    expect(p).toMatchObject({
      id: "CVE-2021-44228",
      title: "Log4Shell",
      severity: "CRITICAL",
      cvss: { score: 10, vector: enriched.cvssVector },
      epss: { score: 0.97565, percent: 97.6 },
      kev: {
        listed: true,
        dateAdded: "2021-12-10",
        dueDate: "2021-12-24",
        ransomwareUse: "Known",
      },
      exploitation: {
        ssvc: "active",
        weaponized: true,
        zeroDay: true,
        exploitCount: 12,
        msrcExploited: false,
        nucleiTemplate: true,
      },
      url: "https://ismalicious.com/cve/CVE-2021-44228",
    });
    expect(p.exploitation?.exploitdbIds).toEqual([
      "50592",
      "50590",
      "50593",
      "50594",
      "50595",
    ]);
    expect(p.references).toEqual(enriched.references);
    expect(Buffer.byteLength(JSON.stringify(p))).toBeLessThanOrEqual(4096);
  });

  it("works against the pre-0.2 body: no KEV, no EPSS, derived references", () => {
    const p = projectCve(
      {
        id: "CVE-2024-0001",
        description: "x",
        severity: "HIGH",
        cvssScore: 7.5,
        published: "2024-01-01T00:00:00Z",
        lastModified: "",
      },
      "CVE-2024-0001",
    );
    expect(p.kev).toEqual({ listed: false });
    expect(p.epss).toBeUndefined();
    expect(p.exploitation).toBeUndefined();
    expect(p.lastModified).toBeUndefined();
    expect(p.references).toEqual([
      { source: "nvd", url: "https://nvd.nist.gov/vuln/detail/CVE-2024-0001" },
    ]);
  });

  it("computes EPSS percent when the API only sends the probability", () => {
    expect(projectCve({ epssScore: 0.12345 }, "CVE-2024-1").epss).toEqual({
      score: 0.12345,
      percent: 12.3,
    });
  });

  it("clips a long description at 600 characters", () => {
    const p = projectCve({ description: "a".repeat(2000) }, "CVE-2024-1");
    expect(p.description.length).toBe(600);
    expect(p.description.endsWith("…")).toBe(true);
  });

  it("derives references from KEV, EPSS, CERT-FR, vendor, GHSA and Exploit-DB", () => {
    const refs = deriveReferences(
      {
        isKev: true,
        epssScore: 0.5,
        certfrLink: "https://cert.fr/a",
        vendorAdvisoryId: "DSA-2026-1",
        vendorAdvisoryLink: "https://dell/x",
        ghsaIds: ["GHSA-1"],
        exploitdbIds: "1,2,3",
      },
      "CVE-2024-1",
    );
    expect(refs.map((r) => r.source)).toEqual([
      "nvd",
      "cisa-kev",
      "first-epss",
      "cert-fr",
      "DSA-2026-1",
      "github-advisory",
      "exploit-db",
      "exploit-db",
    ]);
  });
});

describe("projectRecentCves", () => {
  it("maps the recent list, applies the limit and flags truncation", () => {
    const raw = {
      count: 3,
      days: 7,
      cves: [
        {
          cveId: "CVE-2026-1",
          severity: "critical",
          cvssV3Score: "9.8",
          publishedAt: "2026-09-01T00:00:00Z",
          opencveTitle: "A",
          isKev: true,
        },
        {
          id: "CVE-2026-2",
          severity: "HIGH",
          cvssScore: 8.1,
          published: "2026-08-31T00:00:00Z",
          summary: "B",
        },
        { id: "CVE-2026-3" },
      ],
    };
    const p = projectRecentCves(raw, { limit: 2, severity: "CRITICAL" });
    expect(p).toEqual({
      count: 2,
      days: 7,
      severity: "CRITICAL",
      cves: [
        {
          id: "CVE-2026-1",
          severity: "CRITICAL",
          cvssScore: 9.8,
          published: "2026-09-01T00:00:00Z",
          title: "A",
          kev: true,
        },
        {
          id: "CVE-2026-2",
          severity: "HIGH",
          cvssScore: 8.1,
          published: "2026-08-31T00:00:00Z",
          title: "B",
        },
      ],
      truncated: true,
    });
  });
});
