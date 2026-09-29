/**
 * `get_cve` and `recent_cves` projections.
 *
 * Every field the Rust enrichment added in v0.2 (EPSS, KEV, exploitation
 * evidence, references) is optional here, so the server keeps working against
 * an API that has not been redeployed yet — it just says less.
 */

import {
  arr,
  bool,
  clip,
  compact,
  isRec,
  num,
  rec,
  str,
  strs,
} from "./fields.js";

export const CVE_ID_RE = /^CVE-\d{4}-\d{4,}$/;

/** Uppercase and validate; `null` when the id is not a CVE id at all. */
export function normalizeCveId(input: unknown): string | null {
  if (typeof input !== "string") return null;
  const id = input.trim().toUpperCase();
  return CVE_ID_RE.test(id) ? id : null;
}

export interface CveReference {
  source: string;
  url: string;
}

export interface CveProjection {
  id: string;
  title?: string;
  description: string;
  severity: string;
  cvss?: { score?: number; vector?: string };
  epss?: { score: number; percent: number };
  kev: {
    listed: boolean;
    dateAdded?: string;
    dueDate?: string;
    requiredAction?: string;
    ransomwareUse?: string;
    shortDescription?: string;
  };
  exploitation?: {
    ssvc?: string;
    weaponized?: boolean;
    zeroDay?: boolean;
    exploitCount?: number;
    msrcExploited?: boolean;
    nucleiTemplate?: boolean;
    exploitdbIds?: string[];
  };
  published?: string;
  lastModified?: string;
  references: CveReference[];
  url: string;
}

export const CVE_NOT_FOUND_HINT =
  "The canonical CVE route is GET /cve?id=CVE-YYYY-NNNNN (alias GET /cve/{id}). /check/cve, /vulnerability/{id} and /vulnerabilities/{id} do not exist. A 404 here means the id is not in the catalog yet.";

function idList(v: unknown, max: number): string[] {
  if (typeof v === "string") {
    return v
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
      .slice(0, max);
  }
  return strs(v, max);
}

/** Build the reference list client-side when the API did not send one. */
export function deriveReferences(
  raw: Record<string, unknown>,
  id: string,
): CveReference[] {
  const refs: CveReference[] = [
    { source: "nvd", url: `https://nvd.nist.gov/vuln/detail/${id}` },
  ];
  const kev = rec(raw.kev);
  if (raw.isKev === true || kev?.listed === true) {
    refs.push({
      source: "cisa-kev",
      url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${id}`,
    });
  }
  if (raw.epssScore !== undefined && raw.epssScore !== null) {
    refs.push({
      source: "first-epss",
      url: `https://api.first.org/data/v1/epss?cve=${id}`,
    });
  }
  const certfr = str(raw.certfrLink);
  if (certfr) refs.push({ source: "cert-fr", url: certfr });
  const vendor = str(raw.vendorAdvisoryLink);
  if (vendor)
    refs.push({ source: str(raw.vendorAdvisoryId) ?? "vendor", url: vendor });
  for (const ghsa of idList(raw.ghsaIds, 3)) {
    refs.push({
      source: "github-advisory",
      url: `https://github.com/advisories/${ghsa}`,
    });
  }
  for (const edb of idList(raw.exploitdbIds, 2)) {
    refs.push({
      source: "exploit-db",
      url: `https://www.exploit-db.com/exploits/${edb}`,
    });
  }
  return refs;
}

function readReferences(
  raw: Record<string, unknown>,
  id: string,
  max: number,
): CveReference[] {
  const sent = arr(raw.references)
    .map((r) => {
      if (!isRec(r)) return undefined;
      const url = str(r.url);
      if (!url) return undefined;
      return { source: str(r.source) ?? str(r.name) ?? "reference", url };
    })
    .filter((r): r is CveReference => r !== undefined);
  return (sent.length > 0 ? sent : deriveReferences(raw, id)).slice(0, max);
}

export function projectCve(
  rawInput: unknown,
  requestedId: string,
): CveProjection {
  const raw = rec(rawInput) ?? {};
  const id = str(raw.id) ?? str(raw.cveId) ?? requestedId;
  const kev = rec(raw.kev);
  const listed = bool(raw.isKev) ?? bool(kev?.listed) ?? false;
  const epss = num(raw.epssScore) ?? num(rec(raw.epss)?.score);
  const cvssScore = num(raw.cvssScore) ?? num(raw.cvssV3Score);
  const cvssVector = str(raw.cvssVector) ?? str(raw.cvssV3Vector);
  const description =
    clip(str(raw.description) ?? str(raw.summary), 600) ??
    "No description available";

  const exploitation = compact({
    ssvc: str(raw.ssvcExploitation),
    weaponized: bool(raw.zdcIsWeaponized),
    zeroDay: bool(raw.zdcIsZeroDay),
    exploitCount: num(raw.zdcExploitCount),
    msrcExploited: bool(raw.msrcExploited),
    nucleiTemplate: bool(raw.hasNucleiTemplate),
    exploitdbIds: (() => {
      const ids = idList(raw.exploitdbIds, 5);
      return ids.length ? ids : undefined;
    })(),
  });

  const cvss = compact({ score: cvssScore, vector: cvssVector });

  return {
    id,
    ...((str(raw.opencveTitle) ?? str(raw.title))
      ? { title: clip(str(raw.opencveTitle) ?? str(raw.title), 160) }
      : {}),
    description,
    severity: (str(raw.severity) ?? "UNKNOWN").toUpperCase(),
    ...(Object.keys(cvss).length ? { cvss } : {}),
    ...(epss !== undefined
      ? {
          epss: {
            score: epss,
            percent: num(raw.epssPercent) ?? Math.round(epss * 1000) / 10,
          },
        }
      : {}),
    kev: compact({
      listed,
      dateAdded: str(kev?.dateAdded) ?? str(raw.kevDateAdded),
      dueDate: str(kev?.dueDate) ?? str(raw.kevDueDate),
      requiredAction: clip(
        str(kev?.requiredAction) ?? str(raw.kevRequiredAction),
        240,
      ),
      ransomwareUse: str(kev?.ransomwareUse) ?? str(raw.kevRansomwareUse),
      shortDescription: clip(
        str(kev?.shortDescription) ?? str(raw.kevShortDescription),
        240,
      ),
    }) as CveProjection["kev"],
    ...(Object.keys(exploitation).length ? { exploitation } : {}),
    ...((str(raw.published) ?? str(raw.publishedAt))
      ? { published: str(raw.published) ?? str(raw.publishedAt) }
      : {}),
    ...((str(raw.lastModified) ?? str(raw.lastModifiedAt))
      ? { lastModified: str(raw.lastModified) ?? str(raw.lastModifiedAt) }
      : {}),
    references: readReferences(raw, id, 8),
    url: `https://ismalicious.com/cve/${id}`,
  };
}

export interface RecentCveItem {
  id: string;
  severity: string;
  cvssScore?: number;
  published?: string;
  title?: string;
  kev?: boolean;
}

export interface RecentCvesProjection {
  count: number;
  days?: number;
  severity?: string;
  cves: RecentCveItem[];
  truncated?: boolean;
}

export function projectRecentCves(
  rawInput: unknown,
  requested: { limit: number; severity?: string },
): RecentCvesProjection {
  const raw = rec(rawInput) ?? {};
  const items = arr(raw.cves)
    .map((c): RecentCveItem | undefined => {
      if (!isRec(c)) return undefined;
      const id = str(c.id) ?? str(c.cveId);
      if (!id) return undefined;
      return compact({
        id,
        severity: (str(c.severity) ?? "UNKNOWN").toUpperCase(),
        cvssScore: num(c.cvssScore) ?? num(c.cvssV3Score),
        published: str(c.published) ?? str(c.publishedAt),
        title: clip(
          str(c.opencveTitle) ??
            str(c.kevShortDescription) ??
            str(c.summary) ??
            str(c.description),
          120,
        ),
        kev: bool(c.isKev),
      }) as RecentCveItem;
    })
    .filter((c): c is RecentCveItem => c !== undefined);
  const cves = items.slice(0, requested.limit);
  return {
    count: cves.length,
    ...(num(raw.days) !== undefined ? { days: num(raw.days) } : {}),
    ...(requested.severity ? { severity: requested.severity } : {}),
    cves,
    ...(items.length > cves.length ? { truncated: true } : {}),
  };
}
