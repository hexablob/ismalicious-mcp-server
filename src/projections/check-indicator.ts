/**
 * `check_indicator`: the 40–92 KB `/check` document reduced to what an agent
 * needs to enrich an alert or decide a block, in under 4 KB.
 *
 * Listings carry a `threatClass`; only `threat` ones (the default) reach the
 * verdict and `blocklist`. Infrastructure, policy and allowlist rows are
 * reported under `infrastructure` — what the entity is known as, never a
 * verdict — so a Microsoft 365 range or a Tor exit is not sent to review.
 *
 * The verdict ladder is the one `verdict_from_doc` applies in
 * `apps/rust-api/src/api/gate.rs`, so `check_url` and `check_indicator` never
 * disagree on the same indicator. `headline` and `recommendedAction` are the
 * `{summary, confidence, recommendedAction}` shape of `apps/web/lib/analyze-llm.ts`
 * without the LLM: deterministic, and relayable into Slack as-is.
 */

import { classifyIndicator } from "../indicators.js";
import {
  arr,
  bool,
  clip,
  compact,
  day,
  isRec,
  num,
  rec,
  str,
  strs,
  type Rec,
} from "./fields.js";

export type IndicatorType =
  "ip" | "domain" | "url" | "hash" | "email" | "phone";
export type Verdict = "malicious" | "suspicious" | "clean" | "unknown";
export type RecommendedAction = "block" | "review" | "allow" | "unverified";

/**
 * What the entity IS according to its non-threat listings (cloud range, Tor
 * exit, DoH resolver, crawler…), kept apart from the verdict. Absent when
 * every listing is a threat listing.
 */
export interface InfrastructureAttribution {
  attributes: string[];
  sources: Array<{ name: string; category?: string; threatClass: string }>;
  truncated?: boolean;
}

/**
 * What the file is, for a hash the dataset knows (MalwareBazaar enrichment,
 * ThreatFox): enough for an agent to name it in a ticket. Never OTX pulse
 * content, whose licence is undecided.
 */
export interface FileFacts {
  family?: string;
  /** Every family named, when there is more than one. */
  families?: string[];
  fileType?: string;
  mimeType?: string;
  fileName?: string;
  sizeBytes?: number;
  /** The detection signature, when it is not the family already given. */
  signature?: string;
  tags?: string[];
  /** The file's other digests, to pivot to another tool or feed. */
  digests?: { md5?: string; sha1?: string; sha256?: string };
}

export interface CheckIndicatorProjection {
  /** The value looked up: the input refanged (`evil[.]com` → `evil.com`). */
  indicator: string;
  /** The input as given, when refanging changed it. */
  input?: string;
  type: IndicatorType;
  verdict: Verdict;
  headline: string;
  recommendedAction: RecommendedAction;
  malicious: boolean;
  /** `known` / `unknown` for a hash: whether any source has seen it. */
  lookupStatus?: string;
  risk?: { score?: number; level?: string; summary?: string };
  /** The API's own top evidence sentences, at most three. */
  reasons?: string[];
  categories?: string[];
  file?: FileFacts;
  confidence?: { score?: number; level?: string };
  classification?: {
    primary?: string;
    secondary?: string[];
    confidence?: number;
  };
  reputation?: {
    malicious?: number;
    suspicious?: number;
    harmless?: number;
    undetected?: number;
  };
  /** Threat listings only; infrastructure, policy and allowlist rows are under `infrastructure`. */
  blocklist: {
    hits: number;
    listed: boolean;
    /** `via`: `alias` (listed under another digest of the same file) or `cidr` (through a listed range). */
    sources: Array<{ name: string; category?: string; via?: string }>;
    truncated?: boolean;
  };
  infrastructure?: InfrastructureAttribution;
  /**
   * Hash queries: the digest is the SHA-1 (40 hex) or NTLM (32 hex) of a
   * breached password. Beside the file verdict, never part of it.
   */
  pwnedPassword?: { hashType: string; count: number };
  timeline?: {
    firstSeen?: string;
    lastSeen?: string;
    trend?: string;
    totalDetections?: number;
  };
  network?: {
    countryCode?: string;
    country?: string;
    asn?: string;
    org?: string;
  };
  domain?: {
    registrar?: string;
    createdDate?: string;
    expirationDate?: string;
  };
  asnReputation?: Rec;
  vulnerabilities?: { count: number; cves: string[]; ports: number[] };
  flags: {
    delisted: boolean;
    knownGood: boolean;
    microsoftTenant: boolean;
    ransomware: boolean;
    relatedInfrastructure: boolean;
  };
  reportUrl: string;
  meta?: {
    enrichment?: string;
    processingMs?: number;
    dataTrust?: string;
    /**
     * Facets the `fast` level found no cached value for (`dns`, `whois`,
     * `circl`…); the API is completing them, so one re-check after a few
     * seconds can be fuller.
     */
    pending?: string[];
  };
}

const INDICATOR_TYPES: ReadonlySet<string> = new Set([
  "ip",
  "domain",
  "url",
  "hash",
  "email",
  "phone",
]);

/**
 * The API's declared `type` when it sends one, else the local typing of the
 * indicator (`indicators.ts`), which the tools already ran before the call.
 */
export function detectIndicatorType(
  indicator: string,
  raw: Rec,
): IndicatorType {
  const declared = str(raw.type);
  if (declared && INDICATOR_TYPES.has(declared))
    return declared as IndicatorType;
  if (isRec(raw.hashInfo)) return "hash";
  const local = classifyIndicator(indicator);
  if (local.ok) return local.kind;
  return local.looksLike ?? "domain";
}

/**
 * A listing counts towards the verdict only when its `threatClass` is
 * `"threat"` (or absent: every listing written before the class existed is a
 * threat listing). `infrastructure`, `policy` and `allowlist` rows say what
 * the entity is or what a customer may choose to block, not that it attacked
 * anyone. An entry that is not an object has an unknown shape and is kept on
 * the safe side, as a threat listing.
 */
export function isThreatListing(s: unknown): boolean {
  if (!isRec(s)) return true;
  const cls = str(s.threatClass);
  return cls === undefined || cls === "threat";
}

/** No feed, CIRCL or NSRL answer for this hash: absence of evidence. */
function isUnseenHash(raw: Rec): boolean {
  return str(raw.lookupStatus) === "unknown" && raw.knownGood !== true;
}

/**
 * The ladder of `gate.rs::verdict_from_doc`, so this tool and `check_url`
 * agree whenever the document carries reputation counts. Documents without a
 * `reputation` object (older stored documents, partner samples) get a
 * fallback the gate does not have: an indicator cited by at least one threat
 * source is never called clean — the risk level decides between malicious
 * and suspicious. Non-threat listings alone (an Office 365 range, a Tor exit
 * list) are clean here, as they are for the gate.
 *
 * A hash no source has seen comes back as a full document with zeroed
 * counters and `lookupStatus: "unknown"`; the ladder alone would call it
 * clean and allow it. It is unknown.
 *
 * A hash NSRL knows and a threat source also lists is never `malicious`:
 * NSRL says which software a file belongs to, not that it is safe, so the two
 * disagree. That is a case for an analyst (`suspicious`, `review`); `block`
 * would have an agent quarantine known software on the strength of one feed.
 */
export function verdictFromCheck(raw: Rec): Verdict {
  const verdict = ladderVerdict(raw);
  return raw.knownGood === true && verdict === "malicious"
    ? "suspicious"
    : verdict;
}

function ladderVerdict(raw: Rec): Verdict {
  const reputation = rec(raw.reputation);
  const threatSources = arr(raw.sources).filter(isThreatListing);
  const hasDoc =
    reputation !== undefined ||
    Array.isArray(raw.sources) ||
    bool(raw.malicious) !== undefined;
  if (!hasDoc) return "unknown";
  if (raw.malicious === true) return "malicious";
  if (isUnseenHash(raw)) return "unknown";
  if (reputation) {
    const repMalicious = num(reputation.malicious) ?? 0;
    const repSuspicious = num(reputation.suspicious) ?? 0;
    if (repMalicious > 0 || repSuspicious >= 5) return "malicious";
    if (repSuspicious > 0) return "suspicious";
    return "clean";
  }
  if (threatSources.length === 0) return "clean";
  const level = (str(rec(raw.riskScore)?.level) ?? "").toLowerCase();
  return level === "critical" || level === "high" ? "malicious" : "suspicious";
}

const ACTION: Record<Verdict, RecommendedAction> = {
  malicious: "block",
  suspicious: "review",
  clean: "allow",
  unknown: "unverified",
};

export interface SourceEntry {
  name: string;
  category?: string;
  via?: string;
}

interface InfrastructureEntry {
  name: string;
  category?: string;
  threatClass: string;
}

export interface ProjectedSources {
  /** Threat listings, in document order. */
  threats: SourceEntry[];
  /** Threat listings counted before the name filter, so `hits` matches the document. */
  threatTotal: number;
  /** Infrastructure, policy and allowlist listings. */
  nonThreats: InfrastructureEntry[];
}

function sourceCategory(s: Rec): string | undefined {
  return str(s.category) ?? strs(s.categories, 1)[0] ?? str(s.type);
}

/**
 * How a threat listing reached the indicator when it is not a direct hit:
 * `alias` (the same file under another digest, `HashAlias`) or `cidr` (a
 * listed range the IP falls in). A range listing is weaker evidence about
 * one address than a listing of the address itself.
 */
const MATCH_TYPES: ReadonlySet<string> = new Set(["alias", "cidr"]);

export function projectSources(raw: Rec): ProjectedSources {
  const threats: SourceEntry[] = [];
  const nonThreats: InfrastructureEntry[] = [];
  let threatTotal = 0;
  for (const s of arr(raw.sources)) {
    const threat = isThreatListing(s);
    if (threat) threatTotal += 1;
    if (!isRec(s)) continue;
    const name = str(s.name) ?? str(s.provider) ?? str(s.id);
    if (!name) continue;
    const category = sourceCategory(s);
    if (threat) {
      const match = str(s.matchType);
      const via = match && MATCH_TYPES.has(match) ? match : undefined;
      threats.push(compact({ name, category, via }) as SourceEntry);
    } else {
      nonThreats.push({
        ...(compact({ name, category }) as { name: string; category?: string }),
        threatClass: str(s.threatClass) as string,
      });
    }
  }
  return { threats, threatTotal, nonThreats };
}

/**
 * Attribute derived from a non-threat listing's category when the document
 * predates the server-side `infrastructure` block. The server reads the
 * registry tags too and is the authority; this table only covers category
 * values that name the attribute unambiguously (`anonymizer` and
 * `infrastructure` do not).
 */
const ATTRIBUTE_BY_CATEGORY: Record<string, string> = {
  tor: "tor-exit",
  "tor-exit": "tor-exit",
  "exit-node": "tor-exit",
  vpn: "vpn",
  proxy: "proxy",
  doh: "doh-resolver",
  "doh-resolver": "doh-resolver",
  dns: "dns-resolver",
  "dns-resolver": "dns-resolver",
  sinkhole: "sinkhole",
  cloud: "cloud",
  cdn: "cdn",
  crawler: "crawler",
  scanner: "scanner",
  "benign-scanner": "scanner",
  monitoring: "monitoring",
  uptime: "monitoring",
  disposable: "disposable-email",
  "disposable-email": "disposable-email",
  dyndns: "dynamic-dns",
  "dynamic-dns": "dynamic-dns",
  shortener: "url-shortener",
  "url-shortener": "url-shortener",
  bogon: "bogon",
  unroutable: "bogon",
  saas: "saas",
  allowlist: "allowlist",
};

export function projectInfrastructure(
  raw: Rec,
  nonThreats: ProjectedSources["nonThreats"],
  maxSources: number,
): InfrastructureAttribution | undefined {
  const served = rec(raw.infrastructure);
  if (!served && nonThreats.length === 0) return undefined;
  let attributes = strs(served?.attributes, 32);
  if (attributes.length === 0) {
    const derived = new Set<string>();
    for (const s of arr(raw.sources)) {
      if (!isRec(s) || isThreatListing(s)) continue;
      if (str(s.threatClass) === "allowlist") derived.add("allowlist");
      for (const c of [str(s.category), ...strs(s.categories, 8)]) {
        const attr = c ? ATTRIBUTE_BY_CATEGORY[c.toLowerCase()] : undefined;
        if (attr) derived.add(attr);
      }
    }
    attributes = [...derived].sort();
  }
  return {
    attributes,
    sources: nonThreats.slice(0, maxSources),
    ...(nonThreats.length > maxSources ? { truncated: true } : {}),
  };
}

function projectTimeline(raw: Rec) {
  const t = rec(raw.timeline);
  const trust = rec(raw.dataTrust);
  return compact({
    firstSeen: day(
      str(t?.firstSeen) ??
        str(t?.first_seen) ??
        str(trust?.firstSeen) ??
        str(raw.firstSeen),
    ),
    lastSeen: day(
      str(t?.lastSeen) ??
        str(t?.last_seen) ??
        str(trust?.lastSeen) ??
        str(raw.lastSeen),
    ),
    trend: str(t?.trend),
    totalDetections: num(t?.totalDetections) ?? num(t?.total_detections),
  });
}

function projectNetwork(raw: Rec) {
  const geo = rec(raw.geo);
  const whois = rec(raw.whois);
  const whoisAsn = rec(whois?.asn);
  const asnText = str(geo?.as);
  const asnFromGeo = asnText
    ? /^AS\d+/i.exec(asnText)?.[0]?.toUpperCase()
    : undefined;
  const asnFromWhois =
    str(whoisAsn?.asn) ??
    (num(whoisAsn?.asn) !== undefined ? `AS${num(whoisAsn?.asn)}` : undefined);
  return compact({
    countryCode: str(geo?.countryCode),
    country: str(geo?.country),
    asn: asnFromWhois
      ? asnFromWhois.toUpperCase().startsWith("AS")
        ? asnFromWhois.toUpperCase()
        : `AS${asnFromWhois}`
      : asnFromGeo,
    org: str(geo?.org) ?? str(geo?.isp) ?? str(whoisAsn?.name),
  });
}

function projectDomain(raw: Rec) {
  const whois = rec(raw.whois);
  if (!whois) return {};
  const registrar = rec(whois.registrar);
  const domain = rec(whois.domain);
  return compact({
    registrar: str(registrar?.name) ?? str(whois.registrar),
    createdDate: day(
      str(domain?.created_date) ??
        str(domain?.createdDate) ??
        str(whois.createdDate) ??
        str(whois.created),
    ),
    expirationDate: day(
      str(domain?.expiration_date) ??
        str(domain?.expirationDate) ??
        str(whois.expirationDate) ??
        str(whois.expires),
    ),
  });
}

function projectAsnReputation(raw: Rec): Rec | undefined {
  const a = rec(raw.asnReputation);
  if (!a) return undefined;
  const listed = bool(a.listed) ?? bool(a.isListed) ?? bool(a.malicious);
  const out = compact({
    listed,
    asn:
      str(a.asn) ?? (num(a.asn) !== undefined ? `AS${num(a.asn)}` : undefined),
    score: num(a.score),
    level: str(a.level) ?? str(a.riskLevel),
    name: str(a.name) ?? str(a.org),
  });
  return Object.keys(out).length > 0 && listed !== false ? out : undefined;
}

function projectVulnerabilities(raw: Rec) {
  const v = rec(raw.vulnerabilities);
  if (!v) return undefined;
  const vulns = strs(v.vulns, 1000);
  const ports = arr(v.ports)
    .map((p) => num(p))
    .filter((p): p is number => p !== undefined);
  if (vulns.length === 0 && ports.length === 0) return undefined;
  return {
    count: vulns.length,
    cves: vulns.slice(0, 5),
    ports: ports.slice(0, 10),
  };
}

function ransomwareFlag(v: unknown): boolean {
  if (Array.isArray(v)) return v.length > 0;
  if (!isRec(v)) return false;
  const explicit = bool(v.found) ?? bool(v.isRansomware) ?? bool(v.detected);
  if (explicit !== undefined) return explicit;
  return Object.keys(v).length > 0;
}

function processingMs(v: unknown): number | undefined {
  const n = num(v);
  if (n !== undefined) return Math.round(n);
  const s = str(v);
  const m = s ? /^(\d+(?:\.\d+)?)\s*ms$/.exec(s) : null;
  return m ? Math.round(Number(m[1])) : undefined;
}

/** Longest evidence sentence relayed; the API's run to ~120 characters. */
const REASON_CHARS = 200;

/**
 * The API's own explanation, at most `max` sentences: `evidence.reasons`
 * (Data Trust, every type), else the score factors that pushed the score up,
 * largest first. An agent that must justify a block quotes these.
 */
export function projectReasons(raw: Rec, max = 3): string[] {
  const clipped = (xs: string[]) =>
    xs.map((r) => clip(r, REASON_CHARS) as string).slice(0, max);
  const evidence = strs(rec(raw.evidence)?.reasons, max);
  if (evidence.length > 0) return clipped(evidence);
  const factors = arr(rec(raw.riskScore)?.factors)
    .map((f) => rec(f))
    .filter((f): f is Rec => f !== undefined)
    .map((f) => ({ text: str(f.description), weight: num(f.contribution) }))
    .filter(
      (f): f is { text: string; weight: number } =>
        f.text !== undefined && f.weight !== undefined && f.weight > 0,
    )
    .sort((a, b) => b.weight - a.weight);
  return clipped(factors.map((f) => f.text));
}

/**
 * `pending` from `GET /check?enrichment=fast` (top level, or under `meta` on
 * a projection replayed through a proxy): what the cache did not hold yet.
 */
export function pendingFacets(raw: Rec): string[] {
  const top = strs(raw.pending, 8);
  return top.length > 0 ? top : strs(rec(raw.meta)?.pending, 8);
}

/**
 * Appended to a headline when facets are pending, and only then: one
 * re-check, never a loop. The API lists a facet only while a background
 * fetch can still fill it, so the re-check is usually complete; a facet
 * still listed after it is not coming soon, and every re-check is a billed
 * request.
 */
export function pendingHint(pending: string[]): string {
  if (pending.length === 0) return "";
  const [them, theyAre] =
    pending.length === 1 ? ["it", "it is"] : ["them", "they are"];
  return ` Not cached yet: ${pending.join(", ")}; one re-check after a few seconds may complete ${them}. If ${theyAre} still pending then, this answer stands: do not re-check again.`;
}

function projectFile(raw: Rec, indicator: string): FileFacts | undefined {
  const info = rec(raw.hashInfo);
  const threatFox = rec(raw.threatFox);
  const families = [
    ...new Set(
      [
        str(raw.malwareFamily),
        ...strs(raw.malwareFamilies, 8),
        str(threatFox?.malwareFamily),
      ].filter(
        (f): f is string => f !== undefined && f.toLowerCase() !== "unknown",
      ),
    ),
  ];
  const signature = str(info?.signature);
  const family = families[0] ?? signature;
  // The queried digest is `indicator` already; only the others help pivot.
  const other = (d: string | undefined) =>
    d && d.toLowerCase() !== indicator.toLowerCase() ? d : undefined;
  const digests = compact({
    md5: other(str(info?.md5)),
    sha1: other(str(info?.sha1)),
    sha256: other(str(info?.sha256)),
  });
  const tags = strs(info?.tags, 5);
  const file = compact({
    family,
    families: families.length > 1 ? families.slice(0, 3) : undefined,
    fileType: str(info?.fileType),
    mimeType: str(info?.mimeType),
    fileName: clip(str(info?.fileName), 80),
    sizeBytes: num(info?.fileSizeBytes) ?? num(info?.fileSize),
    signature: signature && signature !== family ? signature : undefined,
    tags: tags.length > 0 ? tags : undefined,
    digests: Object.keys(digests).length > 0 ? digests : undefined,
  }) as FileFacts;
  return Object.keys(file).length > 0 ? file : undefined;
}

export function buildHeadline(
  indicator: string,
  verdict: Verdict,
  parts: {
    hits: number;
    category?: string;
    riskScore?: number;
    firstSeen?: string;
    lastSeen?: string;
    knownGood: boolean;
    delisted: boolean;
    /** A hash with `lookupStatus: "unknown"`, as opposed to a body that is not a document. */
    unseen?: boolean;
    /** Non-threat attribution: what the entity is known as, and how many listings say so. */
    infrastructure?: { attributes: string[]; count: number };
  },
): string {
  const plural = parts.hits === 1 ? "source" : "sources";
  const risk =
    parts.riskScore !== undefined ? `; risk ${parts.riskScore}/100` : "";
  const infra =
    parts.infrastructure && parts.infrastructure.count > 0
      ? parts.infrastructure.attributes.length > 0
        ? `; known infrastructure: ${parts.infrastructure.attributes.join(", ")}`
        : `; ${parts.infrastructure.count} infrastructure listing${parts.infrastructure.count === 1 ? "" : "s"}`
      : "";
  const seen =
    parts.firstSeen && parts.lastSeen
      ? parts.firstSeen === parts.lastSeen
        ? `; seen on ${parts.firstSeen}`
        : `; seen from ${parts.firstSeen} to ${parts.lastSeen}`
      : parts.lastSeen
        ? `; last seen ${parts.lastSeen}`
        : "";
  const delisted = parts.delisted
    ? " (delisted since; treat as historical)"
    : "";
  switch (verdict) {
    case "malicious": {
      const cat = parts.category ? ` (${parts.category})` : "";
      return `${indicator} is flagged malicious by ${parts.hits} ${plural}${cat}${risk}${seen}${infra}${delisted}.`;
    }
    case "suspicious":
      if (parts.knownGood && parts.hits > 0) {
        const lists = parts.hits === 1 ? "lists" : "list";
        return `${indicator} is known software (NSRL), yet ${parts.hits} ${plural} ${lists} it; review before blocking${risk}${seen}${infra}${delisted}.`;
      }
      return `${indicator} is flagged suspicious by ${parts.hits} ${plural}${risk}${seen}${infra}${delisted}.`;
    case "clean":
      if (parts.knownGood)
        return `${indicator} is a known-good file (NSRL); no source lists it${risk}.`;
      return infra
        ? `${indicator} is not listed by any threat source${infra}${risk}.`
        : `${indicator} is not listed by any of our sources${risk}.`;
    default:
      return parts.unseen
        ? `${indicator} is unknown to our sources: no evidence either way, which is not a clean verdict.`
        : `No reputation data for ${indicator}.`;
  }
}

export interface CheckProjectionOptions {
  requestedEnrichment?: string;
  maxSources?: number;
  /** The input as given, reported when refanging changed it. */
  input?: string;
}

// A classification that merely restates the verdict adds nothing to the headline.
const VERDICT_WORDS = new Set([
  "unknown",
  "malicious",
  "suspicious",
  "clean",
  "benign",
  "harmless",
]);

function headlineCategory(s: string | undefined): string | undefined {
  return s && !VERDICT_WORDS.has(s.toLowerCase()) ? s : undefined;
}

/** `input` when it says something `indicator` does not (not a mere case change). */
export function inputIfRefanged(
  indicator: string,
  input: string | undefined,
): string | undefined {
  return input !== undefined &&
    input.trim().toLowerCase() !== indicator.toLowerCase()
    ? input.trim()
    : undefined;
}

export function projectCheckIndicator(
  indicator: string,
  rawInput: unknown,
  options: CheckProjectionOptions = {},
): CheckIndicatorProjection {
  const raw = rec(rawInput) ?? {};
  const maxSources = options.maxSources ?? 10;
  const type = detectIndicatorType(indicator, raw);
  const verdict = verdictFromCheck(raw);
  const { threats, threatTotal, nonThreats } = projectSources(raw);
  const infrastructure = projectInfrastructure(raw, nonThreats, maxSources);
  const riskScore = rec(raw.riskScore);
  const confidence = rec(raw.confidence);
  const classification = rec(raw.classification);
  const reputation = rec(raw.reputation);
  const timeline = projectTimeline(raw);
  const flags = {
    delisted: bool(raw.delisted) ?? false,
    knownGood: bool(raw.knownGood) ?? false,
    microsoftTenant: isRec(raw.microsoftTenant)
      ? (bool(raw.microsoftTenant.isTenant) ??
        bool(raw.microsoftTenant.found) ??
        true)
      : (bool(raw.microsoftTenant) ?? false),
    ransomware: ransomwareFlag(raw.ransomware),
    relatedInfrastructure:
      (num(rec(raw.relatedInfrastructure)?.totalRelated) ?? 0) > 0,
  };
  const unseen = isUnseenHash(raw);
  // An unseen hash's score measures nothing (the API kept it for REST
  // compatibility, labelled `safe` before 2026-09-25): keep the summary only.
  const risk = compact({
    score: unseen ? undefined : num(riskScore?.score),
    level: unseen ? undefined : str(riskScore?.level),
    summary: clip(str(riskScore?.summary), 240),
  });
  const primary = str(classification?.primary);
  const file = type === "hash" ? projectFile(raw, indicator) : undefined;
  const pending = pendingFacets(raw);
  // The risk summary is often the first evidence sentence: say it once.
  const reasons = projectReasons(raw, 4)
    .filter((r) => r !== risk.summary)
    .slice(0, 3);
  const categories = strs(raw.categories, 5);

  // A hash document carries no classification on the REST path; its family
  // (MalwareBazaar, ThreatFox) is the category an analyst would name.
  const headlineBase = buildHeadline(indicator, verdict, {
    hits: threatTotal,
    category: headlineCategory(primary) ?? headlineCategory(file?.family),
    riskScore: risk.score,
    firstSeen: timeline.firstSeen,
    lastSeen: timeline.lastSeen,
    knownGood: flags.knownGood,
    delisted: flags.delisted,
    unseen,
    ...(infrastructure
      ? {
          infrastructure: {
            attributes: infrastructure.attributes,
            count: nonThreats.length,
          },
        }
      : {}),
  });

  const pwned = rec(raw.pwnedPassword);
  const pwnedPassword =
    pwned && bool(pwned.found) && num(pwned.count) !== undefined
      ? { hashType: str(pwned.hashType) ?? "sha1", count: num(pwned.count)! }
      : undefined;
  const pwnedSentence = pwnedPassword
    ? ` It is also the ${pwnedPassword.hashType === "ntlm" ? "NTLM" : "SHA-1"} hash of a password seen ${pwnedPassword.count.toLocaleString("en-US")} times in data breaches.`
    : "";
  const headline = headlineBase + pwnedSentence + pendingHint(pending);

  const dataTrust = rec(raw.dataTrust);
  const vulnerabilities = projectVulnerabilities(raw);
  const domain = type === "domain" || type === "url" ? projectDomain(raw) : {};
  const network = projectNetwork(raw);
  const input = inputIfRefanged(indicator, options.input);
  const lookupStatus = str(raw.lookupStatus);

  const projection: CheckIndicatorProjection = {
    indicator,
    ...(input ? { input } : {}),
    type,
    verdict,
    headline,
    recommendedAction: ACTION[verdict],
    malicious: verdict === "malicious",
    ...(lookupStatus ? { lookupStatus } : {}),
    ...(Object.keys(risk).length ? { risk } : {}),
    ...(reasons.length ? { reasons } : {}),
    ...(categories.length ? { categories } : {}),
    ...(file ? { file } : {}),
    ...(confidence
      ? {
          confidence: compact({
            score: num(confidence.score),
            level: str(confidence.level),
          }),
        }
      : {}),
    ...(classification
      ? {
          classification: compact({
            primary,
            secondary: strs(classification.secondary, 3),
            confidence: num(classification.confidence),
          }),
        }
      : {}),
    ...(reputation
      ? {
          reputation: compact({
            malicious: num(reputation.malicious),
            suspicious: num(reputation.suspicious),
            harmless: num(reputation.harmless),
            undetected: num(reputation.undetected),
          }),
        }
      : {}),
    blocklist: {
      hits: threatTotal,
      listed: threatTotal > 0,
      sources: threats.slice(0, maxSources),
      ...(threats.length > maxSources ? { truncated: true } : {}),
    },
    ...(infrastructure ? { infrastructure } : {}),
    ...(pwnedPassword ? { pwnedPassword } : {}),
    ...(Object.keys(timeline).length ? { timeline } : {}),
    ...(Object.keys(network).length ? { network } : {}),
    ...(Object.keys(domain).length ? { domain } : {}),
    ...(projectAsnReputation(raw)
      ? { asnReputation: projectAsnReputation(raw) }
      : {}),
    ...(vulnerabilities ? { vulnerabilities } : {}),
    flags,
    reportUrl: `https://ismalicious.com/report?query=${encodeURIComponent(indicator)}`,
    meta: compact({
      enrichment:
        str(raw.enrichmentLevel) ??
        str(rec(raw.meta)?.enrichment) ??
        options.requestedEnrichment,
      processingMs: processingMs(raw.processingTime ?? raw.processingTimeMs),
      dataTrust: str(dataTrust?.freshness) ?? str(dataTrust?.level),
      pending: pending.length ? pending : undefined,
    }),
  };
  if (projection.meta && Object.keys(projection.meta).length === 0)
    delete projection.meta;
  return projection;
}
