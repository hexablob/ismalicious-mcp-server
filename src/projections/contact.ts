/**
 * `check_indicator` for an email address or a phone number: the `/check`
 * body of `type: "email" | "phone"` (API contract of 2026-09-30) reduced to
 * what an agent relays.
 *
 * The API decides the verdict from an evidence ladder — a listing on the
 * address or number, the sender domain's own listings, a disposable domain,
 * a domain whose null MX says it accepts no mail — and never answers `clean`: its email and phone
 * sources are a few feeds, so absence proves nothing. This projection relays
 * that verdict as it came, restricted to the values the contract allows,
 * and builds a headline from the same facts.
 *
 * Before that contract the API looked an address up as the domain
 * `user@host`, found nothing and said `malicious: false`, which the IP/domain
 * ladder reads as clean / allow: a false allow, charged a request. When the
 * indicator is an address or a number but the body is not typed as one, the
 * answer is `unknown` / `unverified` with a note that the API did not
 * evaluate it — never a verdict borrowed from the wrong lookup.
 */

import {
  inputIfRefanged,
  projectInfrastructure,
  projectSources,
  type InfrastructureAttribution,
  type SourceEntry,
} from "./check-indicator.js";
import {
  bool,
  clip,
  compact,
  day,
  num,
  rec,
  str,
  strs,
  type Rec,
} from "./fields.js";

export type ContactType = "email" | "phone";
export type ContactVerdict = "malicious" | "suspicious" | "unknown";
export type ContactAction = "block" | "review" | "unverified";

const VERDICTS: ReadonlySet<string> = new Set([
  "malicious",
  "suspicious",
  "unknown",
]);
const ACTIONS: ReadonlySet<string> = new Set(["block", "review", "unverified"]);
const ACTION_FOR: Record<ContactVerdict, ContactAction> = {
  malicious: "block",
  suspicious: "review",
  unknown: "unverified",
};
const RESOLUTIONS: ReadonlySet<string> = new Set([
  "e164",
  "country",
  "nanp-guess",
  "digits",
]);

export interface EmailFacts {
  domain?: string;
  disposable?: boolean;
  /** A consumer or shared provider: its reputation is not the address's. */
  freeProvider?: boolean;
  /**
   * `false` only for a null MX (RFC 7505): the domain says it accepts no
   * mail. `null`: not evaluated — no cached DNS answer, or one that lists no
   * MX, which a failed lookup also looks like (the API never resolves live).
   */
  mx: boolean | null;
  domainReputation?: {
    lookupStatus?: string;
    malicious?: boolean;
    blocklistHits?: number;
    sources?: string[];
    infrastructure?: string[];
  };
}

export interface PhoneFacts {
  e164: string | null;
  countryCallingCode: string | null;
  /** `e164` | `country` | `nanp-guess` | `digits`. */
  resolvedWith?: string;
}

export interface ContactProjection {
  /** Lowercased address, or the E.164 number (its digits when no country could be told). */
  indicator: string;
  input?: string;
  type: ContactType;
  verdict: ContactVerdict;
  headline: string;
  recommendedAction: ContactAction;
  malicious: boolean;
  /** `found`: a dataset document exists for the address or number. */
  lookupStatus: "found" | "unknown";
  risk?: { score?: number; level?: string; summary?: string };
  reasons?: string[];
  categories?: string[];
  blocklist: {
    hits: number;
    listed: boolean;
    sources: SourceEntry[];
    truncated?: boolean;
  };
  infrastructure?: InfrastructureAttribution;
  timeline?: { firstSeen?: string; lastSeen?: string };
  email?: EmailFacts;
  phone?: PhoneFacts;
  flags: { delisted: boolean };
  meta?: { enrichment?: string; processingMs?: number };
}

/** The answer when the API did not type the indicator as the tool did. */
export interface UnevaluatedProjection {
  indicator: string;
  input?: string;
  type: ContactType;
  verdict: "unknown";
  headline: string;
  recommendedAction: "unverified";
  malicious: false;
  lookupStatus: "unknown";
  note: string;
  meta?: { enrichment?: string; processingMs?: number };
}

export interface ContactProjectionOptions {
  requestedEnrichment?: string;
  input?: string;
  maxSources?: number;
}

const NOUN: Record<ContactType, string> = {
  email: "email address",
  phone: "phone number",
};
const ARTICLE: Record<ContactType, string> = { email: "an", phone: "a" };

export function isContactType(t: string | undefined): t is ContactType {
  return t === "email" || t === "phone";
}

function plural(n: number, one: string, many: string): string {
  return n === 1 ? one : many;
}

function meta(raw: Rec, requested?: string) {
  const processingMs = num(raw.processingTime);
  const out = compact({
    enrichment: str(raw.enrichmentLevel) ?? requested,
    processingMs:
      processingMs !== undefined ? Math.round(processingMs) : undefined,
  });
  return Object.keys(out).length > 0 ? out : undefined;
}

/** `true` / `false` / `null`; anything else (absent, malformed) is `null`. */
function triState(v: unknown): boolean | null {
  return typeof v === "boolean" ? v : null;
}

function projectEmail(raw: Rec): EmailFacts | undefined {
  const e = rec(raw.email);
  if (!e) return undefined;
  const d = rec(e.domainReputation);
  const infrastructure = strs(d?.infrastructure, 8);
  const reputation = d
    ? compact({
        lookupStatus: str(d.lookupStatus),
        malicious: bool(d.malicious),
        blocklistHits: num(d.blocklistHits),
        sources: strs(d.sources, 5),
        infrastructure: infrastructure.length ? infrastructure : undefined,
      })
    : undefined;
  return {
    ...compact({
      domain: str(e.domain),
      disposable: bool(e.disposable),
      freeProvider: bool(e.freeProvider),
    }),
    mx: triState(e.mx),
    ...(reputation && Object.keys(reputation).length
      ? { domainReputation: reputation }
      : {}),
  };
}

function projectPhone(raw: Rec): PhoneFacts | undefined {
  const p = rec(raw.phone);
  if (!p) return undefined;
  const resolvedWith = str(p.resolvedWith);
  return {
    e164: str(p.e164) ?? null,
    countryCallingCode: str(p.countryCallingCode) ?? null,
    ...(resolvedWith && RESOLUTIONS.has(resolvedWith) ? { resolvedWith } : {}),
  };
}

/** What the sender domain contributes, as a headline clause. */
function domainClause(email: EmailFacts): string[] {
  const d = email.domain;
  if (!d) return [];
  const rep = email.domainReputation;
  const hits = rep?.blocklistHits ?? 0;
  const out: string[] = [];
  if (email.freeProvider) {
    out.push(
      `${d} is a shared mail provider, whose reputation is not the address's`,
    );
  } else if (rep?.malicious) {
    out.push(
      hits > 0
        ? `the domain ${d} is malicious (${hits} threat ${plural(hits, "listing", "listings")})`
        : `the domain ${d} is flagged malicious`,
    );
  } else if (hits > 0) {
    out.push(
      `the domain ${d} has ${hits} threat ${plural(hits, "listing", "listings")}`,
    );
  } else if (!email.disposable) {
    // A disposable domain's listings are attributes, not threat listings:
    // what the domain is (below) says more than "not listed".
    if (rep?.lookupStatus === "found")
      out.push(`the domain ${d} is not listed`);
    else if (rep) out.push(`the domain ${d} is not in our dataset`);
  }
  if (email.disposable) out.push(`${d} is a disposable mail provider`);
  if (email.mx === false)
    out.push(`${d} publishes a null MX (it accepts no mail)`);
  return out;
}

function phoneClause(phone: PhoneFacts | undefined): string[] {
  switch (phone?.resolvedWith) {
    case "nanp-guess":
      return [
        "read as a North American number (pass an E.164 number or country for another country)",
      ];
    case "digits":
      return [
        "its country could not be told (pass an E.164 number or country)",
      ];
    default:
      return [];
  }
}

export function buildContactHeadline(parts: {
  indicator: string;
  type: ContactType;
  verdict: ContactVerdict;
  hits: number;
  categories: string[];
  riskScore?: number;
  delisted: boolean;
  email?: EmailFacts;
  phone?: PhoneFacts;
}): string {
  const { indicator, verdict, hits } = parts;
  const clauses: string[] = [];
  if (hits > 0) {
    const cats = parts.categories.slice(0, 2);
    clauses.push(
      `${indicator} is listed by ${hits} threat ${plural(hits, "source", "sources")}${cats.length ? ` (${cats.join(", ")})` : ""}`,
    );
  } else if (verdict === "unknown") {
    clauses.push(`${indicator} is not in any source we hold`);
  } else {
    clauses.push(`${indicator} is not listed itself`);
  }
  if (parts.delisted) clauses.push("a delisting removed its listings");
  if (parts.type === "email" && parts.email)
    clauses.push(...domainClause(parts.email));
  if (parts.type === "phone") clauses.push(...phoneClause(parts.phone));
  if (verdict !== "unknown" && parts.riskScore !== undefined)
    clauses.push(`risk ${parts.riskScore}/100`);
  if (verdict === "unknown") clauses.push("absence is not evidence of safety");
  return `${clauses.join("; ")}.`;
}

/** The `/check` body of an email address or a phone number. */
export function projectContact(
  indicator: string,
  rawInput: unknown,
  options: ContactProjectionOptions = {},
): ContactProjection {
  const raw = rec(rawInput) ?? {};
  const type: ContactType = str(raw.type) === "phone" ? "phone" : "email";
  const maxSources = options.maxSources ?? 10;
  const declaredVerdict = str(raw.verdict);
  const validVerdict =
    declaredVerdict !== undefined && VERDICTS.has(declaredVerdict);
  const verdict = (
    validVerdict ? declaredVerdict : "unknown"
  ) as ContactVerdict;
  const declaredAction = str(raw.recommendedAction);
  const recommendedAction =
    validVerdict && declaredAction && ACTIONS.has(declaredAction)
      ? (declaredAction as ContactAction)
      : ACTION_FOR[verdict];
  const entity = str(raw.entity) ?? indicator;
  const { threats, threatTotal, nonThreats } = projectSources(raw);
  const hits = num(raw.blocklistHits) ?? threatTotal;
  const infrastructure = projectInfrastructure(raw, nonThreats, maxSources);
  const riskScore = rec(raw.riskScore);
  // An unknown verdict measured nothing: a 0 would read as "safe".
  const risk = compact({
    score: verdict === "unknown" ? undefined : num(riskScore?.score),
    level: verdict === "unknown" ? undefined : str(riskScore?.level),
    summary: clip(str(riskScore?.summary), 240),
  });
  const reasons = strs(raw.reasons, 5).map((r) => clip(r, 200) as string);
  const categories = strs(raw.categories, 5);
  const timeline = compact({
    firstSeen: day(str(raw.firstSeen)),
    lastSeen: day(str(raw.lastSeen)),
  });
  const email = type === "email" ? projectEmail(raw) : undefined;
  const phone = type === "phone" ? projectPhone(raw) : undefined;
  const delisted = raw.delisted === true;
  const input = inputIfRefanged(entity, options.input);
  const m = meta(raw, options.requestedEnrichment);
  return {
    indicator: entity,
    ...(input ? { input } : {}),
    type,
    verdict,
    headline: buildContactHeadline({
      indicator: entity,
      type,
      verdict,
      hits,
      categories,
      riskScore: risk.score,
      delisted,
      email,
      phone,
    }),
    recommendedAction,
    malicious: verdict === "malicious",
    lookupStatus: str(raw.lookupStatus) === "found" ? "found" : "unknown",
    ...(Object.keys(risk).length ? { risk } : {}),
    ...(reasons.length ? { reasons } : {}),
    ...(categories.length ? { categories } : {}),
    blocklist: {
      hits,
      listed: bool(raw.blocklistListed) ?? hits > 0,
      sources: threats.slice(0, maxSources),
      ...(threats.length > maxSources ? { truncated: true } : {}),
    },
    ...(infrastructure ? { infrastructure } : {}),
    ...(Object.keys(timeline).length ? { timeline } : {}),
    ...(email ? { email } : {}),
    ...(phone ? { phone } : {}),
    flags: { delisted },
    ...(m ? { meta: m } : {}),
  };
}

/**
 * The indicator is an address or a number, and the API answered with
 * another type (or none): a server from before the contract, which looked it
 * up as a domain. Its "not listed" is about a key that never exists.
 */
export function projectUnevaluated(
  indicator: string,
  type: ContactType,
  rawInput: unknown,
  options: ContactProjectionOptions = {},
): UnevaluatedProjection {
  const raw = rec(rawInput) ?? {};
  const answered = str(raw.type);
  const noun = NOUN[type];
  const input = inputIfRefanged(indicator, options.input);
  const m = meta(raw, options.requestedEnrichment);
  return {
    indicator,
    ...(input ? { input } : {}),
    type,
    verdict: "unknown",
    headline: `${indicator} was not evaluated as ${ARTICLE[type]} ${noun}: no verdict either way, which is not a clean verdict.`,
    recommendedAction: "unverified",
    malicious: false,
    lookupStatus: "unknown",
    note: `The API did not type this ${noun} (${answered ? `it answered as ${answered}` : "its answer carries no type"}). A server that predates email and phone support looks it up as a domain, and its "not listed" says nothing about the ${noun}.`,
    ...(m ? { meta: m } : {}),
  };
}
