import { invalidParams } from "../errors.js";
import {
  classifyIndicator,
  MAX_INDICATOR_CHARS,
  normalizeCountry,
  SUPPORTED_HASHES,
} from "../indicators.js";
import { isRecord } from "../cache.js";
import { inputIfRefanged } from "../projections/check-indicator.js";
import { projectCheckResult } from "../projections/check-result.js";
import { fetchJson } from "./request.js";
import { fail, ok, READ_ONLY_TOOL, type ToolDefinition } from "./types.js";

/**
 * `fast` first: an agent waits on every call, and `fast` answers from what
 * the API holds without a live upstream call before the response (a hash
 * nobody has cached may still wait up to ~2.5 s on CIRCL). A server that
 * predates the level reads it as `standard` for an IP, a domain or a URL; for
 * a hash it stored `enrichmentLevel: "fast"` in the cached document, which is
 * why this release ships after the API deploy that adds the level
 * (PUBLISHING.md).
 */
const ENRICHMENT = ["fast", "standard", "basic"] as const;
type Enrichment = (typeof ENRICHMENT)[number];

export const MAX_INDICATOR_LENGTH = MAX_INDICATOR_CHARS;

/**
 * The arguments as sent: shared by the call and the cache key. The length is
 * checked before typing: the schema's `maxLength` is a hint the server does
 * not enforce, and typing a hostile string is work for nothing.
 */
function normalize(args: Record<string, unknown>) {
  const raw = typeof args.indicator === "string" ? args.indicator.trim() : "";
  const tooLong = raw.length > MAX_INDICATOR_LENGTH;
  const classified = raw && !tooLong ? classifyIndicator(raw) : undefined;
  const enrichment: Enrichment = (ENRICHMENT as readonly string[]).includes(
    args.enrichment as string,
  )
    ? (args.enrichment as Enrichment)
    : "fast";
  const country = normalizeCountry(args.country);
  return { raw, tooLong, classified, enrichment, country };
}

/**
 * The shared result with this call's own `input`. Calls are keyed on the
 * refanged value, so `evil[.]com` and `evil.com` share one answer; the
 * `input` echoed on it belonged to whichever call ran first, and was replayed
 * to the other — a string that call never sent.
 */
function withOwnInput(value: unknown, raw: string): unknown {
  if (!isRecord(value) || typeof value.indicator !== "string") return value;
  const { indicator, input: _shared, ...rest } = value;
  const input = inputIfRefanged(indicator, raw);
  return { indicator, ...(input ? { input } : {}), ...rest };
}

export const checkIndicator: ToolDefinition = {
  name: "check_indicator",
  title: "Check indicator reputation",
  description: `The one tool for any single indicator: an IP address, domain, URL, file hash (${SUPPORTED_HASHES}; an imphash is looked up as an MD5), email address or phone number. Defanged input (hxxp://, [.], [@]) is accepted. Returns a verdict (malicious, suspicious, clean or unknown), a headline you can relay as is, recommendedAction (block, review, allow or unverified), a 0-100 risk score, the threat blocklists that cite it, up to three evidence reasons, first/last seen, and network, registration or file context. An email address or phone number is never called clean: not being in our sources is unknown / unverified; its answer adds the sender domain's reputation, disposable and MX facts, or the E.164 form of the number. \`infrastructure\` says what the entity is known as (cloud range, CDN, Tor exit, VPN, crawler, allowlist) without being a verdict. SHA-512, TLSH, ssdeep and input that is none of the six kinds (an address in a form the API cannot read, digits that are not a phone number, a number written with letters, a host that is not a dotted domain name) are refused before any request, at no cost. The default level, fast, answers from cached intelligence without a live DNS, WHOIS or OTX call (a hash nobody has cached may wait up to ~2.5 s on CIRCL); facets not cached yet are listed in meta.pending, and one re-check after a few seconds may complete them; if they are still pending then, keep the answer and do not re-check again. Costs one request of the monthly quota; check_url is the cheaper pre-fetch gate for a link.`,
  inputSchema: {
    type: "object",
    properties: {
      indicator: {
        type: "string",
        description: `The IP, domain, URL, file hash (${SUPPORTED_HASHES}), email address or phone number to check. Defanged forms are accepted, and so are full-width characters, a display-name address (Name <user@example.com>), a mailto:, tel:, sms: or callto: link, and a labelled hash (sha256:…).`,
        minLength: 1,
        maxLength: MAX_INDICATOR_LENGTH,
      },
      enrichment: {
        type: "string",
        enum: [...ENRICHMENT],
        description:
          '"fast" (default): cached intelligence only, no live upstream call before the answer; facets not cached yet are listed in meta.pending and fetched in the background, so one re-check after a few seconds may complete them (a hash no source has cached may wait up to a few seconds on CIRCL). "standard": may call live upstreams (DNS, OTX, CIRCL) before answering; seconds on an entity nobody has checked recently. "basic": verdict and blocklists only, no risk score. Email addresses and phone numbers are answered from cached data at every level.',
      },
      country: {
        type: "string",
        minLength: 2,
        maxLength: 2,
        description:
          "ISO 3166-1 alpha-2 country (FR, GB, DE…) for a phone number written in national format, e.g. 06 12 34 56 78 with FR. Not needed for +… or 00… numbers; without it a 10-digit number is read as North American. Ignored for other indicators.",
      },
    },
    required: ["indicator"],
    additionalProperties: false,
  },
  annotations: READ_ONLY_TOOL,
  requiresKey: true,
  timeoutMs: 25_000,
  cacheTtlSec: 60,
  cacheArgs: (args) => {
    const { raw, classified, enrichment, country } = normalize(args);
    return {
      indicator: classified?.ok ? classified.value : raw,
      enrichment,
      country: country ?? undefined,
    };
  },
  rebind: (value, args) => withOwnInput(value, normalize(args).raw),
  async call(args, ctx) {
    const { raw, tooLong, classified, enrichment, country } = normalize(args);
    if (tooLong)
      return fail(
        invalidParams(
          `indicator is longer than ${MAX_INDICATOR_LENGTH} characters.`,
        ),
      );
    if (!raw || !classified)
      return fail(invalidParams("indicator is required."));
    if (!classified.ok) return fail(invalidParams(classified.message));
    if (country === null)
      return fail(
        invalidParams(
          "country must be an ISO 3166-1 alpha-2 code such as FR or GB.",
        ),
      );
    const query = new URLSearchParams({ query: classified.value, enrichment });
    if (country) query.set("country", country);
    const fetched = await fetchJson(ctx, () =>
      ctx.http.get(`/check?${query.toString()}`, {
        signal: ctx.signal,
        timeoutMs: ctx.timeoutMs,
      }),
    );
    if (!fetched.ok) return fail(fetched.error);
    return ok(
      projectCheckResult(classified.value, fetched.json, {
        localType: classified.kind,
        requestedEnrichment: enrichment,
        input: classified.input,
      }),
    );
  },
};
