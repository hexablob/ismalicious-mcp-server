import { isRecord } from "../cache.js";
import { invalidParams } from "../errors.js";
import {
  classifyIndicator,
  MAX_INDICATOR_CHARS,
  normalizeCountry,
  SUPPORTED_HASHES,
  type Classification,
} from "../indicators.js";
import { fetchJson } from "./request.js";
import { fail, ok, READ_ONLY_TOOL, type ToolDefinition } from "./types.js";

/**
 * Tool ceiling. The plan ceiling is lower on most plans (Free 10, Basic 50,
 * Pro 100, Enterprise 500 — `Plan::bulk_limit`); over it the API answers 400
 * with `errors[]` naming the plan limit, relayed as `bad_request`.
 */
export const CHECK_INDICATORS_MAX = 100;
const ENRICHMENT = ["basic", "standard", "full"] as const;
type Enrichment = (typeof ENRICHMENT)[number];

/**
 * Every value a row's `recommendedAction` takes: the Data Trust ladder
 * (`data_trust.rs::recommended_action`) for IP/domain/URL/hash rows, and
 * `unverified` for an email address or phone number nothing is known about.
 */
export const BULK_ACTIONS = [
  "block",
  "escalate",
  "review",
  "monitor",
  "allow",
  "unverified",
] as const;

interface BulkRow {
  entity?: unknown;
  type?: unknown;
  isMalicious?: unknown;
  confidence?: unknown;
  sources?: unknown;
  categories?: unknown;
  riskScore?: unknown;
  riskLevel?: unknown;
  lookupStatus?: unknown;
  recommendedAction?: unknown;
  infrastructure?: { attributes?: unknown } | null;
  pending?: unknown;
  error?: unknown;
}

type Row = Record<string, unknown>;

type Parsed =
  | {
      ok: true;
      /** Every item, in input order, typed locally. */
      items: Classification[];
      /** What is sent: the refanged value of every item the API can look up. */
      entities: string[];
      enrichment: Enrichment;
      country?: string;
    }
  | { ok: false; message: string };

/**
 * The API keeps only entries of 3 bytes or more once trimmed and lowercased
 * (`bulk.rs`); a shorter one got no row and vanished from the answer, and a
 * batch of nothing else was still charged the one request the gate takes.
 * Said of a value typing refused as no kind at all too (`ab` is no hostname
 * either): its length is the more useful reason.
 */
const MIN_ENTITY_BYTES = 3;

function tooShort(item: Classification): Classification {
  const plain =
    item.ok || (item.value !== "" && !item.looksLike && !item.unsupportedHash);
  if (
    !plain ||
    Buffer.byteLength(item.value.toLowerCase(), "utf8") >= MIN_ENTITY_BYTES
  )
    return item;
  return {
    ok: false,
    input: item.input,
    value: item.value,
    message: `${item.value} is shorter than ${MIN_ENTITY_BYTES} characters: the API skips it and returns no row. Nothing was sent and no request was charged.`,
  };
}

/**
 * The batch as sent: shared by the call and the cache key, and typed afresh
 * on each use from the values the arguments hold then. Until 0.5.0 it was
 * memoised on the arguments object's identity: an embedder of
 * `createServer` that reused or mutated one object got the previous batch's
 * parse, sent it, and — the cache on — the previous batch's answer, an allow
 * for indicators never looked up. Typing is linear, so the three uses per
 * call (`cacheArgs`, `call`, `rebind`) cost little even on a hostile batch.
 */
function parse(args: Record<string, unknown>): Parsed {
  if (!Array.isArray(args.indicators) || args.indicators.length === 0)
    return { ok: false, message: "indicators must be a non-empty array." };
  if (args.indicators.length > CHECK_INDICATORS_MAX)
    return {
      ok: false,
      message: `indicators holds ${args.indicators.length} items; the ceiling is ${CHECK_INDICATORS_MAX} per call (each one costs one request).`,
    };
  const items: Classification[] = [];
  for (const item of args.indicators) {
    const v = typeof item === "string" ? item.trim() : "";
    if (!v) return { ok: false, message: "indicators must all be strings." };
    if (v.length > MAX_INDICATOR_CHARS)
      return {
        ok: false,
        message: `an indicator is longer than ${MAX_INDICATOR_CHARS} characters.`,
      };
    items.push(tooShort(classifyIndicator(v)));
  }
  const country = normalizeCountry(args.country);
  if (country === null)
    return {
      ok: false,
      message: "country must be an ISO 3166-1 alpha-2 code such as FR or GB.",
    };
  const enrichment: Enrichment = (ENRICHMENT as readonly string[]).includes(
    args.enrichment as string,
  )
    ? (args.enrichment as Enrichment)
    : "standard";
  const entities = items.flatMap((c) => (c.ok ? [c.value] : []));
  return { ok: true, items, entities, enrichment, country };
}

/** The API dedups on the trimmed, lowercased string and echoes that form. */
function rowKey(value: string): string {
  return value.trim().toLowerCase();
}

function countMalicious(rows: unknown[]): number {
  return rows.filter(
    (r) => (r as { malicious?: unknown } | null)?.malicious === true,
  ).length;
}

/** One compact row per entity; `evidence` and `observedAt` are dropped. */
function projectRow(raw: unknown): Row {
  const r = (raw ?? {}) as BulkRow;
  const row: Row = {
    entity: typeof r.entity === "string" ? r.entity : String(r.entity ?? ""),
    type: typeof r.type === "string" ? r.type : "unknown",
    malicious: r.isMalicious === true,
    recommendedAction:
      typeof r.recommendedAction === "string" ? r.recommendedAction : "review",
    sources: typeof r.sources === "number" ? r.sources : 0,
  };
  if (typeof r.riskScore === "number") row.riskScore = r.riskScore;
  if (typeof r.riskLevel === "string") row.riskLevel = r.riskLevel;
  if (Array.isArray(r.categories) && r.categories.length > 0)
    row.categories = r.categories.slice(0, 5);
  if (typeof r.lookupStatus === "string") row.lookupStatus = r.lookupStatus;
  if (r.infrastructure && Array.isArray(r.infrastructure.attributes))
    row.infrastructure = r.infrastructure.attributes;
  // A cold hash past the API's CIRCL deadline comes back unknown with
  // `pending: ["circl"]`: not a settled unknown, and a re-check can answer.
  const pending = Array.isArray(r.pending)
    ? r.pending.filter((p): p is string => typeof p === "string")
    : [];
  if (pending.length > 0) row.pending = pending;
  if (typeof r.error === "string") row.error = r.error;
  return row;
}

const NOUN: Record<string, string> = {
  email: "email address",
  phone: "phone number",
};

/**
 * An address or a number the API typed as something else: a server from
 * before email and phone support, which looked it up as a domain (or refused
 * it as an unsupported type). Its `malicious: false` is about a key that
 * never exists, so nothing of the row is kept but the entity.
 */
function unevaluatedRow(entity: string, kind: string, answered: unknown): Row {
  return {
    entity,
    type: kind,
    malicious: false,
    recommendedAction: "unverified",
    sources: 0,
    lookupStatus: "unknown",
    error: `The API did not evaluate this ${NOUN[kind]} (it answered as ${typeof answered === "string" ? answered : "an untyped row"}): no verdict, which is not a clean one.`,
  };
}

/**
 * Refused here, never sent: a digest or fuzzy hash the API does not index,
 * an address or a number in a shape the API cannot read, an entry under 3
 * characters, or a value that was nothing but brackets and defanging.
 */
function refusedRow(item: Extract<Classification, { ok: false }>): Row {
  return {
    entity: item.input,
    type: item.looksLike ?? "unknown",
    ...(item.unsupportedHash ? { hashType: item.unsupportedHash } : {}),
    malicious: false,
    recommendedAction: "unverified",
    sources: 0,
    error: item.message,
  };
}

/**
 * Rows in input order: each item's API row (matched on the form the API
 * echoes), its refusal when it was never sent, then any API row no item
 * claimed. A row whose local type is email or phone and whose API type is
 * not the same is replaced by an unevaluated row.
 */
function mergeRows(items: Classification[], apiRows: unknown[]): Row[] {
  const projected = apiRows.map(projectRow);
  const byKey = new Map<string, Row[]>();
  for (const row of projected) {
    const key = rowKey(String(row.entity));
    byKey.set(key, [...(byKey.get(key) ?? []), row]);
  }
  const claimed = new Set<Row>();
  const seen = new Set<string>();
  const out: Row[] = [];
  for (const item of items) {
    const key = `${item.ok ? "ok" : "refused"}:${rowKey(item.ok ? item.value : item.input)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (!item.ok) {
      out.push(refusedRow(item));
      continue;
    }
    const row = byKey.get(rowKey(item.value))?.find((r) => !claimed.has(r));
    if (!row) continue;
    claimed.add(row);
    out.push(
      (item.kind === "email" || item.kind === "phone") && row.type !== item.kind
        ? unevaluatedRow(String(row.entity), item.kind, row.type)
        : row,
    );
  }
  for (const row of projected) if (!claimed.has(row)) out.push(row);
  return out;
}

/**
 * Each row's `input`, when refanging changed the value, so the agent can map
 * the row back — from this call's items. Calls are keyed on the refanged
 * values, so a batch shared with another call (cached, or in flight) carried
 * that call's inputs; they are replaced, never replayed.
 */
function withInputs(rows: unknown[], items: Classification[]): unknown[] {
  const inputs = new Map<string, string | undefined>();
  for (const item of items) {
    if (!item.ok) continue;
    const key = rowKey(item.value);
    if (inputs.has(key)) continue;
    inputs.set(key, rowKey(item.input) !== key ? item.input : undefined);
  }
  return rows.map((row) => {
    if (!isRecord(row) || typeof row.entity !== "string") return row;
    const key = rowKey(row.entity);
    if (!inputs.has(key)) return row;
    const { input: _shared, ...rest } = row;
    const input = inputs.get(key);
    return input ? { ...rest, input } : rest;
  });
}

function countPending(rows: unknown[]): number {
  return rows.filter(
    (r) => isRecord(r) && Array.isArray(r.pending) && r.pending.length > 0,
  ).length;
}

export const checkIndicators: ToolDefinition = {
  name: "check_indicators",
  title: "Check indicators in bulk",
  description: `Reputation of up to ${CHECK_INDICATORS_MAX} indicators in one call, for triaging a list rather than one alert: IPs, domains, URLs, file hashes (${SUPPORTED_HASHES}), email addresses and phone numbers, mixed freely; defanged input is accepted. Each row: malicious, recommendedAction (${BULK_ACTIONS.join(", ")}; unverified means nothing is known either way, and an email address or phone number is never allow), risk 0-100 with level, the number of threat blocklists citing it, categories, lookupStatus, and \`infrastructure\` (cloud, cdn, tor-exit…) when the entity is known as such. A row with \`pending\` (e.g. ["circl"] for a hash whose lookup outlasted the API's deadline) is not settled: re-check it once, after a few seconds. A URL row is judged on its host. BILLING: every unique indicator the API receives charges one request of the monthly quota — unique after trimming and lowercasing, and including rows the API cannot type, which come back with an error. Exact duplicates are free; entries under 3 characters, SHA-512, TLSH and ssdeep, and input that is none of the six kinds (an address or a number in a shape the API cannot read, a number written with letters, a host that is not a dotted domain name) are refused here with a per-row error, never sent and never charged. Plans cap the batch below the tool ceiling (Free 10, Basic 50, Pro 100); over the cap the API refuses the whole batch. Use check_indicator for the full picture of one indicator.`,
  inputSchema: {
    type: "object",
    properties: {
      indicators: {
        type: "array",
        items: {
          type: "string",
          minLength: 3,
          maxLength: MAX_INDICATOR_CHARS,
        },
        minItems: 1,
        maxItems: CHECK_INDICATORS_MAX,
        description: `The indicators to check, at most ${CHECK_INDICATORS_MAX}. Each unique one sent costs one request.`,
      },
      enrichment: {
        type: "string",
        enum: [...ENRICHMENT],
        description:
          '"standard" (default) adds the risk score; "basic" is the verdict and blocklist count only and answers faster; "full" adds nothing visible in this projection.',
      },
      country: {
        type: "string",
        minLength: 2,
        maxLength: 2,
        description:
          "ISO 3166-1 alpha-2 country applied to every phone number written in national format (06 12 34 56 78 with FR). Numbers written with + or 00 ignore it.",
      },
    },
    required: ["indicators"],
    additionalProperties: false,
  },
  annotations: READ_ONLY_TOOL,
  requiresKey: true,
  timeoutMs: 60_000,
  // 100 rows of SHA-256 hashes with categories, or of 150-character URLs,
  // fit whole; past this, tail rows are dropped and `malicious` still counts
  // every row, with the split between kept and dropped rows alongside.
  maxResultBytes: 49_152,
  listCap: {
    field: "results",
    describe: (kept, omitted) => ({
      maliciousReturned: countMalicious(kept),
      maliciousOmitted: countMalicious(omitted),
    }),
  },
  cacheTtlSec: 60,
  rebind: (value, args) => {
    const p = parse(args);
    if (!p.ok || !isRecord(value) || !Array.isArray(value.results))
      return value;
    return { ...value, results: withInputs(value.results, p.items) };
  },
  cacheArgs: (args) => {
    const p = parse(args);
    return p.ok
      ? {
          items: p.items.map((c) => (c.ok ? c.value : `!${c.input}`)),
          enrichment: p.enrichment,
          country: p.country,
        }
      : args;
  },
  async call(args, ctx) {
    const parsed = parse(args);
    if (!parsed.ok) return fail(invalidParams(parsed.message));
    const { items, entities, enrichment, country } = parsed;
    const refused = items.length - entities.length;
    const refusalNote =
      refused > 0
        ? [
            `${refused} ${refused === 1 ? "indicator was" : "indicators were"} refused before sending and not charged; each row's error says why.`,
          ]
        : [];
    let body: {
      processed?: unknown;
      results?: unknown;
      errors?: unknown;
    } = {};
    // Nothing the API can look up: answer without a request, charged nothing.
    if (entities.length > 0) {
      const fetched = await fetchJson(ctx, () =>
        ctx.http.post(
          "/bulk/check",
          {
            entities,
            enrichment,
            format: "json",
            ...(country ? { country } : {}),
          },
          { signal: ctx.signal, timeoutMs: ctx.timeoutMs },
        ),
      );
      if (!fetched.ok) return fail(fetched.error);
      body = (fetched.json ?? {}) as typeof body;
    }
    const apiRows = Array.isArray(body.results) ? body.results : [];
    const results = withInputs(mergeRows(items, apiRows), items);
    const pendingRows = countPending(results);
    const pendingNote =
      pendingRows > 0
        ? [
            `${pendingRows} ${pendingRows === 1 ? "row is" : "rows are"} not settled: its lookup was still running when the API answered (pending lists what). Re-check ${pendingRows === 1 ? "it" : "them"} once, after a few seconds; unknown there is not a verdict.`,
          ]
        : [];
    const apiNotes = Array.isArray(body.errors) ? body.errors : [];
    const notes = [...refusalNote, ...pendingNote, ...apiNotes];
    return ok({
      submitted: items.length,
      processed:
        typeof body.processed === "number" ? body.processed : apiRows.length,
      ...(refused > 0 ? { refused } : {}),
      malicious: countMalicious(results),
      ...(pendingRows > 0 ? { pendingRows } : {}),
      notes: notes.length > 0 ? notes : undefined,
      results,
    });
  },
};
