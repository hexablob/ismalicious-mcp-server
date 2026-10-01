import { invalidParams } from "../errors.js";
import { fetchJson } from "./request.js";
import { fail, ok, READ_ONLY_TOOL, type ToolDefinition } from "./types.js";

/** Server-side ceiling on hits (`MAX_HITS` in `api/search.rs`). */
export const SEARCH_MAX_HITS = 500;
const DEFAULT_LIMIT = 50;

type Parsed =
  | { ok: true; keywords: string; limit: number }
  | { ok: false; message: string };

/** The arguments as used: shared by the call and the cache key. */
function parse(args: Record<string, unknown>): Parsed {
  const keywords =
    typeof args.keywords === "string" ? args.keywords.trim() : "";
  if (keywords.length < 2)
    return { ok: false, message: "keywords must be at least 2 characters." };
  if (keywords.length > 128)
    return { ok: false, message: "keywords is longer than 128 characters." };
  let limit = DEFAULT_LIMIT;
  if (args.limit !== undefined) {
    if (
      typeof args.limit !== "number" ||
      !Number.isInteger(args.limit) ||
      args.limit < 1
    ) {
      return {
        ok: false,
        message: `limit must be an integer between 1 and ${SEARCH_MAX_HITS}.`,
      };
    }
    limit = Math.min(args.limit, SEARCH_MAX_HITS);
  }
  return { ok: true, keywords, limit };
}

/**
 * Strip the dataset key prefix (`domain:`, `ip:`, `url:`, `hash:`) the Rust
 * `/search` handler returns; the Next.js `/api/search` implementation already
 * answers bare domains, so both bases project to the same rows.
 */
function toIndicator(hit: string): { value: string; type?: string } {
  const m = /^(domain|ip|url|hash):(.+)$/.exec(hit);
  return m ? { value: m[2], type: m[1] } : { value: hit };
}

export const searchIndicators: ToolDefinition = {
  name: "search_indicators",
  title: "Find lookalike domains",
  description:
    'Find the domains isMalicious lists that look like a brand or domain (e.g. "paypal", read as paypal.com, or "login.paypal.com"): typosquats, homoglyphs, the same name on other TLDs or hosting platforms, or wrapped in phishing words such as login or secure. The default API returns them most dangerous first, at most 500, with the searched name itself first when it is listed; other API bases can have different bounds. `total_hits` counts this API sample. `truncated: true` means results were omitted; `null` means completeness is unknown. An empty answer does not prove no lookalike exists: only listed domains are returned, and a name buried in a longer hostname is not matched. Follow up with check_indicator or check_indicators for verdicts. Cost: one request of the monthly quota on the Rust API host (https://api.ismalicious.com); through the default https://ismalicious.com/api it is not charged on the monthly quota, only counted against the burst rate limit.',
  inputSchema: {
    type: "object",
    properties: {
      keywords: {
        type: "string",
        description:
          "Brand, domain or URL to find lookalikes of, e.g. paypal (read as paypal.com) or login.paypal.com.",
        minLength: 2,
        maxLength: 128,
      },
      limit: {
        type: "integer",
        minimum: 1,
        maximum: SEARCH_MAX_HITS,
        description: `Maximum hits to keep from the API sample (default ${DEFAULT_LIMIT}, max ${SEARCH_MAX_HITS}); this does not increase the backend search limit.`,
      },
    },
    required: ["keywords"],
    additionalProperties: false,
  },
  annotations: READ_ONLY_TOOL,
  requiresKey: true,
  timeoutMs: 20_000,
  // 500 hits of ~40 bytes each fit; longer hostnames drop tail rows (least
  // dangerous first, since the API sorts most dangerous first).
  maxResultBytes: 32_768,
  listCap: { field: "indicators" },
  cacheTtlSec: 300,
  cacheArgs: (args) => {
    const p = parse(args);
    return p.ok ? { keywords: p.keywords, limit: p.limit } : args;
  },
  async call(args, ctx) {
    const parsed = parse(args);
    if (!parsed.ok) return fail(invalidParams(parsed.message));
    const { keywords, limit } = parsed;
    const query = new URLSearchParams({ keywords });
    // The API routes search as a POST and reads the keywords from the query
    // string; the body is empty.
    const fetched = await fetchJson(ctx, () =>
      ctx.http.post(`/search?${query.toString()}`, undefined, {
        signal: ctx.signal,
        timeoutMs: ctx.timeoutMs,
      }),
    );
    if (!fetched.ok) return fail(fetched.error);
    const body = (fetched.json ?? {}) as {
      keywords?: unknown;
      hits?: unknown;
      total_hits?: unknown;
      truncated?: unknown;
    };
    if (
      !Array.isArray(body.hits) ||
      !body.hits.every((h) => typeof h === "string")
    ) {
      return fail({
        error: "upstream_error",
        message: "The search API answered without a valid indicator sample.",
      });
    }
    const hits = body.hits as string[];
    const truncated =
      hits.length > limit ||
      body.truncated === true ||
      (typeof body.total_hits === "number" && body.total_hits > hits.length)
        ? true
        : body.truncated === false
          ? false
          : null;
    return ok({
      keywords,
      total_hits: hits.length,
      total_hits_scope: "upstream_sample",
      returned: Math.min(hits.length, limit),
      truncated,
      indicators: hits.slice(0, limit).map(toIndicator),
    });
  },
};
