import { invalidParams } from "../errors.js";
import { fetchJson } from "./request.js";
import { fail, ok, type ToolDefinition } from "./types.js";

/**
 * Tool ceiling. The plan ceiling is lower on most plans (Free 10, Basic 50,
 * Pro 100, Enterprise 500 — `Plan::bulk_limit`); over it the API answers 400
 * with `errors[]` naming the plan limit, relayed as `bad_request`.
 */
export const CHECK_INDICATORS_MAX = 100;
const ENRICHMENT = ["basic", "standard", "full"] as const;
type Enrichment = (typeof ENRICHMENT)[number];

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
  error?: unknown;
}

/** One compact row per entity; `evidence` and `observedAt` are dropped. */
function projectRow(raw: unknown) {
  const r = (raw ?? {}) as BulkRow;
  const row: Record<string, unknown> = {
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
  if (typeof r.error === "string") row.error = r.error;
  return row;
}

export const checkIndicators: ToolDefinition = {
  name: "check_indicators",
  description: `Reputation of up to ${CHECK_INDICATORS_MAX} indicators (IPs, domains, URLs, MD5/SHA-1/SHA-256 hashes) in one call — for triaging a list, not one alert. Each row: malicious, recommendedAction (block/review), risk 0-100 with level, the number of threat blocklists citing it, categories, and \`infrastructure\` (cloud, cdn, tor-exit…) when the entity is known as such. EVERY INDICATOR CHARGES ONE REQUEST of the monthly quota (duplicates and rejects are free), so ${CHECK_INDICATORS_MAX} indicators cost ${CHECK_INDICATORS_MAX} requests. Plans cap the batch below the tool ceiling (Free 10, Basic 50, Pro 100); over the cap the API refuses the whole batch. Use check_indicator for the full picture of one indicator.`,
  inputSchema: {
    type: "object",
    properties: {
      indicators: {
        type: "array",
        items: { type: "string", minLength: 3, maxLength: 2048 },
        minItems: 1,
        maxItems: CHECK_INDICATORS_MAX,
        description: `The indicators to check, at most ${CHECK_INDICATORS_MAX}. Each one costs one request.`,
      },
      enrichment: {
        type: "string",
        enum: [...ENRICHMENT],
        description:
          '"standard" (default) adds the risk score; "basic" is the verdict and blocklist count only and answers faster; "full" adds nothing visible in this projection.',
      },
    },
    required: ["indicators"],
    additionalProperties: false,
  },
  requiresKey: true,
  timeoutMs: 60_000,
  maxResultBytes: 24_576,
  async call(args, ctx) {
    if (!Array.isArray(args.indicators) || args.indicators.length === 0)
      return fail(invalidParams("indicators must be a non-empty array."));
    if (args.indicators.length > CHECK_INDICATORS_MAX)
      return fail(
        invalidParams(
          `indicators holds ${args.indicators.length} items; the ceiling is ${CHECK_INDICATORS_MAX} per call (each one costs one request).`,
        ),
      );
    const entities: string[] = [];
    for (const item of args.indicators) {
      const v = typeof item === "string" ? item.trim() : "";
      if (!v) return fail(invalidParams("indicators must all be strings."));
      if (v.length > 2048)
        return fail(
          invalidParams("an indicator is longer than 2048 characters."),
        );
      entities.push(v);
    }
    const enrichment: Enrichment = (ENRICHMENT as readonly string[]).includes(
      args.enrichment as string,
    )
      ? (args.enrichment as Enrichment)
      : "standard";
    const fetched = await fetchJson(ctx, () =>
      ctx.http.post(
        "/bulk/check",
        { entities, enrichment, format: "json" },
        { signal: ctx.signal, timeoutMs: ctx.timeoutMs },
      ),
    );
    if (!fetched.ok) return fail(fetched.error);
    const body = (fetched.json ?? {}) as {
      success?: unknown;
      total?: unknown;
      processed?: unknown;
      results?: unknown;
      errors?: unknown;
      processingTimeMs?: unknown;
    };
    const results = Array.isArray(body.results)
      ? body.results.map(projectRow)
      : [];
    const malicious = results.filter((r) => r.malicious === true).length;
    return ok({
      submitted: entities.length,
      processed:
        typeof body.processed === "number" ? body.processed : results.length,
      malicious,
      notes: Array.isArray(body.errors) ? body.errors : undefined,
      results,
    });
  },
};
