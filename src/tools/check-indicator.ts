import { invalidParams } from "../errors.js";
import { projectCheckIndicator } from "../projections/check-indicator.js";
import { fetchJson } from "./request.js";
import { fail, ok, type ToolDefinition } from "./types.js";

const ENRICHMENT = ["basic", "standard"] as const;
type Enrichment = (typeof ENRICHMENT)[number];

export const checkIndicator: ToolDefinition = {
  name: "check_indicator",
  description:
    "Reputation verdict for an IP, domain, URL or file hash (MD5/SHA-1/SHA-256): malicious, suspicious, clean or unknown, a 0-100 risk score, the threat blocklists that cite it, first/last seen, network and registration context, known CVEs on the host. `infrastructure` says what the entity is known as (cloud range, CDN, Tor exit, VPN, DoH resolver, crawler, allowlist) without being a verdict. Use it to enrich an alert or decide a block; use check_url for the cheaper pre-fetch check of a link. Costs one request of the monthly quota.",
  inputSchema: {
    type: "object",
    properties: {
      indicator: {
        type: "string",
        description: "The IP, domain, URL or hash to check.",
        minLength: 1,
        maxLength: 2048,
      },
      enrichment: {
        type: "string",
        enum: [...ENRICHMENT],
        description:
          '"standard" (default) adds network, registration and timeline context; "basic" returns the verdict and blocklists only and answers faster.',
      },
    },
    required: ["indicator"],
    additionalProperties: false,
  },
  requiresKey: true,
  timeoutMs: 25_000,
  async call(args, ctx) {
    const indicator =
      typeof args.indicator === "string" ? args.indicator.trim() : "";
    if (!indicator) return fail(invalidParams("indicator is required."));
    if (indicator.length > 2048)
      return fail(invalidParams("indicator is longer than 2048 characters."));
    const enrichment: Enrichment =
      args.enrichment === "basic" ? "basic" : "standard";
    const query = new URLSearchParams({ query: indicator, enrichment });
    const fetched = await fetchJson(ctx, () =>
      ctx.http.get(`/check?${query.toString()}`, {
        signal: ctx.signal,
        timeoutMs: ctx.timeoutMs,
      }),
    );
    if (!fetched.ok) return fail(fetched.error);
    return ok(
      projectCheckIndicator(indicator, fetched.json, {
        requestedEnrichment: enrichment,
      }),
    );
  },
};
