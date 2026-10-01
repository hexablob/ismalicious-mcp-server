import { invalidParams } from "../errors.js";
import { projectRecentCves } from "../projections/cve.js";
import { fetchJson } from "./request.js";
import { fail, ok, READ_ONLY_TOOL, type ToolDefinition } from "./types.js";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;
export const RECENT_CVES_MAX = 20;

type Parsed =
  | { ok: true; limit: number; severity?: string }
  | { ok: false; message: string };

/** The arguments as sent: shared by the call and the cache key. */
function parse(args: Record<string, unknown>): Parsed {
  let limit = 10;
  if (args.limit !== undefined) {
    if (
      typeof args.limit !== "number" ||
      !Number.isInteger(args.limit) ||
      args.limit < 1
    ) {
      return {
        ok: false,
        message: `limit must be an integer between 1 and ${RECENT_CVES_MAX}.`,
      };
    }
    limit = Math.min(args.limit, RECENT_CVES_MAX);
  }
  let severity: string | undefined;
  if (args.severity !== undefined) {
    const s =
      typeof args.severity === "string" ? args.severity.toUpperCase() : "";
    if (!(SEVERITIES as readonly string[]).includes(s)) {
      return {
        ok: false,
        message: `severity must be one of ${SEVERITIES.join(", ")}.`,
      };
    }
    severity = s;
  }
  return { ok: true, limit, severity };
}

export const recentCves: ToolDefinition = {
  name: "recent_cves",
  title: "Latest published CVEs",
  description:
    "Most recently published CVEs, newest first, optionally filtered by severity. At most 20 items, each with id, severity, CVSS, publication date and a one-line title. Follow up with get_cve for details. Costs one request of the monthly quota.",
  inputSchema: {
    type: "object",
    properties: {
      severity: {
        type: "string",
        enum: [...SEVERITIES],
        description: "Keep only this severity.",
      },
      limit: {
        type: "integer",
        minimum: 1,
        maximum: RECENT_CVES_MAX,
        description: `Number of CVEs to return (default 10, max ${RECENT_CVES_MAX}).`,
      },
    },
    additionalProperties: false,
  },
  annotations: READ_ONLY_TOOL,
  requiresKey: true,
  timeoutMs: 10_000,
  cacheTtlSec: 300,
  cacheArgs: (args) => {
    const p = parse(args);
    return p.ok ? { limit: p.limit, severity: p.severity } : args;
  },
  async call(args, ctx) {
    const parsed = parse(args);
    if (!parsed.ok) return fail(invalidParams(parsed.message));
    const { limit, severity } = parsed;
    const params = new URLSearchParams({
      recent: "true",
      limit: String(limit),
    });
    if (severity) params.set("severity", severity);
    const fetched = await fetchJson(ctx, () =>
      ctx.http.get(`/cve?${params.toString()}`, {
        signal: ctx.signal,
        timeoutMs: ctx.timeoutMs,
      }),
    );
    if (!fetched.ok) return fail(fetched.error);
    return ok(projectRecentCves(fetched.json, { limit, severity }));
  },
};
