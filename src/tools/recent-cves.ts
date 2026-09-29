import { invalidParams } from "../errors.js";
import { projectRecentCves } from "../projections/cve.js";
import { fetchJson } from "./request.js";
import { fail, ok, type ToolDefinition } from "./types.js";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;
export const RECENT_CVES_MAX = 20;

export const recentCves: ToolDefinition = {
  name: "recent_cves",
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
  requiresKey: true,
  timeoutMs: 10_000,
  async call(args, ctx) {
    let limit = 10;
    if (args.limit !== undefined) {
      if (
        typeof args.limit !== "number" ||
        !Number.isInteger(args.limit) ||
        args.limit < 1
      ) {
        return fail(
          invalidParams(
            `limit must be an integer between 1 and ${RECENT_CVES_MAX}.`,
          ),
        );
      }
      limit = Math.min(args.limit, RECENT_CVES_MAX);
    }
    let severity: string | undefined;
    if (args.severity !== undefined) {
      const s =
        typeof args.severity === "string" ? args.severity.toUpperCase() : "";
      if (!(SEVERITIES as readonly string[]).includes(s)) {
        return fail(
          invalidParams(`severity must be one of ${SEVERITIES.join(", ")}.`),
        );
      }
      severity = s;
    }
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
