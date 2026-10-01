/**
 * The error envelope every tool returns with `isError: true`.
 *
 * v0.1 collapsed the HTTP status to a boolean, so the model could not tell an
 * expired key from an exhausted quota from an outage, and a 200 with a
 * non-JSON body came back as a successful `"null"`. Each case now has a code,
 * the status, a message, the quota block when a limit was hit, and a hint the
 * model can act on.
 */

import {
  HttpCancelledError,
  HttpNetworkError,
  HttpTimeoutError,
  type HttpResponse,
  type QuotaHeaders,
} from "./http.js";

export type ToolErrorCode =
  | "rate_limited"
  | "unauthorized"
  | "forbidden"
  | "not_found"
  | "bad_request"
  | "upstream_error"
  | "timeout"
  | "network_error"
  | "invalid_params";

export interface QuotaBlock {
  kind: "burst" | "monthly" | "daily" | "scans" | "issuance";
  used?: number;
  limit?: number;
  remaining?: number;
  plan?: string;
  /** Seconds to wait before retrying, when the API said so. */
  retry_after?: number | null;
  /** ISO timestamp of the reset, when it can be derived. */
  resets_at?: string | null;
}

export interface ToolErrorEnvelope {
  error: ToolErrorCode;
  status?: number;
  message: string;
  quota?: QuotaBlock;
  hint?: string;
}

export interface ErrorContext {
  keyConfigured: boolean;
  /** Only set for `get_cve`, whose 404 carries a route-specific hint. */
  notFoundHint?: string;
}

const KEY_HINT =
  "Set ISMALICIOUS_API_KEY and ISMALICIOUS_API_SECRET in the MCP client config (keys: https://ismalicious.com/app/account), or call the bootstrap_key tool to mint a free key from an email address.";

function bodyMessage(json: unknown, fallback: string): string {
  if (json && typeof json === "object") {
    const o = json as Record<string, unknown>;
    if (typeof o.message === "string" && o.message) return o.message;
    if (typeof o.error === "string" && o.error) return o.error;
  }
  return fallback;
}

function bodyString(json: unknown, key: string): string | undefined {
  if (json && typeof json === "object") {
    const v = (json as Record<string, unknown>)[key];
    if (typeof v === "string") return v;
  }
  return undefined;
}

function bodyNumber(json: unknown, path: string[]): number | undefined {
  let cur: unknown = json;
  for (const key of path) {
    if (!cur || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[key];
  }
  return typeof cur === "number" ? cur : undefined;
}

/** First instant of next month, UTC — when the monthly quota resets. */
export function nextMonthStart(now: Date): string {
  const y = now.getUTCFullYear();
  const m = now.getUTCMonth();
  return new Date(Date.UTC(y, m + 1, 1)).toISOString();
}

export function quotaFrom429(
  json: unknown,
  headers: QuotaHeaders,
  now: Date,
): QuotaBlock {
  const error = bodyString(json, "error") ?? "";
  if (error === "Scan quota exceeded") {
    return {
      kind: "scans",
      used: bodyNumber(json, ["usage"]),
      limit: bodyNumber(json, ["limit"]),
      plan: headers.plan,
      retry_after: null,
      resets_at: nextMonthStart(now),
    };
  }
  if (bodyNumber(json, ["usage", "current"]) !== undefined || headers.monthly) {
    const used =
      bodyNumber(json, ["usage", "current"]) ?? headers.monthly?.usage;
    const limit =
      bodyNumber(json, ["usage", "limit"]) ?? headers.monthly?.limit;
    return {
      kind: headers.daily ? "daily" : "monthly",
      used,
      limit,
      remaining:
        used !== undefined && limit !== undefined
          ? Math.max(0, limit - used)
          : undefined,
      plan: headers.plan,
      retry_after: null,
      resets_at: headers.daily ? null : nextMonthStart(now),
    };
  }
  const retry =
    bodyNumber(json, ["retryAfter"]) ?? headers.retryAfterSec ?? null;
  return {
    kind: "burst",
    limit: headers.rateLimit?.limit ?? bodyNumber(json, ["rateLimit", "limit"]),
    remaining:
      headers.rateLimit?.remaining ??
      bodyNumber(json, ["rateLimit", "remaining"]),
    plan: headers.plan ?? bodyString(json, "plan"),
    retry_after: retry,
    resets_at:
      headers.rateLimit?.resetMs !== undefined
        ? new Date(headers.rateLimit.resetMs).toISOString()
        : retry !== null
          ? new Date(now.getTime() + retry * 1000).toISOString()
          : null,
  };
}

/**
 * Build the envelope for a response, or return `null` when the response is a
 * usable success (status < 400 and a JSON body).
 */
export function envelopeFromResponse(
  res: HttpResponse,
  ctx: ErrorContext,
  now: Date = new Date(),
): ToolErrorEnvelope | null {
  const { status, json } = res;
  if (status < 400) {
    if (res.invalidBody || json === null) {
      return {
        error: "upstream_error",
        status,
        message: "The API answered without a JSON body.",
        hint: "Retry once; if it persists the API is degraded.",
      };
    }
    return null;
  }
  if (status === 401) {
    return {
      error: "unauthorized",
      status,
      message: bodyMessage(json, "Authentication failed."),
      hint: ctx.keyConfigured
        ? "The configured key was refused: it may have been rotated or revoked. " +
          KEY_HINT
        : "No API key is configured. " + KEY_HINT,
    };
  }
  if (status === 403) {
    return {
      error: "forbidden",
      status,
      message: bodyMessage(
        json,
        "This plan does not include the requested surface.",
      ),
      hint: "Plan limits are at https://ismalicious.com/pricing.",
    };
  }
  if (status === 404) {
    return {
      error: "not_found",
      status,
      message: bodyMessage(json, "Not found."),
      ...(ctx.notFoundHint ? { hint: ctx.notFoundHint } : {}),
    };
  }
  if (status === 429) {
    const quota = quotaFrom429(json, res.headers, now);
    const wait =
      quota.retry_after != null
        ? `Wait ${quota.retry_after}s before retrying.`
        : quota.resets_at
          ? `The quota resets at ${quota.resets_at}; do not retry before then.`
          : "Do not retry in a loop.";
    return {
      error: "rate_limited",
      status,
      message: bodyMessage(json, "Rate limit exceeded."),
      quota,
      hint:
        quota.kind === "monthly" || quota.kind === "scans"
          ? `${wait} A higher allowance is a plan change: https://ismalicious.com/pricing.`
          : wait,
    };
  }
  if (status >= 400 && status < 500) {
    return {
      error: "bad_request",
      status,
      message: bodyMessage(json, "The API rejected the request."),
    };
  }
  return {
    error: "upstream_error",
    status,
    message: bodyMessage(json, `The API answered ${status}.`),
    hint: "Retry once after a short pause; a persistent 5xx is an outage on our side.",
  };
}

export function envelopeFromException(e: unknown): ToolErrorEnvelope {
  if (e instanceof HttpTimeoutError) {
    return {
      error: "timeout",
      message: e.message,
      hint: "The API did not answer in time. Retry once; raise ISMALICIOUS_TIMEOUT_<TOOL>_MS (one tool) or ISMALICIOUS_TIMEOUT_MS (every tool) if your network is slow.",
    };
  }
  if (e instanceof HttpCancelledError) {
    return { error: "network_error", message: e.message };
  }
  if (e instanceof HttpNetworkError) {
    return {
      error: "network_error",
      message: e.message,
      hint: "Check connectivity and ISMALICIOUS_API_BASE (default https://ismalicious.com/api).",
    };
  }
  return {
    error: "network_error",
    message: e instanceof Error ? e.message : String(e),
  };
}

export function invalidParams(message: string): ToolErrorEnvelope {
  return { error: "invalid_params", message };
}
