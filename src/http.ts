/**
 * HTTP layer shared by every tool.
 *
 * Owns what the tools must not each reinvent: the auth and identification
 * headers, a per-request timeout, cancellation chained from the MCP client,
 * and the quota headers the API sends on every response — which the previous
 * version discarded, so a model could not tell a 401 from a 429 and never saw
 * how much quota was left.
 */

import { SERVER_VERSION } from "./version.js";

export interface RateLimitWindow {
  limit: number;
  remaining: number;
  /** Epoch milliseconds when the window resets, when the API said so. */
  resetMs?: number;
  type?: string;
}

export interface UsageWindow {
  usage: number;
  limit: number;
  percentage?: number;
}

/**
 * Quota state read off response headers. `apps/rust-api/src/auth/middleware.rs`
 * sets these on success and on 429 alike, so a client can track its budget
 * without a dedicated endpoint.
 */
export interface QuotaHeaders {
  retryAfterSec?: number;
  rateLimit?: RateLimitWindow;
  monthly?: UsageWindow;
  daily?: UsageWindow;
  plan?: string;
}

export interface HttpResponse {
  status: number;
  /** Parsed JSON body, or `null` when the body was empty or not JSON. */
  json: unknown;
  /** True when a body was present and did not parse as JSON. */
  invalidBody: boolean;
  headers: QuotaHeaders;
}

export interface RequestOptions {
  signal?: AbortSignal;
  timeoutMs?: number;
}

export interface HttpClient {
  get(path: string, options?: RequestOptions): Promise<HttpResponse>;
  post(
    path: string,
    body: unknown,
    options?: RequestOptions,
  ): Promise<HttpResponse>;
}

export class HttpTimeoutError extends Error {
  constructor(public readonly timeoutMs: number) {
    super(`request timed out after ${timeoutMs} ms`);
    this.name = "HttpTimeoutError";
  }
}

export class HttpCancelledError extends Error {
  constructor() {
    super("request cancelled by the client");
    this.name = "HttpCancelledError";
  }
}

export class HttpNetworkError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "HttpNetworkError";
  }
}

export const DEFAULT_TIMEOUT_MS = 20_000;

function num(value: string | null): number | undefined {
  if (value == null) return undefined;
  const n = Number(value);
  return Number.isFinite(n) ? n : undefined;
}

/** Read the quota headers the API sets (`auth/middleware.rs`). */
export function parseQuotaHeaders(headers: Headers): QuotaHeaders {
  const out: QuotaHeaders = {};
  const retry = num(headers.get("retry-after"));
  if (retry !== undefined) out.retryAfterSec = retry;

  const limit = num(headers.get("x-ratelimit-limit"));
  const remaining = num(headers.get("x-ratelimit-remaining"));
  if (limit !== undefined && remaining !== undefined) {
    out.rateLimit = { limit, remaining };
    const reset = num(headers.get("x-ratelimit-reset"));
    if (reset !== undefined) out.rateLimit.resetMs = reset;
    const type = headers.get("x-ratelimit-type");
    if (type) out.rateLimit.type = type;
  }

  const monthlyUsage = num(headers.get("x-monthly-usage"));
  const monthlyLimit = num(headers.get("x-monthly-limit"));
  if (monthlyUsage !== undefined && monthlyLimit !== undefined) {
    out.monthly = { usage: monthlyUsage, limit: monthlyLimit };
    const pct = num(headers.get("x-monthly-percentage"));
    if (pct !== undefined) out.monthly.percentage = pct;
  }

  const dailyUsage = num(headers.get("x-daily-usage"));
  const dailyLimit = num(headers.get("x-daily-limit"));
  if (dailyUsage !== undefined && dailyLimit !== undefined) {
    out.daily = { usage: dailyUsage, limit: dailyLimit };
  }

  const plan = headers.get("x-ratelimit-plan");
  if (plan) out.plan = plan;
  return out;
}

export interface HttpClientConfig {
  /** Base URL, e.g. `https://ismalicious.com/api`. Trailing slash tolerated. */
  baseUrl: string;
  /** `X-API-KEY` value, or `null` before a key exists (bootstrap mode). */
  apiKeyHeader: string | null;
  /** Name of the tool making the call; sent as `X-Ismalicious-Tool`. */
  tool?: string;
  defaultTimeoutMs?: number;
  /** Called with the quota headers of every response, for the quota resource. */
  onQuota?: (quota: QuotaHeaders) => void;
  /** Injectable for tests. */
  fetchImpl?: typeof fetch;
}

export interface ConfigurableHttpClient extends HttpClient {
  setApiKeyHeader(value: string | null): void;
  withTool(tool: string): HttpClient;
}

/**
 * The real client. One `AbortController` per request: the timeout aborts it
 * with reason `timeout`, the MCP client's cancellation aborts it with reason
 * `cancelled`, and the two are told apart afterwards.
 */
export function defaultHttpClient(
  config: HttpClientConfig,
): ConfigurableHttpClient {
  const base = config.baseUrl.replace(/\/$/, "");
  const fetchImpl = config.fetchImpl ?? fetch;
  const defaultTimeout = config.defaultTimeoutMs ?? DEFAULT_TIMEOUT_MS;
  let apiKeyHeader = config.apiKeyHeader;

  function headersFor(tool: string | undefined, hasBody: boolean) {
    const h: Record<string, string> = {
      Accept: "application/json",
      "User-Agent": `ismalicious-mcp/${SERVER_VERSION}`,
    };
    if (hasBody) h["Content-Type"] = "application/json";
    if (apiKeyHeader) h["X-API-KEY"] = apiKeyHeader;
    if (tool) h["X-Ismalicious-Tool"] = tool;
    return h;
  }

  async function run(
    tool: string | undefined,
    path: string,
    init: { method: "GET" | "POST"; body?: unknown },
    options: RequestOptions = {},
  ): Promise<HttpResponse> {
    const controller = new AbortController();
    const timeoutMs = options.timeoutMs ?? defaultTimeout;
    const timer = setTimeout(() => controller.abort("timeout"), timeoutMs);
    const onOuterAbort = () => controller.abort("cancelled");
    if (options.signal) {
      if (options.signal.aborted) onOuterAbort();
      else
        options.signal.addEventListener("abort", onOuterAbort, { once: true });
    }

    try {
      const res = await fetchImpl(`${base}${path}`, {
        method: init.method,
        headers: headersFor(tool, init.body !== undefined),
        body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
        signal: controller.signal,
      });
      const quota = parseQuotaHeaders(res.headers);
      config.onQuota?.(quota);
      const text = await res.text();
      let json: unknown = null;
      let invalidBody = false;
      if (text.trim().length > 0) {
        try {
          json = JSON.parse(text);
        } catch {
          invalidBody = true;
        }
      }
      return { status: res.status, json, invalidBody, headers: quota };
    } catch (e) {
      if (controller.signal.aborted) {
        if (controller.signal.reason === "timeout") {
          throw new HttpTimeoutError(timeoutMs);
        }
        throw new HttpCancelledError();
      }
      throw new HttpNetworkError(e instanceof Error ? e.message : String(e));
    } finally {
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", onOuterAbort);
    }
  }

  const client: ConfigurableHttpClient = {
    get: (path, options) => run(config.tool, path, { method: "GET" }, options),
    post: (path, body, options) =>
      run(config.tool, path, { method: "POST", body }, options),
    setApiKeyHeader(value) {
      apiKeyHeader = value;
    },
    withTool(tool) {
      return {
        get: (path, options) => run(tool, path, { method: "GET" }, options),
        post: (path, body, options) =>
          run(tool, path, { method: "POST", body }, options),
      };
    },
  };
  return client;
}
