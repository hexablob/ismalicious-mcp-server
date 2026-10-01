/**
 * HTTP layer shared by every tool.
 *
 * Owns what the tools must not each reinvent: the auth and identification
 * headers, a per-request timeout, cancellation chained from the MCP client,
 * and the quota headers the API sends on every response — which the previous
 * version discarded, so a model could not tell a 401 from a 429 and never saw
 * how much quota was left.
 *
 * The wire is node:http / node:https on a keep-alive agent, not the global
 * fetch. undici drops an idle connection after 4 s, and an agent calls tools
 * at LLM pace — seconds apart — so nearly every call paid DNS + TCP + TLS
 * again (measured against a stub on 2026-09-30: reused at 3.9 s idle, a new
 * socket at 4.5 s). The agent below keeps an idle socket 30 s, under the
 * edge's keep-alive window, and asks for gzip/brotli: the /check document is
 * ~87 KB minified and ~12 KB gzipped.
 */

import {
  Agent as HttpAgent,
  request as httpRequest,
  type IncomingHttpHeaders,
  type IncomingMessage,
} from "node:http";
import {
  Agent as HttpsAgent,
  globalAgent as httpsGlobalAgent,
  request as httpsRequest,
} from "node:https";
import {
  brotliDecompress,
  constants as zlibConstants,
  gunzip,
  inflate,
} from "node:zlib";
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

// ─── Transport ──────────────────────────────────────────────────────────────

/** One request as the wire sees it; the client has already built the headers. */
export interface TransportRequest {
  url: string;
  method: "GET" | "POST";
  headers: Record<string, string>;
  body?: string;
  /** Aborted on timeout or cancellation; the client tells the two apart. */
  signal: AbortSignal;
}

/** A complete response: status, headers and the decoded body text. */
export interface TransportResponse {
  status: number;
  headers: Headers;
  body: string;
}

export type HttpTransport = (
  request: TransportRequest,
) => Promise<TransportResponse>;

/**
 * Idle lifetime of a pooled socket. Under nginx's default 75 s keep-alive, so
 * the client normally closes first; a server `Keep-Alive: timeout=N` hint
 * shortens it (Node subtracts a second from the hint).
 */
export const IDLE_SOCKET_TIMEOUT_MS = 30_000;
/** Same-host hops followed before giving up; the API itself never redirects. */
export const MAX_REDIRECTS = 3;
const ACCEPT_ENCODING = "gzip, br";

export interface KeepAliveAgents {
  http: HttpAgent;
  https: HttpsAgent;
}

/** Proxy variables as Node's `proxyEnv` agent option reads them. */
export type ProxyEnv = Readonly<Record<string, string | undefined>>;

/**
 * How the default wire reaches the API when Node's env-proxy mode is on
 * (`NODE_USE_ENV_PROXY=1` or `--use-env-proxy`, with `HTTPS_PROXY` /
 * `HTTP_PROXY` / `NO_PROXY`). The global `fetch` this client used until 0.4
 * honoured it; an `Agent` built here does not unless it is handed the proxy
 * variables, so behind an egress proxy every call failed on DNS.
 *
 * - `direct`: the mode is off; connect directly, as `fetch` did.
 * - `agent`: Node 22.21+ / 24.5+ builds its own global agents with
 *   `proxyEnv`; ours get the same variables and keep their pool.
 * - `fetch`: the mode is on but this Node's agents cannot proxy (it predates
 *   `proxyEnv`); go through the global `fetch`, which still can, and give up
 *   the keep-alive pool rather than the connection.
 */
export type ProxyMode =
  { kind: "direct" } | { kind: "agent"; env: ProxyEnv } | { kind: "fetch" };

export interface ProxyModeInputs {
  env: NodeJS.ProcessEnv;
  execArgv: readonly string[];
  /** What Node put on its own global agent (`options.proxyEnv`), if anything. */
  globalAgentProxyEnv: unknown;
}

function envProxyRequested(
  env: NodeJS.ProcessEnv,
  execArgv: readonly string[],
) {
  return (
    env.NODE_USE_ENV_PROXY === "1" ||
    execArgv.includes("--use-env-proxy") ||
    /(?:^|\s)--use-env-proxy(?:\s|$)/.test(env.NODE_OPTIONS ?? "")
  );
}

export function resolveProxyMode(
  inputs: ProxyModeInputs = {
    env: process.env,
    execArgv: process.execArgv,
    globalAgentProxyEnv: (
      httpsGlobalAgent as unknown as { options?: { proxyEnv?: unknown } }
    ).options?.proxyEnv,
  },
): ProxyMode {
  const fromNode = inputs.globalAgentProxyEnv;
  if (fromNode && typeof fromNode === "object") {
    return { kind: "agent", env: fromNode as ProxyEnv };
  }
  if (!envProxyRequested(inputs.env, inputs.execArgv))
    return { kind: "direct" };
  const proxied = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"];
  return proxied.some((name) => inputs.env[name])
    ? { kind: "fetch" }
    : { kind: "direct" };
}

/**
 * Agents for both schemes. `lifo` hands out the most recently used socket,
 * the one least likely to have been closed by the server; 16 sockets bound a
 * fan-out of parallel tool calls. The `timeout` only destroys a socket while
 * it sits idle in the pool: on a socket carrying a request it merely emits
 * `timeout`, which nothing here listens to — the per-request deadline is the
 * client's AbortController. `proxyEnv` routes through the proxy those
 * variables name (Node 22.21+ / 24.5+; older Node ignores the option).
 */
export function createKeepAliveAgents(
  idleTimeoutMs: number = IDLE_SOCKET_TIMEOUT_MS,
  proxyEnv?: ProxyEnv,
): KeepAliveAgents {
  const options = {
    keepAlive: true,
    maxSockets: 16,
    maxFreeSockets: 8,
    scheduling: "lifo" as const,
    timeout: idleTimeoutMs,
    ...(proxyEnv ? { proxyEnv } : {}),
  };
  return { http: new HttpAgent(options), https: new HttpsAgent(options) };
}

const PROXY_MODE = resolveProxyMode();

/** Module-level so every client in the process shares one pool per scheme. */
const SHARED_AGENTS = createKeepAliveAgents(
  IDLE_SOCKET_TIMEOUT_MS,
  PROXY_MODE.kind === "agent" ? PROXY_MODE.env : undefined,
);

export interface NodeTransportOptions {
  /** Defaults to the module-level keep-alive pool. */
  agents?: KeepAliveAgents;
  maxRedirects?: number;
}

/**
 * Marks an error the transport may retry: a connection-level failure on a
 * reused socket before the response started. That is the keep-alive race —
 * the server closed the idle socket while this request was being written —
 * and the request never reached a handler.
 */
const RETRYABLE = Symbol("retryable");

function isConnectionReset(err: unknown): boolean {
  const e = err as NodeJS.ErrnoException | undefined;
  return (
    e?.code === "ECONNRESET" ||
    e?.code === "EPIPE" ||
    /socket hang up/i.test(e?.message ?? "")
  );
}

function abortError(): Error {
  const err = new Error("request aborted");
  err.name = "AbortError";
  return err;
}

const ZLIB_OPTIONS = {
  // Lenient on a body cut short at a flush boundary, as fetch is.
  flush: zlibConstants.Z_SYNC_FLUSH,
  finishFlush: zlibConstants.Z_SYNC_FLUSH,
};
const BROTLI_OPTIONS = {
  flush: zlibConstants.BROTLI_OPERATION_FLUSH,
  finishFlush: zlibConstants.BROTLI_OPERATION_FLUSH,
};

function decodeBody(body: Buffer, encoding: string): Promise<Buffer> {
  if (body.length === 0) return Promise.resolve(body);
  return new Promise((resolve, reject) => {
    const done = (err: Error | null, out: Buffer) =>
      err ? reject(err) : resolve(out);
    switch (encoding) {
      case "gzip":
      case "x-gzip":
        gunzip(body, ZLIB_OPTIONS, done);
        return;
      case "deflate":
        inflate(body, ZLIB_OPTIONS, done);
        return;
      case "br":
        brotliDecompress(body, BROTLI_OPTIONS, done);
        return;
      default:
        // identity, or a coding we did not ask for: hand the bytes over.
        resolve(body);
    }
  });
}

function toHeaders(raw: IncomingHttpHeaders): Headers {
  const out = new Headers();
  for (const [name, value] of Object.entries(raw)) {
    if (value === undefined) continue;
    try {
      if (Array.isArray(value)) for (const v of value) out.append(name, v);
      else out.set(name, value);
    } catch {
      // A value the WHATWG Headers class refuses carries nothing we read.
    }
  }
  return out;
}

function sendOnce(
  request: TransportRequest,
  agents: KeepAliveAgents,
): Promise<TransportResponse> {
  return new Promise((resolve, reject) => {
    const url = new URL(request.url);
    const secure = url.protocol === "https:";
    if (!secure && url.protocol !== "http:") {
      reject(new Error(`unsupported URL scheme ${url.protocol}`));
      return;
    }
    if (request.signal.aborted) {
      reject(abortError());
      return;
    }
    const headers: Record<string, string> = {
      ...request.headers,
      "Accept-Encoding": ACCEPT_ENCODING,
    };
    if (request.body !== undefined) {
      headers["Content-Length"] = String(Buffer.byteLength(request.body));
    }
    const req = (secure ? httpsRequest : httpRequest)(url, {
      method: request.method,
      headers,
      agent: secure ? agents.https : agents.http,
    });

    let res: IncomingMessage | undefined;
    let settled = false;
    const settle = (fn: () => void) => {
      if (settled) return;
      settled = true;
      request.signal.removeEventListener("abort", onAbort);
      fn();
    };
    const fail = (err: unknown) => settle(() => reject(err));
    function onAbort() {
      fail(abortError());
      res?.destroy();
      req.destroy();
    }
    request.signal.addEventListener("abort", onAbort, { once: true });

    req.on("error", (err) => {
      if (!res && req.reusedSocket && isConnectionReset(err)) {
        (err as unknown as Record<symbol, boolean>)[RETRYABLE] = true;
      }
      fail(err);
    });
    req.on("response", (incoming) => {
      res = incoming;
      const chunks: Buffer[] = [];
      incoming.on("data", (chunk: Buffer) => chunks.push(chunk));
      incoming.on("error", fail);
      incoming.on("close", () => {
        if (!incoming.complete) {
          fail(new Error("connection closed before the response completed"));
        }
      });
      incoming.on("end", () => {
        const encoding = String(incoming.headers["content-encoding"] ?? "")
          .trim()
          .toLowerCase();
        decodeBody(Buffer.concat(chunks), encoding).then(
          (decoded) =>
            settle(() =>
              resolve({
                status: incoming.statusCode ?? 0,
                headers: toHeaders(incoming.headers),
                body: decoded.toString("utf8"),
              }),
            ),
          (err: Error) =>
            fail(
              new Error(
                `could not decode the ${encoding} response body: ${err.message}`,
              ),
            ),
        );
      });
    });
    req.end(request.body);
  });
}

/**
 * The server dropped a pooled socket, so the others of the same age are
 * probably dead too: close them rather than let the next calls find out.
 */
function dropIdleSockets(agent: HttpAgent): void {
  for (const sockets of Object.values(agent.freeSockets)) {
    for (const socket of sockets ?? []) socket.destroy();
  }
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/**
 * The next hop of a redirect, `null` when the response is final. Only a
 * same-host hop is followed (an http → https upgrade included): the request
 * carries the API key, and a redirect elsewhere would hand it to another
 * host or send it in clear. POST only follows 307/308, which keep the method
 * and the body.
 */
function redirectTarget(
  request: TransportRequest,
  response: TransportResponse,
): TransportRequest | null {
  if (!REDIRECT_STATUSES.has(response.status)) return null;
  const location = response.headers.get("location");
  if (!location) return null;
  if (
    request.method === "POST" &&
    response.status !== 307 &&
    response.status !== 308
  ) {
    return null;
  }
  const from = new URL(request.url);
  const to = new URL(location, from);
  const sameOrigin = to.origin === from.origin;
  const upgrade =
    to.hostname === from.hostname &&
    from.protocol === "http:" &&
    to.protocol === "https:";
  if (!sameOrigin && !upgrade) {
    throw new Error(
      `the API redirected to ${to.origin}, which is not followed; point the base URL at the final address`,
    );
  }
  return { ...request, url: to.toString() };
}

/**
 * The default wire: keep-alive pool, compressed bodies, one retry of an
 * idempotent GET that hit a dead pooled socket, bounded same-host redirects.
 * Never retried: a timeout or a cancellation (the signal is aborted), an HTTP
 * status, a POST — a POST that reached the handler is billed, and a second
 * one would be billed again.
 */
export function createNodeTransport(
  options: NodeTransportOptions = {},
): HttpTransport {
  const agents = options.agents ?? SHARED_AGENTS;
  const maxRedirects = options.maxRedirects ?? MAX_REDIRECTS;

  async function sendWithRetry(
    request: TransportRequest,
  ): Promise<TransportResponse> {
    try {
      return await sendOnce(request, agents);
    } catch (e) {
      const retryable =
        request.method === "GET" &&
        !request.signal.aborted &&
        (e as Record<symbol, unknown> | null)?.[RETRYABLE] === true;
      if (!retryable) throw e;
      dropIdleSockets(
        new URL(request.url).protocol === "https:" ? agents.https : agents.http,
      );
      return sendOnce(request, agents);
    }
  }

  return (request) => followRedirects(sendWithRetry, request, maxRedirects);
}

/** `send`, then each hop `redirectTarget` allows, at most `maxRedirects`. */
async function followRedirects(
  send: HttpTransport,
  request: TransportRequest,
  maxRedirects: number,
): Promise<TransportResponse> {
  let current = request;
  for (let hop = 0; ; hop++) {
    const response = await send(current);
    const next = redirectTarget(current, response);
    if (!next) return response;
    if (hop >= maxRedirects) {
      throw new Error(`more than ${maxRedirects} redirects`);
    }
    current = next;
  }
}

/**
 * Adapts a fetch-shaped function to the transport seam: the env-proxy
 * fallback on a Node whose agents cannot proxy, and tests. fetch does not
 * follow redirects itself (`redirect: "manual"`); the hops go through
 * `redirectTarget`, as on the node transport. undici's own `follow` strips
 * only `Authorization` and `Cookie` on a cross-origin hop, so the
 * `X-API-KEY` went to whichever host a `Location` named.
 */
export function fetchTransport(
  fetchImpl: typeof fetch,
  maxRedirects: number = MAX_REDIRECTS,
): HttpTransport {
  const send: HttpTransport = async (request) => {
    const res = await fetchImpl(request.url, {
      method: request.method,
      headers: request.headers,
      body: request.body,
      signal: request.signal,
      redirect: "manual",
    });
    return { status: res.status, headers: res.headers, body: await res.text() };
  };
  return (request) => followRedirects(send, request, maxRedirects);
}

// ─── Client ─────────────────────────────────────────────────────────────────

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
  /** Injectable wire; defaults to the keep-alive node transport. */
  transport?: HttpTransport;
  /** Injectable for tests: a fetch-shaped wire, used when no transport is given. */
  fetchImpl?: typeof fetch;
}

/**
 * Path the pre-warm request opens the connection with. `/health` is public
 * and unmetered on both hosts: the Next.js route (`app/api/health`) runs no
 * auth or rate-limit middleware, and Rust serves it from `public_routes` with
 * a 5 s cache. A GET, not a HEAD: a bodiless HEAD answer without
 * Content-Length leaves Node unable to reuse the socket, which would throw
 * the warmed connection away; the body is ~150 bytes.
 */
export const PREWARM_PATH = "/health";
export const PREWARM_TIMEOUT_MS = 5_000;
/**
 * Its own product token, not `ismalicious-mcp/…`: Rust counts every request
 * with the MCP User-Agent in `mcp_tool_*`, and a connection warm-up is not a
 * tool call.
 */
export const PREWARM_USER_AGENT = `ismalicious-mcp-prewarm/${SERVER_VERSION}`;

export interface ConfigurableHttpClient extends HttpClient {
  setApiKeyHeader(value: string | null): void;
  withTool(tool: string): HttpClient;
  /**
   * Open the connection to the API host ahead of the first tool call with
   * one `GET /health`. Fire and forget: never throws, never rejects, carries
   * no key and no tool name.
   */
  prewarm(): void;
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
  const transport =
    config.transport ??
    (config.fetchImpl
      ? fetchTransport(config.fetchImpl)
      : PROXY_MODE.kind === "fetch"
        ? fetchTransport(fetch)
        : createNodeTransport());
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
      const res = await transport({
        url: `${base}${path}`,
        method: init.method,
        headers: headersFor(tool, init.body !== undefined),
        body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
        signal: controller.signal,
      });
      const quota = parseQuotaHeaders(res.headers);
      config.onQuota?.(quota);
      let json: unknown = null;
      let invalidBody = false;
      if (res.body.trim().length > 0) {
        try {
          json = JSON.parse(res.body);
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

  function prewarm(): void {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), PREWARM_TIMEOUT_MS);
      // A warm-up must never hold the process open on its own.
      timer.unref?.();
      transport({
        url: `${base}${PREWARM_PATH}`,
        method: "GET",
        headers: {
          Accept: "application/json",
          "User-Agent": PREWARM_USER_AGENT,
        },
        signal: controller.signal,
      })
        .catch(() => undefined)
        .finally(() => clearTimeout(timer));
    } catch {
      // Fire and forget: a malformed base URL surfaces on the first real call.
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
    prewarm,
  };
  return client;
}
