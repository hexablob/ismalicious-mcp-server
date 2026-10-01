import {
  createServer as createHttpServer,
  type IncomingHttpHeaders,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import type { AddressInfo } from "node:net";
import { vi } from "vitest";
import type { HttpClient, HttpResponse } from "../http.js";

export function response(
  status: number,
  json: unknown,
  headers: HttpResponse["headers"] = {},
  invalidBody = false,
): HttpResponse {
  return { status, json, invalidBody, headers };
}

export function stubHttp(overrides: Partial<HttpClient> = {}): HttpClient {
  return {
    post: vi.fn(async () => response(200, { verdict: "allow" })),
    get: vi.fn(async () => response(200, { verdict: "allow" })),
    ...overrides,
  };
}

export function text(res: { result?: unknown } | null): string {
  const r = res?.result as { content: { text: string }[] };
  return r.content[0].text;
}

export function parsed<T = Record<string, unknown>>(
  res: { result?: unknown } | null,
): T {
  return JSON.parse(text(res)) as T;
}

export function isError(res: { result?: unknown } | null): boolean {
  return (res?.result as { isError: boolean }).isError;
}

export interface SeenRequest {
  method: string;
  path: string;
  headers: IncomingHttpHeaders;
  body: string;
  /** Client port: the same value on two requests means the same socket. */
  remotePort: number | undefined;
}

export interface LocalServer {
  /** `http://127.0.0.1:<port>`, no trailing slash. */
  origin: string;
  requests: SeenRequest[];
  close(): Promise<void>;
}

/**
 * A real node:http server on a free port, recording every request, for the
 * tests that must exercise the actual wire (keep-alive, compression, the
 * headers a tool call carries) rather than a stubbed client.
 */
export async function startLocalServer(
  handler: (
    req: IncomingMessage,
    res: ServerResponse,
    seen: SeenRequest,
    index: number,
  ) => void,
  options: { keepAliveTimeoutMs?: number } = {},
): Promise<LocalServer> {
  const requests: SeenRequest[] = [];
  const server = createHttpServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const seen: SeenRequest = {
        method: req.method ?? "",
        path: req.url ?? "",
        headers: req.headers,
        body: Buffer.concat(chunks).toString("utf8"),
        remotePort: req.socket.remotePort,
      };
      requests.push(seen);
      handler(req, res, seen, requests.length);
    });
  });
  server.keepAliveTimeout = options.keepAliveTimeoutMs ?? 60_000;
  await new Promise<void>((resolve) =>
    server.listen(0, "127.0.0.1", () => resolve()),
  );
  const { port } = server.address() as AddressInfo;
  return {
    origin: `http://127.0.0.1:${port}`,
    requests,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

export function sendJson(
  res: ServerResponse,
  body: unknown,
  status = 200,
  headers: Record<string, string> = {},
): void {
  res.writeHead(status, { "Content-Type": "application/json", ...headers });
  res.end(JSON.stringify(body));
}

/** Resolve once `predicate` holds, polling; fail after `ms`. */
export async function until(predicate: () => boolean, ms = 2000) {
  const started = Date.now();
  while (!predicate()) {
    if (Date.now() - started > ms) throw new Error("condition not met in time");
    await new Promise((r) => setTimeout(r, 10));
  }
}

export function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}
