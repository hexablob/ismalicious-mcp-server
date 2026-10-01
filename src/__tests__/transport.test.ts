/**
 * Tests for the node:http transport against a real local server: connection
 * reuse across idle gaps, compressed bodies, deadlines, cancellation, the one
 * retry of a GET on a dead pooled socket, redirects, the pre-warm and Node's
 * env-proxy mode.
 */
import { createServer as createHttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { brotliCompressSync, gzipSync } from "node:zlib";
import { afterEach, describe, expect, it } from "vitest";
import {
  createKeepAliveAgents,
  createNodeTransport,
  defaultHttpClient,
  fetchTransport,
  HttpCancelledError,
  HttpNetworkError,
  HttpTimeoutError,
  IDLE_SOCKET_TIMEOUT_MS,
  PREWARM_PATH,
  resolveProxyMode,
  type KeepAliveAgents,
  type ProxyEnv,
} from "../http.js";
import { SERVER_VERSION } from "../version.js";
import {
  sendJson,
  startLocalServer,
  until,
  type LocalServer,
} from "./helpers.js";

const cleanup: Array<() => Promise<void> | void> = [];

afterEach(async () => {
  while (cleanup.length) await cleanup.pop()?.();
});

async function serve(
  handler: Parameters<typeof startLocalServer>[0],
  options?: Parameters<typeof startLocalServer>[1],
): Promise<LocalServer> {
  const server = await startLocalServer(handler, options);
  cleanup.push(() => server.close());
  return server;
}

/** A private pool per test, so no socket leaks from one test into another. */
function pool(idleTimeoutMs?: number, proxyEnv?: ProxyEnv): KeepAliveAgents {
  const agents = createKeepAliveAgents(idleTimeoutMs, proxyEnv);
  cleanup.push(() => {
    agents.http.destroy();
    agents.https.destroy();
  });
  return agents;
}

function client(server: LocalServer, agents: KeepAliveAgents) {
  return defaultHttpClient({
    baseUrl: `${server.origin}/api`,
    apiKeyHeader: "k",
    transport: createNodeTransport({ agents }),
  });
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("keep-alive pool", () => {
  it("keeps idle sockets 30 s, lifo, at most 16 per origin", () => {
    const agents = pool();
    expect(IDLE_SOCKET_TIMEOUT_MS).toBe(30_000);
    expect(agents.https.options).toMatchObject({
      keepAlive: true,
      maxSockets: 16,
      maxFreeSockets: 8,
      scheduling: "lifo",
      timeout: 30_000,
    });
  });

  it("reuses one socket for calls spaced more than 4 s apart (undici's idle window)", async () => {
    const server = await serve((_req, res) => sendJson(res, { ok: true }));
    const http = client(server, pool());
    await http.get("/a");
    await sleep(4_500);
    await http.get("/b");
    expect(server.requests).toHaveLength(2);
    expect(server.requests[1].remotePort).toBe(server.requests[0].remotePort);
  }, 10_000);

  it("opens a new socket once the idle threshold has passed", async () => {
    const server = await serve((_req, res) => sendJson(res, { ok: true }));
    const http = client(server, pool(150));
    await http.get("/a");
    await sleep(50);
    await http.get("/b");
    await sleep(400);
    await http.get("/c");
    const [a, b, c] = server.requests.map((r) => r.remotePort);
    expect(b).toBe(a);
    expect(c).not.toBe(a);
  });

  it("does not cut a response that takes longer than the idle threshold", async () => {
    const server = await serve((_req, res) => {
      setTimeout(() => sendJson(res, { slow: true }), 300);
    });
    const http = client(server, pool(100));
    const res = await http.get("/slow", { timeoutMs: 5_000 });
    expect(res.json).toEqual({ slow: true });
  });
});

describe("compressed bodies", () => {
  it("asks for gzip and brotli", async () => {
    const server = await serve((_req, res) => sendJson(res, {}));
    await client(server, pool()).get("/x");
    expect(server.requests[0].headers["accept-encoding"]).toBe("gzip, br");
  });

  it.each([
    ["gzip", gzipSync],
    ["br", brotliCompressSync],
  ] as const)("decodes a %s body", async (encoding, compress) => {
    const body = { verdict: "malicious", pad: "x".repeat(2_000) };
    const server = await serve((_req, res) => {
      res.writeHead(200, {
        "Content-Type": "application/json",
        "Content-Encoding": encoding,
        "X-Monthly-Usage": "3",
        "X-Monthly-Limit": "1000",
      });
      res.end(compress(Buffer.from(JSON.stringify(body))));
    });
    const res = await client(server, pool()).get("/check");
    expect(res.json).toEqual(body);
    expect(res.invalidBody).toBe(false);
    expect(res.headers.monthly).toEqual({ usage: 3, limit: 1000 });
  });

  it("reports a corrupt compressed body as a network error", async () => {
    const server = await serve((_req, res) => {
      res.writeHead(200, { "Content-Encoding": "gzip" });
      res.end("not gzip at all");
    });
    await expect(client(server, pool()).get("/check")).rejects.toBeInstanceOf(
      HttpNetworkError,
    );
  });
});

describe("deadlines and cancellation", () => {
  it("aborts with HttpTimeoutError and does not retry", async () => {
    const server = await serve(() => {
      // never answers
    });
    const http = client(server, pool());
    await expect(http.get("/slow", { timeoutMs: 150 })).rejects.toBeInstanceOf(
      HttpTimeoutError,
    );
    await sleep(100);
    expect(server.requests).toHaveLength(1);
  });

  it("aborts with HttpCancelledError when the caller cancels", async () => {
    const server = await serve(() => {
      // never answers
    });
    const controller = new AbortController();
    const pending = client(server, pool()).get("/slow", {
      signal: controller.signal,
      timeoutMs: 60_000,
    });
    await until(() => server.requests.length === 1);
    controller.abort("cancelled");
    await expect(pending).rejects.toBeInstanceOf(HttpCancelledError);
  });

  it("wraps a refused connection in HttpNetworkError", async () => {
    const server = await serve((_req, res) => sendJson(res, {}));
    const origin = server.origin;
    await server.close();
    const http = defaultHttpClient({
      baseUrl: `${origin}/api`,
      apiKeyHeader: "k",
      transport: createNodeTransport({ agents: pool() }),
    });
    await expect(http.get("/x")).rejects.toBeInstanceOf(HttpNetworkError);
  });
});

describe("one retry on a dead pooled socket", () => {
  /** The second request, on the reused socket, dies before any byte back. */
  const resetSecond = (
    _req: unknown,
    res: import("node:http").ServerResponse,
    _seen: unknown,
    index: number,
  ) => {
    if (index === 2) {
      res.socket?.destroy();
      return;
    }
    sendJson(res, { n: index });
  };

  it("retries an idempotent GET once, on a new socket", async () => {
    const server = await serve(resetSecond);
    const http = client(server, pool());
    await http.get("/a");
    const res = await http.get("/b");
    expect(res.json).toEqual({ n: 3 });
    expect(server.requests.map((r) => r.path)).toEqual([
      "/api/a",
      "/api/b",
      "/api/b",
    ]);
    expect(server.requests[1].remotePort).toBe(server.requests[0].remotePort);
    expect(server.requests[2].remotePort).not.toBe(
      server.requests[0].remotePort,
    );
  });

  it("never retries a POST: it may have been billed", async () => {
    const server = await serve(resetSecond);
    const http = client(server, pool());
    await http.post("/bulk/check", { entities: ["a"] });
    await expect(
      http.post("/bulk/check", { entities: ["b"] }),
    ).rejects.toBeInstanceOf(HttpNetworkError);
    await sleep(50);
    expect(server.requests).toHaveLength(2);
  });

  it("does not retry a reset on a fresh socket", async () => {
    const server = await serve((_req, res) => {
      res.socket?.destroy();
    });
    await expect(client(server, pool()).get("/a")).rejects.toBeInstanceOf(
      HttpNetworkError,
    );
    expect(server.requests).toHaveLength(1);
  });

  it("does not retry an HTTP error status", async () => {
    const server = await serve((_req, res) => sendJson(res, {}, 503));
    const res = await client(server, pool()).get("/a");
    expect(res.status).toBe(503);
    expect(server.requests).toHaveLength(1);
  });
});

describe("redirects", () => {
  it("follows a same-origin redirect of a GET, keeping the headers", async () => {
    const server = await serve((req, res) => {
      if (req.url === "/api/old") {
        res.writeHead(301, { Location: "/api/new" });
        res.end();
        return;
      }
      sendJson(res, { moved: true });
    });
    const res = await client(server, pool()).get("/old");
    expect(res.json).toEqual({ moved: true });
    expect(server.requests[1].headers["x-api-key"]).toBe("k");
  });

  it("refuses to follow a redirect to another host with the key", async () => {
    const server = await serve((_req, res) => {
      res.writeHead(302, { Location: "https://elsewhere.example/api/x" });
      res.end();
    });
    await expect(client(server, pool()).get("/x")).rejects.toThrow(
      /elsewhere\.example/,
    );
    expect(server.requests).toHaveLength(1);
  });

  it("stops after a bounded number of hops", async () => {
    const server = await serve((_req, res) => {
      res.writeHead(302, { Location: "/api/loop" });
      res.end();
    });
    await expect(client(server, pool()).get("/loop")).rejects.toThrow(
      /redirects/,
    );
    expect(server.requests.length).toBeLessThanOrEqual(4);
  });

  /** The wire an older Node in env-proxy mode falls back to. */
  function viaFetch(server: LocalServer) {
    return defaultHttpClient({
      baseUrl: `${server.origin}/api`,
      apiKeyHeader: "SECRET-KEY",
      transport: fetchTransport(fetch),
    });
  }

  it("fetch fallback: never follows a redirect to another origin with the key", async () => {
    // undici's `follow` stripped Authorization and Cookie only: X-API-KEY
    // reached the other origin.
    const other = await serve((_req, res) => sendJson(res, { stolen: true }));
    const server = await serve((_req, res) => {
      res.writeHead(302, { Location: `${other.origin}/api/x` });
      res.end();
    });
    await expect(viaFetch(server).get("/x")).rejects.toThrow(/is not followed/);
    expect(server.requests).toHaveLength(1);
    expect(other.requests).toHaveLength(0);
  });

  it("fetch fallback: follows a same-origin redirect, keeping the key, and stops after a bounded number of hops", async () => {
    const server = await serve((req, res) => {
      if (req.url === "/api/old") {
        res.writeHead(307, { Location: "/api/new" });
        res.end();
        return;
      }
      if (req.url === "/api/loop") {
        res.writeHead(302, { Location: "/api/loop" });
        res.end();
        return;
      }
      sendJson(res, { moved: true });
    });
    const res = await viaFetch(server).get("/old");
    expect(res.json).toEqual({ moved: true });
    expect(server.requests[1].headers["x-api-key"]).toBe("SECRET-KEY");
    await expect(viaFetch(server).get("/loop")).rejects.toThrow(/redirects/);
    expect(server.requests.length).toBeLessThanOrEqual(2 + 4);
  });
});

describe("prewarm", () => {
  it("sends one unauthenticated GET to the health route, without a tool name", async () => {
    const server = await serve((_req, res) => sendJson(res, {}));
    const http = client(server, pool());
    http.prewarm();
    await until(() => server.requests.length === 1);
    const [seen] = server.requests;
    expect(seen.method).toBe("GET");
    expect(seen.path).toBe(`/api${PREWARM_PATH}`);
    expect(seen.headers["x-api-key"]).toBeUndefined();
    expect(seen.headers["x-ismalicious-tool"]).toBeUndefined();
    // Not `ismalicious-mcp/…`: Rust counts that prefix as a tool call.
    expect(seen.headers["user-agent"]).toBe(
      `ismalicious-mcp-prewarm/${SERVER_VERSION}`,
    );
  });

  it("warms the socket the next call reuses", async () => {
    const server = await serve((_req, res) => sendJson(res, {}));
    const http = client(server, pool());
    http.prewarm();
    await until(() => server.requests.length === 1);
    await sleep(20);
    await http.get("/check");
    expect(server.requests[1].remotePort).toBe(server.requests[0].remotePort);
  });

  it("swallows every failure", async () => {
    const server = await serve((_req, res) => sendJson(res, {}));
    const origin = server.origin;
    await server.close();
    const http = defaultHttpClient({
      baseUrl: `${origin}/api`,
      apiKeyHeader: "k",
      transport: createNodeTransport({ agents: pool() }),
    });
    expect(() => http.prewarm()).not.toThrow();
    const broken = defaultHttpClient({
      baseUrl: "not a url",
      apiKeyHeader: "k",
    });
    expect(() => broken.prewarm()).not.toThrow();
    await sleep(100);
  });
});

describe("env-proxy mode", () => {
  const NODE_PROXY_ENV = {
    HTTPS_PROXY: "http://proxy.internal:3128",
    NO_PROXY: "localhost",
  };

  it("follows Node's own global agent when it carries proxy variables", () => {
    expect(
      resolveProxyMode({
        env: {},
        execArgv: [],
        globalAgentProxyEnv: NODE_PROXY_ENV,
      }),
    ).toEqual({ kind: "agent", env: NODE_PROXY_ENV });
  });

  it("connects directly when the mode is off, even with HTTPS_PROXY set, as fetch did", () => {
    expect(
      resolveProxyMode({
        env: { HTTPS_PROXY: "http://proxy.internal:3128" },
        execArgv: [],
        globalAgentProxyEnv: undefined,
      }),
    ).toEqual({ kind: "direct" });
  });

  it("falls back to fetch when the mode is on but this Node's agents cannot proxy", () => {
    const env = { HTTPS_PROXY: "http://proxy.internal:3128" };
    for (const inputs of [
      { env: { ...env, NODE_USE_ENV_PROXY: "1" }, execArgv: [] },
      { env, execArgv: ["--use-env-proxy"] },
      {
        env: {
          ...env,
          NODE_OPTIONS: "--max-old-space-size=512 --use-env-proxy",
        },
        execArgv: [],
      },
    ]) {
      expect(
        resolveProxyMode({ ...inputs, globalAgentProxyEnv: undefined }),
      ).toEqual({ kind: "fetch" });
    }
    // The mode on without any proxy variable changes nothing.
    expect(
      resolveProxyMode({
        env: { NODE_USE_ENV_PROXY: "1" },
        execArgv: [],
        globalAgentProxyEnv: undefined,
      }),
    ).toEqual({ kind: "direct" });
  });

  // `proxyEnv` on http.Agent: Node 22.21+ and 24.5+. Older Node ignores it.
  const [major, minor] = process.versions.node.split(".").map(Number);
  const agentsCanProxy =
    major > 24 || (major === 24 && minor >= 5) || (major === 22 && minor >= 21);

  /** A forward proxy that answers every request itself and refuses CONNECT. */
  async function startProxy() {
    const seen: string[] = [];
    const proxy = createHttpServer((req, res) => {
      seen.push(
        `${req.method} ${req.url} tool=${req.headers["x-ismalicious-tool"] ?? ""}`,
      );
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ via: "proxy" }));
    });
    proxy.on("connect", (req, socket) => {
      seen.push(`CONNECT ${req.url}`);
      socket.end("HTTP/1.1 403 Forbidden\r\n\r\n");
    });
    await new Promise<void>((r) => proxy.listen(0, "127.0.0.1", () => r()));
    const { port } = proxy.address() as AddressInfo;
    cleanup.push(
      () =>
        new Promise<void>((r) => {
          proxy.closeAllConnections();
          proxy.close(() => r());
        }),
    );
    return { url: `http://127.0.0.1:${port}`, seen };
  }

  it.skipIf(!agentsCanProxy)(
    "sends a tool call through the proxy for a host only the proxy can resolve",
    async () => {
      const proxy = await startProxy();
      const http = defaultHttpClient({
        baseUrl: "http://api.invalid-test-host.example/api",
        apiKeyHeader: "k",
        transport: createNodeTransport({
          agents: pool(undefined, { HTTP_PROXY: proxy.url }),
        }),
      }).withTool("check_indicator");
      const res = await http.get("/check?query=1.2.3.4");
      expect(res.json).toEqual({ via: "proxy" });
      expect(proxy.seen).toEqual([
        "GET http://api.invalid-test-host.example/api/check?query=1.2.3.4 tool=check_indicator",
      ]);
    },
  );

  it.skipIf(!agentsCanProxy)("tunnels https through CONNECT", async () => {
    const proxy = await startProxy();
    const http = defaultHttpClient({
      baseUrl: "https://api.invalid-test-host.example/api",
      apiKeyHeader: "k",
      transport: createNodeTransport({
        agents: pool(undefined, { HTTPS_PROXY: proxy.url }),
      }),
    });
    await expect(http.get("/health")).rejects.toBeInstanceOf(HttpNetworkError);
    expect(proxy.seen).toEqual(["CONNECT api.invalid-test-host.example:443"]);
  });
});
