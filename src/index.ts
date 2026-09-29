/**
 * stdio transport for the isMalicious MCP server.
 *
 * Reads newline-delimited JSON-RPC requests on stdin, writes responses on
 * stdout, and logs to stderr (stdout is the protocol channel and must stay
 * clean). Configuration comes from the environment:
 *
 *   ISMALICIOUS_API_KEY     — your organization API key
 *   ISMALICIOUS_API_SECRET  — your organization API secret
 *   ISMALICIOUS_API_BASE    — optional, defaults to https://ismalicious.com/api
 *   ISMALICIOUS_TIMEOUT_MS  — optional, replaces every tool's timeout
 *
 * Without a key pair the server still starts, in a reduced mode where only
 * `bootstrap_key` is offered; it mints a free key from an email address and
 * uses it for the rest of the session. Keys: https://ismalicious.com/app/account.
 */

import { createInterface } from "node:readline";
import { createServer, type JsonRpcRequest } from "./server.js";

const LOG_PREFIX = "ismalicious-mcp";

function log(message: string): void {
  process.stderr.write(`${LOG_PREFIX}: ${message}\n`);
}

function resolveApiKeyHeader(): string | null {
  const key = process.env.ISMALICIOUS_API_KEY;
  const secret = process.env.ISMALICIOUS_API_SECRET;
  if (!key || !secret) {
    log(
      "no ISMALICIOUS_API_KEY / ISMALICIOUS_API_SECRET; starting in bootstrap mode " +
        "(only bootstrap_key is available). Keys: https://ismalicious.com/app/account",
    );
    return null;
  }
  return Buffer.from(`${key}:${secret}`).toString("base64");
}

function resolveTimeoutOverride(): number | undefined {
  const raw = process.env.ISMALICIOUS_TIMEOUT_MS;
  if (!raw) return undefined;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) {
    log(`ignoring ISMALICIOUS_TIMEOUT_MS=${raw} (not a positive number)`);
    return undefined;
  }
  return n;
}

function write(message: unknown): void {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

function main(): void {
  const baseUrl =
    process.env.ISMALICIOUS_API_BASE ?? "https://ismalicious.com/api";
  const server = createServer({
    baseUrl,
    apiKeyHeader: resolveApiKeyHeader(),
    timeoutOverrideMs: resolveTimeoutOverride(),
    notify: write,
  });

  const rl = createInterface({ input: process.stdin });
  rl.on("line", (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    let request: JsonRpcRequest;
    try {
      request = JSON.parse(trimmed) as JsonRpcRequest;
    } catch {
      log("dropped malformed line");
      return;
    }
    server
      .handle(request)
      .then((response) => {
        if (response) write(response);
      })
      .catch((e: unknown) => {
        log(`handler failed: ${e instanceof Error ? e.message : String(e)}`);
        if (request.id !== undefined && request.id !== null) {
          write({
            jsonrpc: "2.0",
            id: request.id,
            error: { code: -32603, message: "Internal error" },
          });
        }
      });
  });

  // The client closing our stdin is the shutdown signal in stdio transports.
  rl.on("close", () => process.exit(0));
  for (const signal of ["SIGTERM", "SIGINT"] as const) {
    process.on(signal, () => process.exit(0));
  }
}

main();
