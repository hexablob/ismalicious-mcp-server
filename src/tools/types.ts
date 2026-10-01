import type { ToolErrorEnvelope } from "../errors.js";
import type { HttpClient } from "../http.js";
import type { ListCap } from "../projections/cap.js";

export interface JsonSchema {
  type: "object";
  properties: Record<string, unknown>;
  required?: string[];
  additionalProperties?: boolean;
}

export interface ToolContext {
  http: HttpClient;
  signal: AbortSignal;
  keyConfigured: boolean;
  /** Called by `bootstrap_key` once a pair has been minted. */
  setApiKey(pair: { apiKey: string; apiSecret: string }): void;
  now(): Date;
  /**
   * Per-tool timeout, after the overrides: `ISMALICIOUS_TIMEOUT_<TOOL>_MS`,
   * then `ISMALICIOUS_TIMEOUT_MS`, then the tool's own default.
   */
  timeoutMs: number;
}

export type ToolResult =
  { ok: true; value: unknown } | { ok: false; error: ToolErrorEnvelope };

/**
 * MCP tool annotations (spec 2025-03-26+). Hints for the client's approval
 * UI, not guarantees; `destructiveHint` is only read when `readOnlyHint` is
 * false, and defaults to true there, so a write tool states it.
 */
export interface ToolAnnotations {
  readOnlyHint: boolean;
  destructiveHint?: boolean;
  idempotentHint: boolean;
  openWorldHint: boolean;
}

/** Every lookup tool: reads third-party-fed intelligence, changes nothing. */
export const READ_ONLY_TOOL: ToolAnnotations = {
  readOnlyHint: true,
  idempotentHint: true,
  openWorldHint: true,
};

/**
 * Which deployment serves the tool's route. `api` routes exist on both
 * `https://ismalicious.com/api` and the Rust host; `web` routes exist only in
 * the Next.js app (`/keys/instant`), so they follow `ISMALICIOUS_WEB_BASE`.
 */
export type ToolSurface = "api" | "web";

export interface ToolDefinition {
  name: string;
  /** Human-readable name for client UIs (`tools/list` `title`). */
  title: string;
  description: string;
  inputSchema: JsonSchema;
  annotations: ToolAnnotations;
  /** Defaults to `api`. */
  surface?: ToolSurface;
  /** Hidden from `tools/list` while no key is configured. */
  requiresKey: boolean;
  /** Only listed while no key is configured. */
  bootstrapOnly?: boolean;
  timeoutMs: number;
  /**
   * Result size ceiling handed to `capResult`; defaults to
   * `MAX_RESULT_BYTES` (4 KB). Only the list-shaped tools raise it.
   */
  maxResultBytes?: number;
  /** List-shaped results: drop tail rows to fit instead of clipping arrays. */
  listCap?: ListCap;
  /**
   * How long a successful result may be replayed to an identical call, in
   * seconds. Absent: never cached nor shared between concurrent calls (a
   * scan, a key mint).
   */
  cacheTtlSec?: number;
  /**
   * The arguments as the call will actually use them (trimmed, defaults
   * applied), for the cache key; defaults to the raw arguments. Must be
   * derived by the same code as `call`, or two calls that differ would share
   * an answer.
   */
  cacheArgs?(args: Record<string, unknown>): unknown;
  /**
   * A result shared under that key, as this call should see it: re-attaches
   * what the call's own arguments add but the key leaves out (the input as
   * typed, before refanging). Applied to every cached or shared result
   * handed to a caller; must be idempotent.
   */
  rebind?(value: unknown, args: Record<string, unknown>): unknown;
  call(args: Record<string, unknown>, ctx: ToolContext): Promise<ToolResult>;
}

export function ok(value: unknown): ToolResult {
  return { ok: true, value };
}

export function fail(error: ToolErrorEnvelope): ToolResult {
  return { ok: false, error };
}
