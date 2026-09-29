import type { ToolErrorEnvelope } from "../errors.js";
import type { HttpClient } from "../http.js";

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
  /** Per-tool timeout, after the `ISMALICIOUS_TIMEOUT_MS` override. */
  timeoutMs: number;
}

export type ToolResult =
  { ok: true; value: unknown } | { ok: false; error: ToolErrorEnvelope };

export interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: JsonSchema;
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
  call(args: Record<string, unknown>, ctx: ToolContext): Promise<ToolResult>;
}

export function ok(value: unknown): ToolResult {
  return { ok: true, value };
}

export function fail(error: ToolErrorEnvelope): ToolResult {
  return { ok: false, error };
}
