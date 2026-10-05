/**
 * The closed set of tools. Order is the order `tools/list` returns; the two
 * gate tools stay first so v0.1 clients that index by position keep working,
 * and the v0.3 tools sit after the v0.2 ones for the same reason (then
 * `check_password_exposure`, added in 0.4.0, and `scan_email`, added in 0.6.0;
 * `bootstrap_key` stays last).
 * `MCP_TOOLS` mirrors `apps/rust-api/src/infra/client.rs` and
 * `apps/web/lib/growth-metrics-constants.ts`, in this order. A Rust test reads
 * the first `name: "…"` of every tool file in this directory (so helpers
 * belong elsewhere); `__tests__/tools-parity.test.ts` checks all three lists
 * from this package's suite.
 */

import { bootstrapKey } from "./bootstrap-key.js";
import { checkIndicator } from "./check-indicator.js";
import { checkIndicators } from "./check-indicators.js";
import { checkPasswordExposure } from "./check-password-exposure.js";
import { checkUrl } from "./check-url.js";
import { getCve } from "./get-cve.js";
import { recentCves } from "./recent-cves.js";
import { scanBeforeUse } from "./scan-before-use.js";
import { scanEmail } from "./scan-email.js";
import { searchIndicators } from "./search-indicators.js";
import type { ToolDefinition } from "./types.js";

export const TOOLS: readonly ToolDefinition[] = [
  scanBeforeUse,
  checkUrl,
  checkIndicator,
  getCve,
  recentCves,
  searchIndicators,
  checkIndicators,
  checkPasswordExposure,
  scanEmail,
  bootstrapKey,
];

export const MCP_TOOLS = TOOLS.map((t) => t.name) as readonly string[];

export type { ToolContext, ToolDefinition, ToolResult } from "./types.js";
