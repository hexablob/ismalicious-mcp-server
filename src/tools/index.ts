/**
 * The closed set of tools. Order is the order `tools/list` returns; the two
 * gate tools stay first so v0.1 clients that index by position keep working,
 * and the v0.3 tools sit after the v0.2 ones for the same reason (then
 * `check_password_exposure`, added in 0.4.0).
 * `MCP_TOOLS` mirrors `apps/rust-api/src/infra/client.rs` (lot 2) — a parity
 * test on the Rust side reads this file.
 */

import { bootstrapKey } from "./bootstrap-key.js";
import { checkIndicator } from "./check-indicator.js";
import { checkIndicators } from "./check-indicators.js";
import { checkPasswordExposure } from "./check-password-exposure.js";
import { checkUrl } from "./check-url.js";
import { getCve } from "./get-cve.js";
import { recentCves } from "./recent-cves.js";
import { scanBeforeUse } from "./scan-before-use.js";
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
  bootstrapKey,
];

export const MCP_TOOLS = TOOLS.map((t) => t.name) as readonly string[];

export type { ToolContext, ToolDefinition, ToolResult } from "./types.js";
