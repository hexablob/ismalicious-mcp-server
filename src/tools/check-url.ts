/** `check_url`: unchanged since v0.1 (see scan-before-use.ts). */

import { invalidParams } from "../errors.js";
import { fetchJson } from "./request.js";
import { fail, ok, type ToolDefinition } from "./types.js";

export const checkUrl: ToolDefinition = {
  name: "check_url",
  description:
    "Check a single URL, domain, or IP against threat intelligence before fetching it. Returns block | warn | allow. Use as a pre-fetch gate; use check_indicator when you need the full reputation picture (score, sources, timeline).",
  inputSchema: {
    type: "object",
    properties: {
      url: { type: "string", description: "The URL/domain/IP to check." },
    },
    required: ["url"],
  },
  requiresKey: true,
  timeoutMs: 15_000,
  async call(args, ctx) {
    if (typeof args.url !== "string" || args.url.length === 0) {
      return fail(invalidParams("url is required"));
    }
    const fetched = await fetchJson(ctx, () =>
      ctx.http.get(`/gate/url?u=${encodeURIComponent(args.url as string)}`, {
        signal: ctx.signal,
        timeoutMs: ctx.timeoutMs,
      }),
    );
    return fetched.ok ? ok(fetched.json) : fail(fetched.error);
  },
};
