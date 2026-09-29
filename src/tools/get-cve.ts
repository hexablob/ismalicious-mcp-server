import { invalidParams } from "../errors.js";
import {
  CVE_NOT_FOUND_HINT,
  normalizeCveId,
  projectCve,
} from "../projections/cve.js";
import { fetchJson } from "./request.js";
import { fail, ok, type ToolDefinition } from "./types.js";

export const getCve: ToolDefinition = {
  name: "get_cve",
  description:
    "One CVE by id: description, CVSS, EPSS probability, CISA KEV status and due date, exploitation evidence (SSVC, weaponized, zero-day, Exploit-DB, Nuclei), publication dates and references. This is the only CVE lookup path; do not guess other routes. Costs one request of the monthly quota.",
  inputSchema: {
    type: "object",
    properties: {
      id: {
        type: "string",
        description: "CVE identifier, e.g. CVE-2021-44228. Case-insensitive.",
        pattern: "^[Cc][Vv][Ee]-\\d{4}-\\d{4,}$",
      },
    },
    required: ["id"],
    additionalProperties: false,
  },
  requiresKey: true,
  timeoutMs: 10_000,
  async call(args, ctx) {
    const id = normalizeCveId(args.id);
    if (!id) {
      return fail(
        invalidParams(
          "id must look like CVE-YYYY-NNNNN (at least four digits after the year).",
        ),
      );
    }
    const fetched = await fetchJson(
      ctx,
      () =>
        ctx.http.get(`/cve?id=${encodeURIComponent(id)}`, {
          signal: ctx.signal,
          timeoutMs: ctx.timeoutMs,
        }),
      { notFoundHint: CVE_NOT_FOUND_HINT },
    );
    if (!fetched.ok) return fail(fetched.error);
    return ok(projectCve(fetched.json, id));
  },
};
