/**
 * Which projection a `/check` body gets. The API's declared `type` decides
 * when it names an email address or a phone number; otherwise the local type
 * (`indicators.ts`) says whether the body can be read at all — an address
 * answered as a domain is not evaluated, whatever the body says.
 */

import type { IndicatorKind } from "../indicators.js";
import {
  projectCheckIndicator,
  type CheckIndicatorProjection,
} from "./check-indicator.js";
import {
  isContactType,
  projectContact,
  projectUnevaluated,
  type ContactProjection,
  type UnevaluatedProjection,
} from "./contact.js";
import { rec, str } from "./fields.js";

export type CheckResult =
  CheckIndicatorProjection | ContactProjection | UnevaluatedProjection;

export interface CheckResultOptions {
  /** The type `classifyIndicator` gave the indicator before the call. */
  localType: IndicatorKind;
  requestedEnrichment?: string;
  /** The input as given, before refanging. */
  input?: string;
}

export function projectCheckResult(
  indicator: string,
  raw: unknown,
  options: CheckResultOptions,
): CheckResult {
  const declared = str(rec(raw)?.type);
  const shared = {
    requestedEnrichment: options.requestedEnrichment,
    input: options.input,
  };
  if (isContactType(declared)) return projectContact(indicator, raw, shared);
  if (isContactType(options.localType)) {
    return projectUnevaluated(indicator, options.localType, raw, shared);
  }
  return projectCheckIndicator(indicator, raw, shared);
}
