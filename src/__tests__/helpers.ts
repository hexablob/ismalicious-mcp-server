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
