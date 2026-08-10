import type { Context } from "hono";
import type { AppVariables, Env } from "./env";

export function apiError(
  context: Context<{ Bindings: Env; Variables: AppVariables }>,
  status: 400 | 401 | 403 | 404 | 409 | 413 | 429 | 500 | 503,
  code: string,
  message: string,
  details?: unknown,
) {
  return context.json(
    {
      code,
      message,
      traceId: context.get("traceId"),
      ...(details === undefined ? {} : { details }),
    },
    status,
  );
}

export function nowIso(): string {
  return new Date().toISOString();
}

export function jsonBody(request: Request): Promise<unknown> {
  const contentType = request.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().includes("application/json"))
    throw new Error("Expected application/json");
  return request.json();
}
