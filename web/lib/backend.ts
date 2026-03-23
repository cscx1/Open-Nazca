/**
 * Backend proxy helpers.
 * In production these forward to the FastAPI service.
 * The BACKEND_URL env var (default: http://localhost:8000) points at the Python server.
 */

export const BACKEND_URL = process.env.BACKEND_URL ?? 'http://localhost:8000'

export async function proxyToBackend(
  path: string,
  init?: RequestInit
): Promise<Response> {
  return fetch(`${BACKEND_URL}${path}`, init)
}

/** Sanitized error message safe to return to the client. */
export function safeError(message: string): Response {
  return Response.json({ error: message }, { status: 500 })
}

export function notFound(message = 'Not found'): Response {
  return Response.json({ error: message }, { status: 404 })
}

export function badRequest(message: string): Response {
  return Response.json({ error: message }, { status: 400 })
}
