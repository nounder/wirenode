export type Result<T, E = Error> =
  | { ok: true; value: T }
  | { ok: false; error: E }

export function ok<T>(value: T): Result<T, never> {
  return { ok: true, value }
}

export function error<E = Error>(error: E): Result<never, E> {
  return { ok: false, error }
}

export function getOrThrow<T, E>(result: Result<T, E>): T {
  if (result.ok) return result.value
  throw result.error instanceof Error ? result.error : new Error(String(result.error))
}

export function getOrNull<T, E>(result: Result<T, E>): T | null {
  return result.ok ? result.value : null
}
