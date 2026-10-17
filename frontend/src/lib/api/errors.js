// Error types for the API layer.

/** A non-2xx HTTP response (or a well-formed error body). */
export class ApiError extends Error {
  constructor(message, status, body) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.body = body
  }
}

/** A network-layer failure: timeout, cancellation, or unreachable backend. */
export class NetworkError extends Error {
  constructor(message, cause) {
    super(message)
    this.name = 'NetworkError'
    this.cause = cause
  }
}

/** True when the failure means the API could not be reached or answered. */
export function isUnavailableError(error) {
  if (!error) return false
  if (error instanceof NetworkError) return error.message !== 'Request cancelled'
  if (error instanceof ApiError) return error.status >= 500 || error.status === 429
  return false
}

/** True when the caller deliberately cancelled the request. */
export function isCancelledError(error) {
  return error instanceof NetworkError && error.message === 'Request cancelled'
}

/** Short, non-leaking, user-facing description of a failure. */
export function describeApiError(error) {
  if (!error) return 'Unknown error'
  if (error instanceof NetworkError) {
    if (error.message === 'Request cancelled') return 'Request cancelled'
    if (error.message === 'Request timed out') return 'The API did not respond in time'
    return 'The API is unreachable'
  }
  if (error instanceof ApiError) {
    if (error.status === 502 || error.status === 503 || error.status === 504) {
      return `The API is unavailable (HTTP ${error.status})`
    }
    if (error.status === 401 || error.status === 403) return 'Not authorised to read this resource'
    if (error.status === 404) return 'Resource not found'
    if (error.status === 429) return 'Too many requests — try again shortly'
    if (error.status === 413) return 'Request too large'
    return error.message || `Request failed (HTTP ${error.status})`
  }
  return error.message || 'Request failed'
}
