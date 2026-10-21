// Central HTTP client. All network access goes through here so timeout,
// cancellation, retry, and error handling live in exactly one place.

import { API_CONFIG, getRuntimeToken } from './config'
import { ApiError, NetworkError } from './errors'

/* Resolve a path against the configured base URL. */
function resolveUrl(path) {
  return API_CONFIG.baseUrl ? `${API_CONFIG.baseUrl}${path}` : path
}

/* Build request headers. A caller may pass an explicit `options.token`; when
   none is given, a runtime-injected token (`window.__GREYWATCH_API_TOKEN__`)
   is used if present. In the loopback/local default neither exists and no
   Authorization header is sent. */
function buildHeaders({ token, contentType = true } = {}) {
  const headers = { Accept: 'application/json' }
  if (contentType) headers['Content-Type'] = 'application/json'
  const authToken = token ?? getRuntimeToken()
  if (authToken) headers.Authorization = `Bearer ${authToken}`
  return headers
}

/* Parse a JSON response body safely, returning null for empty/malformed bodies. */
async function safeJson(response) {
  const text = await response.text()
  if (!text) return null
  try {
    return JSON.parse(text)
  } catch {
    return { _raw: text }
  }
}

/* One fetch attempt, chaining the caller's abort signal with an internal
   timeout so either can cancel the request. */
async function fetchOnce({ url, init, signal }) {
  const controller = new AbortController()
  const onExternalAbort = () => controller.abort()
  if (signal) {
    if (signal.aborted) controller.abort()
    else signal.addEventListener('abort', onExternalAbort, { once: true })
  }
  const timeoutId = setTimeout(() => controller.abort(), API_CONFIG.timeoutMs)

  try {
    const response = await fetch(url, { ...init, signal: controller.signal })
    clearTimeout(timeoutId)
    return response
  } catch (err) {
    clearTimeout(timeoutId)
    if (err.name === 'AbortError') {
      throw new NetworkError(
        signal?.aborted ? 'Request cancelled' : 'Request timed out',
        err,
      )
    }
    throw new NetworkError(err.message || 'Network request failed', err)
  } finally {
    if (signal) signal.removeEventListener('abort', onExternalAbort)
  }
}

/* Core request with bounded retries for transient network failures and 429. */
export async function request(
  path,
  { method = 'GET', body, token, signal, retries = API_CONFIG.maxRetries } = {},
) {
  const url = resolveUrl(path)
  const init = {
    method,
    headers: buildHeaders({ token, contentType: method !== 'GET' }),
    ...(body !== undefined && body !== null ? { body: JSON.stringify(body) } : {}),
    signal,
  }

  let lastError
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    try {
      const response = await fetchOnce({ url, init, signal })

      if (response.ok) {
        return { ok: true, status: response.status, data: await safeJson(response) }
      }

      const bodyData = await safeJson(response)
      const detail =
        (bodyData && (bodyData.detail || bodyData.message || bodyData.error)) ||
        `HTTP ${response.status}`

      if (response.status === 429 && attempt < retries && signal?.aborted !== true) {
        const parsed = parseInt(response.headers.get('retry-after') || '', 10)
        const delay = Number.isFinite(parsed) && parsed > 0
          ? Math.min(parsed * 1000, API_CONFIG.maxRetryAfterMs)
          : API_CONFIG.retryBaseMs * (attempt + 1)
        await sleep(delay)
        continue
      }

      throw new ApiError(String(detail), response.status, bodyData)
    } catch (err) {
      lastError = err
      if (
        err instanceof NetworkError &&
        err.message !== 'Request cancelled' &&
        attempt < retries &&
        signal?.aborted !== true
      ) {
        await sleep(API_CONFIG.retryBaseMs * (attempt + 1))
        continue
      }
      throw err
    }
  }
  throw lastError
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

/* Convenience: GET returning the parsed body (or null). */
export async function get(path, options = {}) {
  const { data } = await request(path, { ...options, method: 'GET' })
  return data
}

/* Convenience: POST returning the parsed body (or null). */
export async function post(path, body, options = {}) {
  const { data } = await request(path, { ...options, method: 'POST', body })
  return data
}
