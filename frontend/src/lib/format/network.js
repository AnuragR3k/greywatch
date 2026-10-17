// Network field formatting.

import { hasValue } from './values'

/** "ip:port" / "ip" / ":port" / null when both are absent. */
export function formatEndpoint(ip, port) {
  if (!hasValue(ip) && !hasValue(port)) return null
  if (!hasValue(ip)) return `:${port}`
  if (!hasValue(port)) return String(ip)
  return `${ip}:${port}`
}

/** Host value or a neutral dash. */
export function formatHost(host) {
  return hasValue(host) ? String(host) : '—'
}
