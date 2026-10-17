// useResource — the single read hook used by every dashboard section.
//
// Guarantees that prevent the historical infinite-loop / request-storm bugs:
//   * the fetch function is kept in a ref, so `run`/`refetch` have stable
//     identities and effects do not re-fire every render;
//   * identical in-flight requests are de-duplicated across hook instances;
//   * overlapping calls for the same resource are coalesced;
//   * the last successful data is retained on error (clearly surfaced as
//     stale by the consumer) instead of blanking the section;
//   * cancellations are distinguished from failures;
//   * a global `gw-refresh` event lets one control refresh every section.

import { useCallback, useEffect, useRef, useState } from 'react'
import { isCancelledError } from '@/lib/api/errors'

const IN_FLIGHT = new Map()

async function dedupe(key, fn) {
  if (IN_FLIGHT.has(key)) return IN_FLIGHT.get(key)
  const promise = Promise.resolve()
    .then(fn)
    .finally(() => IN_FLIGHT.delete(key))
  IN_FLIGHT.set(key, promise)
  return promise
}

export function useResource(fn, key, { enabled = true, immediate = true } = {}) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(immediate && enabled)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState(null)
  const [lastUpdated, setLastUpdated] = useState(null)

  const mounted = useRef(true)
  const inFlight = useRef(false)
  const dataRef = useRef(null)
  const fnRef = useRef(fn)
  useEffect(() => { fnRef.current = fn }, [fn])

  const run = useCallback(async (...args) => {
    if (!enabled) return null
    if (inFlight.current) return null
    inFlight.current = true
    setError(null)
    if (dataRef.current == null) setLoading(true)
    else setRefreshing(true)
    try {
      const result = await dedupe(key, () => fnRef.current(...args))
      if (!mounted.current) return result
      dataRef.current = result
      setData(result)
      setError(null)
      setLastUpdated(new Date())
      return result
    } catch (err) {
      if (isCancelledError(err)) return null
      if (!mounted.current) return null
      setError(err)
      return null
    } finally {
      inFlight.current = false
      if (mounted.current) {
        setLoading(false)
        setRefreshing(false)
      }
    }
  }, [key, enabled])

  useEffect(() => {
    mounted.current = true
    if (immediate && enabled) run()
    return () => { mounted.current = false }
  }, [run, enabled, immediate])

  useEffect(() => {
    if (!enabled) return undefined
    const onRefresh = () => { run() }
    window.addEventListener('gw-refresh', onRefresh)
    return () => window.removeEventListener('gw-refresh', onRefresh)
  }, [run, enabled])

  const refetch = useCallback((...args) => run(...args), [run])

  return { data, loading, refreshing, error, lastUpdated, refetch }
}
