// usePolling — visibility-aware interval that cancels obsolete work.
//
// * calls `fn({ signal })` immediately (optional) then on a fixed interval
// * pauses while the tab is hidden and resumes when visible
// * never overlaps: a tick is skipped while the previous one is in flight
// * aborts in-flight work on unmount/disable via the provided AbortSignal
//
// `fn` is held in a ref so the interval is not torn down on every render.

import { useCallback, useEffect, useRef, useState } from 'react'

export function usePolling(fn, { intervalMs = 15000, enabled = true, immediate = true } = {}) {
  const [lastRunAt, setLastRunAt] = useState(null)
  const timerRef = useRef(null)
  const inFlightRef = useRef(false)
  const abortRef = useRef(null)
  const fnRef = useRef(fn)
  useEffect(() => { fnRef.current = fn }, [fn])

  const stop = useCallback(() => {
    if (timerRef.current) {
      clearInterval(timerRef.current)
      timerRef.current = null
    }
    abortRef.current?.abort()
    abortRef.current = null
    inFlightRef.current = false
  }, [])

  const tick = useCallback(async () => {
    if (inFlightRef.current) return
    inFlightRef.current = true
    abortRef.current = new AbortController()
    try {
      await fnRef.current({ signal: abortRef.current.signal })
      setLastRunAt(new Date())
    } catch {
      // Individual failures are surfaced by the owning resource hooks.
    } finally {
      inFlightRef.current = false
      abortRef.current = null
    }
  }, [])

  const start = useCallback(() => {
    stop()
    if (!enabled) return
    if (immediate) tick()
    timerRef.current = setInterval(tick, intervalMs)
  }, [stop, tick, enabled, immediate, intervalMs])

  useEffect(() => {
    start()
    return stop
  }, [start, stop])

  useEffect(() => {
    const onVisibility = () => {
      if (document.visibilityState === 'hidden') stop()
      else start()
    }
    document.addEventListener('visibilitychange', onVisibility)
    return () => document.removeEventListener('visibilitychange', onVisibility)
  }, [start, stop])

  return { lastRunAt, restart: start }
}
