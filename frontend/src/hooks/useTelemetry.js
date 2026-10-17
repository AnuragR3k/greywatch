// Domain read/write hooks. Each read hook wraps useResource with a stable key
// so identical resources are fetched once and shared across sections.

import { useCallback, useEffect, useRef, useState } from 'react'
import { useResource } from './useResource'
import {
  fetchHealth,
  fetchEvents,
  fetchAlerts,
  fetchAlertDetail,
  closeAlert,
  fetchJournalStatus,
  fetchSuricataStatus,
  collectJournal,
  collectSuricata,
} from '@/lib/api/endpoints'

export function useHealth() {
  return useResource((o = {}) => fetchHealth({ signal: o.signal }), 'health')
}

export function useEvents({ limit = 100 } = {}) {
  return useResource(
    (o = {}) => fetchEvents({ limit, signal: o.signal }),
    `events:${limit}`,
  )
}

export function useAlerts({ status = 'all', limit = 100 } = {}) {
  return useResource(
    (o = {}) => fetchAlerts({ status, limit, signal: o.signal }),
    `alerts:${status}:${limit}`,
  )
}

export function useAlertDetail(id) {
  return useResource(
    (o = {}) => (id != null ? fetchAlertDetail(id, { signal: o.signal }) : null),
    `alert-detail:${id}`,
    { immediate: id != null },
  )
}

export function useJournalStatus() {
  return useResource((o = {}) => fetchJournalStatus({ signal: o.signal }), 'journal:status')
}

export function useSuricataStatus() {
  return useResource((o = {}) => fetchSuricataStatus({ signal: o.signal }), 'suricata:status')
}

/* ------------------------------------------------------------- mutations */

function useMutation(fn) {
  const [pending, setPending] = useState(false)
  const [error, setError] = useState(null)
  const fnRef = useRef(fn)
  useEffect(() => { fnRef.current = fn }, [fn])
  const pendingRef = useRef(false)

  const execute = useCallback(async (...args) => {
    if (pendingRef.current) return null
    pendingRef.current = true
    setPending(true)
    setError(null)
    try {
      return await fnRef.current(...args)
    } catch (err) {
      setError(err)
      return null
    } finally {
      pendingRef.current = false
      setPending(false)
    }
  }, [])

  const reset = useCallback(() => setError(null), [])

  return { execute, pending, error, reset }
}

export function useCloseAlert() {
  return useMutation((id) => closeAlert(id))
}

export function useCollectJournal() {
  return useMutation(() => collectJournal())
}

export function useCollectSuricata() {
  return useMutation(() => collectSuricata())
}
