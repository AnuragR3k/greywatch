// Overview — the operational home. Owns every overview fetch exactly once
// (no duplicate requests) and passes results down. Each section renders its own
// loading / empty / stale / disabled / unavailable state, so one failing
// endpoint never blocks the rest, and an unknown value is shown as "—",
// never as a fabricated zero.

import { useCallback, useMemo, useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { useAlerts, useEvents, useHealth, useJournalStatus, useSuricataStatus } from '@/hooks/useTelemetry'
import { usePolling } from '@/hooks/usePolling'
import { Button } from '@/components/ui/Button'
import { StatusBadge } from '@/components/ui/Badge'
import { cn } from '@/lib/utils'
import { KpiGrid } from './KpiGrid'
import { SystemHealth } from './SystemHealth'
import { ActivityChart } from './ActivityChart'
import { RecentAlerts } from './RecentAlerts'
import { RecentEvents } from './RecentEvents'
import { CollectorHealth } from './CollectorHealth'
import { POLL_INTERVAL_MS } from '@/lib/api/config'

const HIGH_SEVERITIES = new Set(['high', 'critical'])

/** Build a metric descriptor from a resource state. value is null unless it
    can be computed honestly from real data. */
function metric(resource, compute) {
  const { data, loading, error } = resource
  if (data == null) return loading ? { loading: true } : { unavailable: true, error }
  return { value: compute(data) }
}

export function OverviewPage() {
  const health = useHealth()
  const events = useEvents({ limit: 200 })
  const alerts = useAlerts({ status: 'all', limit: 100 })
  const journal = useJournalStatus()
  const suricata = useSuricataStatus()

  const [live, setLive] = useState(true)

  const { refetch: refetchHealth, lastUpdated: healthUpdated } = health
  const { refetch: refetchEvents, lastUpdated: eventsUpdated } = events
  const { refetch: refetchAlerts, lastUpdated: alertsUpdated } = alerts
  const { refetch: refetchJournal, lastUpdated: journalUpdated } = journal
  const { refetch: refetchSuricata, lastUpdated: suricataUpdated } = suricata

  const refreshAll = useCallback(
    ({ signal } = {}) => Promise.all([
      refetchHealth({ signal }),
      refetchEvents({ signal }),
      refetchAlerts({ signal }),
      refetchJournal({ signal }),
      refetchSuricata({ signal }),
    ]),
    [refetchHealth, refetchEvents, refetchAlerts, refetchJournal, refetchSuricata],
  )

  usePolling(refreshAll, { intervalMs: POLL_INTERVAL_MS, enabled: live })

  const lastUpdated = useMemo(() => {
    const stamps = [healthUpdated, eventsUpdated, alertsUpdated, journalUpdated, suricataUpdated]
      .filter(Boolean)
      .map((d) => d.getTime())
    return stamps.length ? new Date(Math.max(...stamps)) : null
  }, [healthUpdated, eventsUpdated, alertsUpdated, journalUpdated, suricataUpdated])

  const metrics = {
    totalEvents: metric(events, (d) => d.length),
    openAlerts: metric(alerts, (d) => d.filter((a) => a.status === 'open').length),
    highSeverity: metric(alerts, (d) => d.filter((a) => a.status === 'open' && HIGH_SEVERITIES.has(a.severity)).length),
    detections: metric(alerts, (d) => new Set(d.filter((a) => a.status === 'open').map((a) => a.rule_id)).size),
  }

  const apiState = health.error
    ? 'unavailable'
    : health.loading && health.data == null
      ? 'unknown'
      : health.data?.status === 'ok'
        ? 'healthy'
        : 'unavailable'

  return (
    <div className="flex flex-col gap-4">
      {/* Header: API state, freshness, live toggle, refresh */}
      <div className="flex flex-wrap items-center gap-2">
        <StatusBadge
          status={apiState}
          label={apiState === 'healthy' ? 'API online' : apiState === 'unknown' ? 'Checking API…' : 'API unavailable'}
        />
        <span className="text-[11px] text-text-muted">
          {lastUpdated ? `Updated ${lastUpdated.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })}` : 'No successful update yet'}
        </span>
        <div className="ml-auto flex items-center gap-2">
          <button
            type="button"
            onClick={() => setLive((v) => !v)}
            aria-pressed={live}
            className={cn(
              'flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-[11px] font-medium transition-colors',
              live
                ? 'border-accent/30 bg-accent/10 text-[#6ee7b7]'
                : 'border-border-card text-text-secondary hover:bg-card-hover',
            )}
          >
            <span className={cn('h-1.5 w-1.5 rounded-full', live ? 'bg-accent gw-pulse' : 'bg-severity-unknown')} aria-hidden="true" />
            {live ? 'Live' : 'Paused'}
          </button>
          <Button variant="outline" size="sm" onClick={() => refreshAll()} aria-label="Refresh overview">
            <RefreshCw size={13} aria-hidden="true" /> Refresh
          </Button>
        </div>
      </div>

      <SystemHealth
        health={health.data}
        healthLoading={health.loading}
        healthError={health.error}
        journal={journal.data}
        journalLoading={journal.loading}
        journalError={journal.error}
        suricata={suricata.data}
        suricataLoading={suricata.loading}
        suricataError={suricata.error}
        onRetry={() => refreshAll()}
      />

      <KpiGrid metrics={metrics} />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="flex flex-col gap-4">
          <ActivityChart events={events.data} loading={events.loading} error={events.error} onRetry={events.refetch} />
          <RecentAlerts alerts={alerts.data} loading={alerts.loading} error={alerts.error} onRetry={alerts.refetch} onNavigate={undefined} />
        </div>
        <div className="flex flex-col gap-4">
          <RecentEvents events={events.data} loading={events.loading} error={events.error} onRetry={events.refetch} />
          <CollectorHealth
            journal={journal.data}
            journalLoading={journal.loading}
            journalError={journal.error}
            refetchJournal={journal.refetch}
            suricata={suricata.data}
            suricataLoading={suricata.loading}
            suricataError={suricata.error}
            refetchSuricata={suricata.refetch}
          />
        </div>
      </div>
    </div>
  )
}
