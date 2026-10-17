// System health panel: API reachability and the two collectors, each shown as
// its own honest state. An unreachable API is never conflated with a disabled
// collector or with live telemetry.

import { Activity, BookLock, Radar } from 'lucide-react'
import { Panel, PanelHeader, RefreshButton } from '@/components/ui/Panel'
import { Badge, StatusBadge } from '@/components/ui/Badge'
import { StatusDot } from '@/components/ui/StatusDot'
import { Skeleton } from '@/components/ui/Skeleton'
import { collectorState } from '@/lib/format/telemetry'
import { describeApiError } from '@/lib/api/errors'

function apiDescriptor(health, loading, error) {
  if (loading && health == null) return { tone: 'unknown', label: 'Checking…', detail: 'Contacting the API' }
  if (error) return { tone: 'unavailable', label: 'Unavailable', detail: describeApiError(error) }
  if (health?.status === 'ok') return { tone: 'healthy', label: 'Connected', detail: `v${health.version || '0.1.0'}` }
  return { tone: 'unavailable', label: 'Unreachable', detail: 'No health response' }
}

function collectorDescriptor(status, loading, error) {
  if (loading && status == null) return { tone: 'unknown', label: 'Checking…', detail: 'Fetching collector status', checking: true }
  if (status == null) return { tone: 'unavailable', label: 'Unavailable', detail: error ? describeApiError(error) : 'No status' }
  const state = collectorState(status)
  const ingested = Number.isFinite(Number(status.events_ingested)) ? Number(status.events_ingested) : null
  const detail = !status.enabled
    ? 'Disabled by default'
    : ingested == null
      ? state.label
      : `${state.label} · ${ingested.toLocaleString()} ingested`
  return { tone: state.tone, label: status.enabled ? state.label : 'Disabled', detail }
}

function overallTone(api, journal, suricata) {
  if (api.tone === 'unavailable') return { tone: 'unavailable', label: 'API unavailable' }
  if (api.tone === 'unknown') return { tone: 'unknown', label: 'Checking…' }
  const tones = [journal.tone, suricata.tone]
  if (tones.includes('unavailable')) return { tone: 'degraded', label: 'Degraded' }
  if (tones.includes('degraded')) return { tone: 'degraded', label: 'Degraded' }
  if (tones.includes('healthy')) return { tone: 'healthy', label: 'Operational' }
  return { tone: 'disabled', label: 'Collectors disabled' }
}

function HealthRow({ icon: Icon, label, descriptor }) {
  return (
    <div className="flex items-center gap-3 rounded-md border border-border-card/70 bg-background/40 p-3">
      <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-raised text-text-muted">
        <Icon size={15} aria-hidden="true" />
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="truncate text-xs font-medium text-text-primary">{label}</span>
        </div>
        <span className="mt-0.5 block truncate text-[11px] text-text-muted" title={descriptor.detail}>{descriptor.detail}</span>
      </div>
      {descriptor.checking ? (
        <Skeleton className="h-4 w-16" />
      ) : (
        <Badge tone={descriptor.tone}>{descriptor.label}</Badge>
      )}
    </div>
  )
}

export function SystemHealth({
  health, healthLoading, healthError,
  journal, journalLoading, journalError,
  suricata, suricataLoading, suricataError,
  onRetry,
}) {
  const api = apiDescriptor(health, healthLoading, healthError)
  const journalD = collectorDescriptor(journal, journalLoading, journalError)
  const suricataD = collectorDescriptor(suricata, suricataLoading, suricataError)
  const overall = overallTone(api, journalD, suricataD)

  return (
    <Panel>
      <PanelHeader
        title="System health"
        icon={Activity}
        actions={
          <>
            <StatusDot tone={overall.tone} pulse={overall.tone === 'healthy'} className="mr-1" />
            <StatusBadge status={overall.tone} label={overall.label} />
            <RefreshButton onClick={onRetry} label="Retry system health" />
          </>
        }
      />
      <div className="grid grid-cols-1 gap-3 p-4 md:grid-cols-3">
        <HealthRow icon={Activity} label="Greywatch API" descriptor={api} />
        <HealthRow icon={BookLock} label="Journal collector" descriptor={journalD} />
        <HealthRow icon={Radar} label="Suricata collector" descriptor={suricataD} />
      </div>
    </Panel>
  )
}
