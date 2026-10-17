// Shared collector panel used by both the journal and Suricata pages.
//
// States are derived only from the real status endpoint: enabled/disabled,
// available/unavailable, stale, and last-run freshness. Manual collection runs
// a single cycle through the real endpoint and reports the actual server result.

import { BookLock, Play, RefreshCw } from 'lucide-react'
import { Panel, PanelHeader } from '@/components/ui/Panel'
import { StatusBadge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Field } from '@/components/ui/Field'
import { Skeleton } from '@/components/ui/Skeleton'
import { collectorState } from '@/lib/format/telemetry'
import { describeApiError } from '@/lib/api/errors'
import { formatDateTime } from '@/lib/format/datetime'

export function CollectorPanel({
  title, subtitle, status, loading, error, onRetry,
  onCollect, collecting, collectError, collectResult,
  disabledHint, evePath = false,
}) {
  const checking = loading && status == null
  const unavailable = status == null && !loading
  const state = collectorState(status)
  const isEnabled = status?.enabled === true
  const ingested = Number.isFinite(Number(status?.events_ingested)) ? Number(status.events_ingested) : null

  return (
    <Panel>
      <PanelHeader
        title={title}
        subtitle={subtitle}
        icon={BookLock}
        actions={
          checking
            ? <Skeleton className="h-4 w-20" />
            : <StatusBadge status={unavailable ? 'unavailable' : state.tone} label={unavailable ? 'Unavailable' : isEnabled ? state.label : 'Disabled'} />
        }
      />

      <div className="flex flex-col gap-4 p-4">
        <dl className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <Field label="Events ingested" value={ingested == null ? null : ingested.toLocaleString()} mono />
          <Field label="Last run" value={status?.last_run_at ? formatDateTime(status.last_run_at) : null} mono />
          <Field label="Last event" value={status?.last_event_ts ? formatDateTime(status.last_event_ts) : null} mono />
          {evePath && <Field label="EVE path" value={status?.eve_path} mono />}
          {!evePath && <Field label="Journal cursor" value={status?.last_cursor} mono />}
          {evePath && status?.last_offset != null && <Field label="Byte offset" value={status.last_offset} mono />}
        </dl>

        {status?.errors?.length > 0 && (
          <div className="rounded-md border border-[#7f1d1d]/40 bg-[#7f1d1d]/10 p-3">
            <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-[#fca5a5]">Reported errors</div>
            <ul className="space-y-1 text-[11px] text-text-secondary">
              {status.errors.map((e, i) => <li key={i} className="truncate" title={e}>{e}</li>)}
            </ul>
          </div>
        )}

        {collecting && (
          <div className="rounded-md border border-border-card bg-background/40 p-3 text-[11px] text-text-secondary">Running a collection cycle…</div>
        )}

        {collectResult && !collecting && (
          <div className="rounded-md border border-accent/30 bg-accent/10 p-3">
            <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-[#6ee7b7]">Collection complete</div>
            <dl className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              <Field label="Seen" value={collectResult.records_seen ?? 0} mono />
              <Field label="Ingested" value={collectResult.events_ingested ?? 0} mono />
              <Field label="Alerts" value={collectResult.alerts?.length ?? 0} mono />
              <Field label="Fallback" value={collectResult.fallback_used ? 'yes' : 'no'} mono />
            </dl>
          </div>
        )}

        {collectError && (
          <div className="rounded-md border border-[#7f1d1d]/40 bg-[#7f1d1d]/10 p-3 text-[11px] text-[#fca5a5]">
            Collection failed: {describeApiError(collectError)}
          </div>
        )}

        {unavailable ? (
          <Button variant="outline" size="md" onClick={() => onRetry()}>
            <RefreshCw size={14} aria-hidden="true" /> Retry status
          </Button>
        ) : (
          <Button variant="primary" size="md" disabled={!isEnabled || collecting} loading={collecting} onClick={onCollect}>
            {!collecting && <Play size={13} aria-hidden="true" />}
            {collecting ? 'Collecting…' : isEnabled ? 'Run collection now' : 'Collector disabled'}
          </Button>
        )}

        <p className="text-[11px] leading-relaxed text-text-muted">{unavailable ? (error ? describeApiError(error) : 'Status endpoint could not be reached.') : disabledHint}</p>
      </div>
    </Panel>
  )
}
