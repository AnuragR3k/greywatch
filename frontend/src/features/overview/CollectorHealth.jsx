// Collector health (overview) — journal and Suricata shown separately. A
// disabled collector is shown as disabled, not broken; an unreachable status
// endpoint shows "Unavailable" with a retry (never "0 ingested").

import { BookLock, Radar } from 'lucide-react'
import { Panel, PanelHeader } from '@/components/ui/Panel'
import { StatusBadge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Skeleton } from '@/components/ui/Skeleton'
import { collectorState } from '@/lib/format/telemetry'
import { describeApiError } from '@/lib/api/errors'
import { formatCompact } from '@/lib/format/datetime'

function CollectorSummary({ title, icon, status, loading, error, onRetry, disabledHint, evePath = false }) {
  const checking = loading && status == null
  const unavailable = status == null && !loading
  const state = collectorState(status)
  const ingested = Number.isFinite(Number(status?.events_ingested)) ? Number(status.events_ingested) : null

  return (
    <Panel>
      <PanelHeader
        title={title}
        icon={icon}
        actions={
          checking
            ? <Skeleton className="h-4 w-20" />
            : <StatusBadge status={unavailable ? 'unavailable' : state.tone} label={unavailable ? 'Unavailable' : status.enabled ? state.label : 'Disabled'} />
        }
      />
      <div className="p-4">
        <dl className="grid grid-cols-2 gap-3">
          <div>
            <dt className="text-[10px] uppercase tracking-wider text-text-muted">Events ingested</dt>
            <dd className="font-mono text-sm text-text-primary">{ingested == null ? '—' : ingested.toLocaleString()}</dd>
          </div>
          <div>
            <dt className="text-[10px] uppercase tracking-wider text-text-muted">Last run</dt>
            <dd className="font-mono text-sm text-text-primary">{status?.last_run_at ? formatCompact(status.last_run_at) : '—'}</dd>
          </div>
          {evePath && (
            <div className="col-span-2">
              <dt className="text-[10px] uppercase tracking-wider text-text-muted">EVE path</dt>
              <dd className="truncate font-mono text-xs text-text-secondary" title={status?.eve_path || ''}>{status?.eve_path || '—'}</dd>
            </div>
          )}
        </dl>

        {status?.errors?.length > 0 && (
          <ul className="mt-3 space-y-1 rounded-md border border-[#7f1d1d]/40 bg-[#7f1d1d]/10 p-2.5 text-[11px] text-[#fca5a5]">
            {status.errors.map((e, i) => <li key={i} className="truncate" title={e}>{e}</li>)}
          </ul>
        )}

        {unavailable && (
          <div className="mt-3 flex items-center justify-between gap-2 rounded-md border border-[#7f1d1d]/40 bg-[#7f1d1d]/10 p-2.5">
            <span className="text-[11px] text-[#fca5a5]">{error ? describeApiError(error) : 'Status unavailable'}</span>
            <Button variant="outline" size="sm" onClick={() => onRetry()}>Retry</Button>
          </div>
        )}

        {!unavailable && !status?.enabled && (
          <p className="mt-3 text-[11px] text-text-muted">{disabledHint}</p>
        )}
      </div>
    </Panel>
  )
}

export function CollectorHealth({
  journal, journalLoading, journalError, refetchJournal,
  suricata, suricataLoading, suricataError, refetchSuricata,
}) {
  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
      <CollectorSummary
        title="Journal collector"
        icon={BookLock}
        status={journal}
        loading={journalLoading}
        error={journalError}
        onRetry={refetchJournal}
        disabledHint="Disabled by default. Enable with GREYWATCH_JOURNAL_ENABLED."
      />
      <CollectorSummary
        title="Suricata collector"
        icon={Radar}
        status={suricata}
        loading={suricataLoading}
        error={suricataError}
        onRetry={refetchSuricata}
        disabledHint="Disabled by default. Enable with GREYWATCH_SURICATA_ENABLED."
        evePath
      />
    </div>
  )
}
