// Recent events — the newest records from the events API. Missing optional
// fields are handled gracefully (shown as "—").

import { ScrollText } from 'lucide-react'
import { Panel, PanelHeader, RefreshButton } from '@/components/ui/Panel'
import { Badge, SeverityBadge } from '@/components/ui/Badge'
import { EmptyState, ErrorState } from '@/components/ui/State'
import { Skeleton } from '@/components/ui/Skeleton'
import { describeApiError } from '@/lib/api/errors'
import { formatClock } from '@/lib/format/datetime'
import { categorizeEvent, eventPreview, eventSourceLabel, eventSourceTone, formatHost } from '@/lib/format/telemetry'

export function RecentEvents({ events, loading, error, onRetry, limit = 6 }) {
  const rows = (events || []).slice(0, limit)

  if (loading) {
    return (
      <Panel>
        <PanelHeader title="Recent event activity" icon={ScrollText} />
        <div className="space-y-1 p-4">
          {Array.from({ length: limit }).map((_, i) => <Skeleton key={i} className="h-8 w-full" />)}
        </div>
      </Panel>
    )
  }

  if (error) {
    return (
      <Panel>
        <PanelHeader title="Recent event activity" icon={ScrollText} />
        <ErrorState title="Events unavailable" message={describeApiError(error)} onRetry={onRetry} />
      </Panel>
    )
  }

  if (rows.length === 0) {
    return (
      <Panel>
        <PanelHeader title="Recent event activity" icon={ScrollText} actions={<RefreshButton onClick={onRetry} />} />
        <EmptyState title="No events" description="Events appear here as they are collected or ingested." />
      </Panel>
    )
  }

  return (
    <Panel>
      <PanelHeader
        title="Recent event activity"
        icon={ScrollText}
        actions={
          <>
            <a href="#/dashboard/events" className="text-[11px] font-medium text-[#6ee7b7] hover:text-accent">View all</a>
            <RefreshButton onClick={onRetry} />
          </>
        }
      />
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-border-card text-left text-[10px] uppercase tracking-wider text-text-muted">
              <th className="px-4 py-2 font-semibold">Time</th>
              <th className="px-2 py-2 font-semibold">Type</th>
              <th className="hidden px-2 py-2 font-semibold md:table-cell">Source</th>
              <th className="px-2 py-2 font-semibold">Host</th>
              <th className="px-4 py-2 font-semibold">Message</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border-card">
            {rows.map((ev) => {
              const cat = categorizeEvent(ev.event_type)
              return (
                <tr key={ev.id} className="align-top hover:bg-card-hover/50">
                  <td className="px-4 py-2.5"><span className="font-mono text-[11px] text-text-secondary">{formatClock(ev.timestamp)}</span></td>
                  <td className="px-2 py-2.5"><SeverityBadge severity={cat.tone === 'critical' ? 'critical' : 'info'} label={cat.category} /></td>
                  <td className="hidden px-2 py-2.5 md:table-cell"><Badge tone={eventSourceTone(ev.source)}>{eventSourceLabel(ev.source)}</Badge></td>
                  <td className="px-2 py-2.5"><span className="font-mono text-[11px] text-text-primary">{formatHost(ev.host)}</span></td>
                  <td className="px-4 py-2.5">
                    <span className="block max-w-[22rem] truncate text-[11px] text-text-secondary" title={eventPreview(ev)}>{eventPreview(ev)}</span>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </Panel>
  )
}
