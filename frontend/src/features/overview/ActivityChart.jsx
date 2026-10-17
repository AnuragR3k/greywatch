// Event activity — a time-bucketed bar chart built from real event timestamps
// (last 24h). No fabricated trend: if there are no events, an explicit empty
// state is shown; a failed fetch offers retry.

import { useMemo } from 'react'
import { BarChart3 } from 'lucide-react'
import { Panel, PanelHeader, RefreshButton } from '@/components/ui/Panel'
import { EmptyState, ErrorState } from '@/components/ui/State'
import { Skeleton } from '@/components/ui/Skeleton'
import { describeApiError } from '@/lib/api/errors'

const BUCKETS = 24
const RANGE_MS = 24 * 60 * 60 * 1000

function bucketEvents(events, now) {
  const counts = Array.from({ length: BUCKETS }, () => 0)
  if (!events) return { counts, max: 0, total: 0 }
  const start = now - RANGE_MS
  let max = 0
  let total = 0
  for (const ev of events) {
    const t = Date.parse(ev.timestamp)
    if (Number.isNaN(t) || t < start || t > now) continue
    const idx = Math.max(0, Math.min(BUCKETS - 1, Math.floor(((t - start) / RANGE_MS) * BUCKETS)))
    counts[idx] += 1
    total += 1
    if (counts[idx] > max) max = counts[idx]
  }
  return { counts, max, total }
}

export function ActivityChart({ events, loading, error, onRetry }) {
  const now = useMemo(() => Date.now(), [])
  const { counts, max, total } = useMemo(() => bucketEvents(events, now), [events, now])

  if (loading) {
    return (
      <Panel>
        <PanelHeader title="Event activity" subtitle="Last 24 hours" icon={BarChart3} />
        <div className="flex h-40 items-end gap-1 p-4">
          {Array.from({ length: BUCKETS }).map((_, i) => <Skeleton key={i} className="h-full w-full" />)}
        </div>
      </Panel>
    )
  }

  if (error) {
    return (
      <Panel>
        <PanelHeader title="Event activity" icon={BarChart3} />
        <ErrorState title="Activity unavailable" message={describeApiError(error)} onRetry={onRetry} />
      </Panel>
    )
  }

  if (!events || total === 0) {
    return (
      <Panel>
        <PanelHeader title="Event activity" subtitle="Last 24 hours" icon={BarChart3} actions={<RefreshButton onClick={onRetry} />} />
        <EmptyState title="No events in the last 24 hours" description="Activity appears here as events are ingested from the journal, Suricata, or the HTTP API." />
      </Panel>
    )
  }

  return (
    <Panel>
      <PanelHeader
        title="Event activity"
        subtitle="Last 24 hours"
        icon={BarChart3}
        actions={<RefreshButton onClick={onRetry} />}
      />
      <div className="p-4">
        <div className="flex h-32 items-end gap-[3px]" role="img" aria-label={`Event activity over the last 24 hours: ${total} events`}>
          {counts.map((count, i) => {
            const pct = max > 0 ? Math.max(count > 0 ? 6 : 0, Math.round((count / max) * 100)) : 0
            return (
              <div
                key={i}
                className="flex h-full w-full flex-col justify-end"
                title={`${String(i).padStart(2, '0')}:00 — ${count} event${count === 1 ? '' : 's'}`}
              >
                <div
                  className={count > 0 ? 'w-full rounded-t-[2px] bg-accent/80' : 'w-full rounded-t-[2px] bg-border-card'}
                  style={{ height: `${pct}%`, minHeight: count > 0 ? '3px' : '1px' }}
                />
              </div>
            )
          })}
        </div>
        <div className="mt-2 flex justify-between font-mono text-[10px] text-text-muted">
          <span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>now</span>
        </div>
        <div className="mt-3 flex items-center justify-between border-t border-border-card pt-2 text-[11px] text-text-muted">
          <span>Events in range</span>
          <span className="font-mono text-text-primary">{total.toLocaleString()}</span>
        </div>
      </div>
    </Panel>
  )
}
