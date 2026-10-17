// Events explorer. Search, type, source, and time filtering are applied
// client-side over the retrieved events (labelled as such — the backend accepts
// limit only). Rows expand to full normalized fields and the raw record.

import { useMemo, useState } from 'react'
import { ChevronDown, ScrollText } from 'lucide-react'
import { useEvents } from '@/hooks/useTelemetry'
import { Panel } from '@/components/ui/Panel'
import { Button } from '@/components/ui/Button'
import { Badge, SeverityBadge } from '@/components/ui/Badge'
import { EmptyState, ErrorState } from '@/components/ui/State'
import { Skeleton } from '@/components/ui/Skeleton'
import { SelectMenu } from '@/components/ui/SelectMenu'
import { FieldGrid } from '@/components/ui/Field'
import { describeApiError } from '@/lib/api/errors'
import { formatClock } from '@/lib/format/datetime'
import {
  categorizeEvent, eventDetailFields, eventPreview, eventRawPayload, eventSearchText,
  eventSourceKey, eventSourceLabel, eventSourceTone, formatHost, hasValue,
} from '@/lib/format/telemetry'

const PAGE_SIZE = 50
const TIME_RANGES = [
  { value: '1h', label: 'Last hour', ms: 3600_000 },
  { value: '24h', label: 'Last 24 hours', ms: 86_400_000 },
  { value: '7d', label: 'Last 7 days', ms: 604_800_000 },
  { value: 'all', label: 'All retrieved', ms: null },
]

function EventRow({ event }) {
  const [open, setOpen] = useState(false)
  const cat = categorizeEvent(event.event_type)
  const fields = eventDetailFields(event)
  const raw = eventRawPayload(event)

  return (
    <>
      <tr className="align-top hover:bg-card-hover/40">
        <td className="whitespace-nowrap px-4 py-2.5">
          <button
            type="button"
            onClick={() => setOpen((o) => !o)}
            aria-expanded={open}
            className="flex items-center gap-1.5 font-mono text-[11px] text-text-secondary hover:text-text-primary"
          >
            <ChevronDown size={12} className={open ? 'rotate-180 transition-transform' : 'transition-transform'} aria-hidden="true" />
            {formatClock(event.timestamp)}
          </button>
        </td>
        <td className="px-2 py-2.5"><Badge tone={eventSourceTone(event.source)}>{eventSourceLabel(event.source)}</Badge></td>
        <td className="px-2 py-2.5"><span className="font-mono text-[11px] text-text-primary">{formatHost(event.host)}</span></td>
        <td className="px-2 py-2.5"><SeverityBadge severity={cat.tone === 'critical' ? 'critical' : 'info'} label={cat.category} /></td>
        <td className="hidden px-2 py-2.5 md:table-cell"><span className="font-mono text-[11px] text-text-secondary">{hasValue(event.event_type) ? event.event_type : '—'}</span></td>
        <td className="px-4 py-2.5"><span className="block max-w-[28rem] truncate text-[11px] text-text-secondary" title={eventPreview(event)}>{eventPreview(event)}</span></td>
      </tr>
      {open && (
        <tr className="bg-background/50">
          <td colSpan={6} className="px-4 pb-4 pt-1">
            <div className="rounded-md border border-border-card bg-card p-3">
              <FieldGrid fields={fields} />
              {raw && (
                <div className="mt-3">
                  <div className="mb-1 text-[10px] uppercase tracking-wider text-text-muted">Raw record</div>
                  <pre className="max-h-60 overflow-auto whitespace-pre-wrap break-words rounded border border-border-card bg-background/60 p-2.5 font-mono text-[11px] leading-relaxed text-text-secondary">{raw}</pre>
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

export function EventsPage() {
  const { data: events, loading, error, refetch } = useEvents({ limit: 500 })
  const [search, setSearch] = useState('')
  const [sourceFilter, setSourceFilter] = useState('all')
  const [typeFilter, setTypeFilter] = useState('all')
  const [timeRange, setTimeRange] = useState('24h')
  const [page, setPage] = useState(1)

  const now = useMemo(() => Date.now(), [])
  const rangeMs = TIME_RANGES.find((r) => r.value === timeRange)?.ms ?? null

  const typeOptions = useMemo(() => {
    const counts = new Map()
    for (const e of events || []) {
      const { category } = categorizeEvent(e.event_type)
      counts.set(category, (counts.get(category) || 0) + 1)
    }
    return [{ value: 'all', label: 'All types' }, ...[...counts.entries()].map(([name, count]) => ({ value: name, label: `${name} (${count})` }))]
  }, [events])

  const filtered = useMemo(() => {
    const term = search.trim().toLowerCase()
    const cutoff = rangeMs != null ? now - rangeMs : null
    return (events || [])
      .filter((e) => {
        if (cutoff != null) {
          const t = Date.parse(e.timestamp)
          if (Number.isNaN(t) || t < cutoff || t > now) return false
        }
        if (sourceFilter !== 'all' && eventSourceKey(e.source) !== sourceFilter) return false
        if (typeFilter !== 'all' && categorizeEvent(e.event_type).category !== typeFilter) return false
        if (term && !eventSearchText(e).some((v) => v.includes(term))) return false
        return true
      })
      .sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp))
  }, [events, search, sourceFilter, typeFilter, rangeMs, now])

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))
  const currentPage = Math.min(page, totalPages)
  const pageRows = filtered.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE)

  const sourceOptions = [
    { value: 'all', label: 'All sources' },
    { value: 'journal', label: 'systemd journal' },
    { value: 'suricata', label: 'Suricata' },
    { value: 'ingest', label: 'HTTP ingest' },
    { value: 'test', label: 'Test' },
    { value: 'unknown', label: 'Unknown' },
  ]

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex flex-wrap items-center gap-2">
          <SelectMenu label="Time range" value={timeRange} onChange={(v) => { setTimeRange(v); setPage(1) }} options={TIME_RANGES} className="w-40" />
          <SelectMenu label="Event type" value={typeFilter} onChange={(v) => { setTypeFilter(v); setPage(1) }} options={typeOptions} className="w-44" />
          <SelectMenu label="Source" value={sourceFilter} onChange={(v) => { setSourceFilter(v); setPage(1) }} options={sourceOptions} className="w-40" />
          <input
            type="search"
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(1) }}
            placeholder="Search events…"
            aria-label="Search events"
            className="h-8 w-full min-w-[200px] rounded-md border border-border-card bg-card px-3 text-xs text-text-primary placeholder:text-text-muted outline-none focus:border-accent sm:w-64"
          />
        </div>
        <div className="text-[11px] text-text-muted">
          {filtered.length} of {(events || []).length} · filters applied client-side over retrieved events
        </div>
      </div>

      {loading ? (
        <Panel><div className="space-y-1.5 p-4">{Array.from({ length: 8 }).map((_, i) => <Skeleton key={i} className="h-9 w-full" />)}</div></Panel>
      ) : error && !events ? (
        <Panel><ErrorState title="Events unavailable" message={describeApiError(error)} onRetry={refetch} /></Panel>
      ) : pageRows.length === 0 ? (
        <Panel>
          <EmptyState
            icon={ScrollText}
            title={search || sourceFilter !== 'all' || typeFilter !== 'all' || timeRange !== 'all' ? 'No events match your filters' : 'No events'}
            description={search ? 'Adjust the search or filters.' : 'Events appear here as they are collected or ingested.'}
            action={() => { setSearch(''); setSourceFilter('all'); setTypeFilter('all'); setTimeRange('all') }}
            actionLabel="Reset filters"
          />
        </Panel>
      ) : (
        <Panel>
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="border-b border-border-card bg-raised/40 text-left text-[10px] uppercase tracking-wider text-text-muted">
                  <th className="px-4 py-2.5 font-semibold">Time</th>
                  <th className="px-2 py-2.5 font-semibold">Source</th>
                  <th className="px-2 py-2.5 font-semibold">Host</th>
                  <th className="px-2 py-2.5 font-semibold">Type</th>
                  <th className="hidden px-2 py-2.5 font-semibold md:table-cell">Event type</th>
                  <th className="px-4 py-2.5 font-semibold">Message</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-card">
                {pageRows.map((ev) => <EventRow key={ev.id} event={ev} />)}
              </tbody>
            </table>
          </div>
          {totalPages > 1 && (
            <div className="flex items-center justify-between border-t border-border-card px-4 py-2.5">
              <Button variant="outline" size="sm" disabled={currentPage === 1} onClick={() => setPage(currentPage - 1)}>Previous</Button>
              <span className="text-[11px] text-text-muted">Page {currentPage} of {totalPages}</span>
              <Button variant="outline" size="sm" disabled={currentPage === totalPages} onClick={() => setPage(currentPage + 1)}>Next</Button>
            </div>
          )}
        </Panel>
      )}
    </div>
  )
}
