// Alerts — investigation workflow. Filtering, search, sort, and pagination are
// applied client-side over the retrieved alerts (clearly labelled). Resolution
// calls the real close endpoint; the row only leaves "open" after the server
// confirms.

import { useCallback, useMemo, useState } from 'react'
import { ShieldAlert } from 'lucide-react'
import { useAlerts, useCloseAlert } from '@/hooks/useTelemetry'
import { Panel } from '@/components/ui/Panel'
import { Button } from '@/components/ui/Button'
import { SeverityBadge, StatusBadge } from '@/components/ui/Badge'
import { EmptyState, ErrorState } from '@/components/ui/State'
import { Skeleton } from '@/components/ui/Skeleton'
import { Dialog } from '@/components/ui/Dialog'
import { SelectMenu } from '@/components/ui/SelectMenu'
import { describeApiError } from '@/lib/api/errors'
import { formatCompact } from '@/lib/format/datetime'
import { SEVERITY_ORDER, alertNetworkSummary, alertRuleLabel, alertSearchText, formatHost, isSuricataAlert } from '@/lib/format/telemetry'
import { AlertDetailDrawer } from './AlertDetailDrawer'

const PAGE_SIZE = 25
const STATUS_OPTIONS = [
  { value: 'open', label: 'Open' },
  { value: 'closed', label: 'Resolved' },
  { value: 'all', label: 'All statuses' },
]
const SEVERITY_OPTIONS = [
  { value: 'all', label: 'All severities' },
  ...SEVERITY_ORDER.map((s) => ({ value: s, label: s.charAt(0).toUpperCase() + s.slice(1) })),
]
const SORT_OPTIONS = [
  { value: 'last_triggered_at', label: 'Last triggered' },
  { value: 'created_at', label: 'First seen' },
  { value: 'severity', label: 'Severity' },
]

export function AlertsPage() {
  // The backend returns ``count`` (this page) and ``total`` (all matching
  // pages). Filtering by status/severity/source IP/search is applied
  // client-side over the fetched set and labelled as such.
  const { data: alerts, loading, error, refetch, total } = useAlerts({
    status: 'all',
    limit: 500,
  })
  const closeAlert = useCloseAlert()

  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('open')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [sourceIpFilter, setSourceIpFilter] = useState('')
  const [sortKey, setSortKey] = useState('last_triggered_at')
  const [sortDir, setSortDir] = useState('desc')
  const [page, setPage] = useState(1)
  const [viewingId, setViewingId] = useState(null)
  const [confirmId, setConfirmId] = useState(null)

  const filtered = useMemo(() => {
    const term = search.trim().toLowerCase()
    const sourceIp = sourceIpFilter.trim()
    const list = (alerts || []).filter((a) => {
      if (statusFilter !== 'all' && a.status !== statusFilter) return false
      if (severityFilter !== 'all' && a.severity !== severityFilter) return false
      if (sourceIp && String(a.source_ip).toLowerCase() !== sourceIp.toLowerCase()) return false
      if (term && !alertSearchText(a).some((v) => v.includes(term))) return false
      return true
    })
    return list.sort((a, b) => {
      const av = a[sortKey] ?? ''
      const bv = b[sortKey] ?? ''
      if (av < bv) return sortDir === 'asc' ? -1 : 1
      if (av > bv) return sortDir === 'asc' ? 1 : -1
      return 0
    })
  }, [alerts, statusFilter, severityFilter, sourceIpFilter, search, sortKey, sortDir])

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))
  const currentPage = Math.min(page, totalPages)
  const pageRows = filtered.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE)
  const openCount = (alerts || []).filter((a) => a.status === 'open').length

  const handleResolve = useCallback(async () => {
    if (confirmId == null) return
    const result = await closeAlert.execute(confirmId)
    if (result) {
      setConfirmId(null)
      refetch()
    }
  }, [confirmId, closeAlert, refetch])

  return (
    <div className="flex flex-col gap-4">
      {/* Toolbar */}
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex flex-wrap items-center gap-2">
          <SelectMenu label="Status" value={statusFilter} onChange={(v) => { setStatusFilter(v); setPage(1) }} options={STATUS_OPTIONS} className="w-40" />
          <SelectMenu label="Severity" value={severityFilter} onChange={(v) => { setSeverityFilter(v); setPage(1) }} options={SEVERITY_OPTIONS} className="w-44" />
          <input
            type="search"
            value={sourceIpFilter}
            onChange={(e) => { setSourceIpFilter(e.target.value); setPage(1) }}
            placeholder="Source IP…"
            aria-label="Filter by source IP"
            className="h-8 w-full min-w-[160px] rounded-md border border-border-card bg-card px-3 text-xs text-text-primary placeholder:text-text-muted outline-none focus:border-accent"
          />
          <input
            type="search"
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(1) }}
            placeholder="Search alerts…"
            aria-label="Search alerts"
            className="h-8 w-full min-w-[200px] rounded-md border border-border-card bg-card px-3 text-xs text-text-primary placeholder:text-text-muted outline-none focus:border-accent sm:w-64"
          />
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[11px] text-text-muted">Sort</span>
          <SelectMenu label="Sort by" value={sortKey} onChange={setSortKey} options={SORT_OPTIONS} className="w-40" />
          <Button variant="outline" size="sm" onClick={() => setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))} aria-label="Toggle sort direction">
            {sortDir === 'asc' ? 'Ascending' : 'Descending'}
          </Button>
          <span className="text-[11px] text-text-muted">
            {total || (alerts?.length ?? 0)} total · {openCount} open
            <span className="hidden sm:inline"> · filters applied client-side</span>
          </span>
        </div>
      </div>

      {loading ? (
        <Panel><div className="space-y-1.5 p-4">{Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div></Panel>
      ) : error && !alerts ? (
        <Panel><ErrorState title="Alerts unavailable" message={describeApiError(error)} onRetry={refetch} /></Panel>
      ) : pageRows.length === 0 ? (
        <Panel>
          <EmptyState
            icon={ShieldAlert}
            title={search || statusFilter !== 'open' || severityFilter !== 'all' ? 'No alerts match your filters' : 'No alerts'}
            description={search ? 'Adjust the search or filters.' : 'Alerts appear here when a detection rule fires.'}
            action={() => { setSearch(''); setStatusFilter('open'); setSeverityFilter('all') }}
            actionLabel="Reset filters"
          />
        </Panel>
      ) : (
        <Panel>
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="border-b border-border-card bg-raised/40 text-left text-[10px] uppercase tracking-wider text-text-muted">
                  <th className="px-4 py-2.5 font-semibold">Last triggered</th>
                  <th className="px-3 py-2.5 font-semibold">Alert</th>
                  <th className="hidden px-3 py-2.5 font-semibold lg:table-cell">Network</th>
                  <th className="px-3 py-2.5 font-semibold">Severity</th>
                  <th className="px-3 py-2.5 font-semibold">Events</th>
                  <th className="px-3 py-2.5 font-semibold">Status</th>
                  <th className="px-4 py-2.5 font-semibold">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-card">
                {pageRows.map((alert) => {
                  const net = isSuricataAlert(alert) ? alertNetworkSummary(alert) : formatHost(alert.source_ip)
                  return (
                    <tr key={alert.id} className="align-top hover:bg-card-hover/40">
                      <td className="whitespace-nowrap px-4 py-3 font-mono text-[11px] text-text-secondary">{formatCompact(alert.last_triggered_at || alert.created_at)}</td>
                      <td className="px-3 py-3">
                        <div className="max-w-[26rem] truncate font-medium text-text-primary" title={alert.title}>{alert.title || alertRuleLabel(alert.rule_id)}</div>
                        <div className="truncate text-[10px] text-text-muted">{alertRuleLabel(alert.rule_id)}</div>
                      </td>
                      <td className="hidden px-3 py-3 lg:table-cell"><span className="font-mono text-[11px] text-text-secondary">{net || '—'}</span></td>
                      <td className="px-3 py-3"><SeverityBadge severity={alert.severity || 'unknown'} /></td>
                      <td className="px-3 py-3 font-mono text-xs text-text-secondary">{alert.event_count ?? '—'}</td>
                      <td className="px-3 py-3"><StatusBadge status={alert.status || 'unknown'} /></td>
                      <td className="px-4 py-3">
                        <div className="flex gap-1.5">
                          <Button variant="outline" size="sm" onClick={() => setViewingId(alert.id)}>Investigate</Button>
                          {alert.status === 'open' && (
                            <Button variant="ghost" size="sm" onClick={() => setConfirmId(alert.id)}>Resolve</Button>
                          )}
                        </div>
                      </td>
                    </tr>
                  )
                })}
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

      {viewingId != null && (
        <AlertDetailDrawer
          alertId={viewingId}
          onClose={() => setViewingId(null)}
          onResolved={() => { setViewingId(null); refetch() }}
        />
      )}

      <Dialog
        open={confirmId != null}
        onClose={() => (closeAlert.pending ? null : setConfirmId(null))}
        title="Resolve this alert?"
        description={confirmId != null ? `Alert #${confirmId} will be marked as resolved. Resolved alerts cannot be reopened from the dashboard.` : ''}
        destructive
        footer={
          <>
            <Button variant="ghost" size="sm" onClick={() => setConfirmId(null)} disabled={closeAlert.pending}>Cancel</Button>
            <Button variant="danger" size="sm" onClick={handleResolve} loading={closeAlert.pending}>Mark as resolved</Button>
          </>
        }
      >
        {closeAlert.error && <p className="text-xs text-[#fca5a5]">{describeApiError(closeAlert.error)}</p>}
      </Dialog>
    </div>
  )
}
