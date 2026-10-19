// Incidents — correlated security events.
// Correlations are produced by the backend detection pipeline (GET
// /api/v1/incidents); resolution/acknowledgement calls the real incident
// endpoints and the row only changes after the server confirms.
import { useCallback, useMemo, useState } from 'react'
import { AlertTriangle } from 'lucide-react'
import { useIncidents, useAcknowledgeIncident, useResolveIncident } from '@/hooks/useTelemetry'
import { Panel } from '@/components/ui/Panel'
import { Button } from '@/components/ui/Button'
import { SeverityBadge, StatusBadge } from '@/components/ui/Badge'
import { EmptyState, ErrorState } from '@/components/ui/State'
import { Skeleton } from '@/components/ui/Skeleton'
import { Dialog } from '@/components/ui/Dialog'
import { SelectMenu } from '@/components/ui/SelectMenu'
import { describeApiError } from '@/lib/api/errors'
import { formatCompact } from '@/lib/format/datetime'
import { SEVERITY_ORDER, incidentRuleLabel, incidentSearchText } from '@/lib/format/telemetry'
import { IncidentDetailDrawer } from './IncidentDetailDrawer'

const PAGE_SIZE = 25
const STATUS_OPTIONS = [
  { value: 'open', label: 'Open' },
  { value: 'acknowledged', label: 'Acknowledged' },
  { value: 'resolved', label: 'Resolved' },
  { value: 'all', label: 'All statuses' },
]
const SEVERITY_OPTIONS = [
  { value: 'all', label: 'All severities' },
  ...SEVERITY_ORDER.map((s) => ({ value: s, label: s.charAt(0).toUpperCase() + s.slice(1) })),
]

export function IncidentsPage() {
  const { data: incidents, loading, error, refetch } = useIncidents({ status: 'all', limit: 500 })
  const acknowledgeIncident = useAcknowledgeIncident()
  const resolveIncident = useResolveIncident()

  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('open')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [viewingId, setViewingId] = useState(null)
  const [confirmId, setConfirmId] = useState(null)
  const [confirmAction, setConfirmAction] = useState(null)

  const filtered = useMemo(() => {
    const term = search.trim().toLowerCase()
    const list = (incidents || []).filter((i) => {
      if (statusFilter !== 'all' && i.status !== statusFilter) return false
      if (severityFilter !== 'all' && i.severity !== severityFilter) return false
      if (term && !incidentSearchText(i).some((v) => v.includes(term))) return false
      return true
    })
    return list.sort((a, b) => {
      const av = a.first_seen_at ?? ''
      const bv = b.first_seen_at ?? ''
      if (av < bv) return 1
      if (av > bv) return -1
      return 0
    })
  }, [incidents, statusFilter, severityFilter, search])

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))
  const pageRows = filtered.slice(0, PAGE_SIZE)
  const openCount = (incidents || []).filter((i) => i.status === 'open').length

  const handleAction = useCallback(async () => {
    if (confirmId == null || !confirmAction) return
    const result =
      confirmAction === 'acknowledge'
        ? await acknowledgeIncident.execute(confirmId)
        : await resolveIncident.execute(confirmId)
    if (result) {
      setConfirmId(null)
      setConfirmAction(null)
      refetch()
    }
  }, [confirmId, confirmAction, acknowledgeIncident, resolveIncident, refetch])

  return (
    <div className="flex flex-col gap-4">
      {/* Toolbar */}
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex flex-wrap items-center gap-2">
          <SelectMenu
            label="Status"
            value={statusFilter}
            onChange={(v) => { setStatusFilter(v) }}
            options={STATUS_OPTIONS}
            className="w-40"
          />
          <SelectMenu
            label="Severity"
            value={severityFilter}
            onChange={(v) => { setSeverityFilter(v) }}
            options={SEVERITY_OPTIONS}
            className="w-44"
          />
          <input
            type="search"
            value={search}
            onChange={(e) => { setSearch(e.target.value) }}
            placeholder="Search incidents…"
            aria-label="Search incidents"
            className="h-8 w-full min-w-[200px] rounded-md border border-border-card bg-card px-3 text-xs text-text-primary placeholder:text-text-muted outline-none focus:border-accent sm:w-64"
          />
        </div>
        <div className="text-[11px] text-text-muted">
          {filtered.length} of {(incidents || []).length} · {openCount} open
          <span className="hidden sm:inline"> · filters applied client-side</span>
        </div>
      </div>

      {loading ? (
        <Panel>
          <div className="space-y-1.5 p-4">
            {Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}
          </div>
        </Panel>
      ) : error && !incidents ? (
        <Panel>
          <ErrorState title="Incidents unavailable" message={describeApiError(error)} onRetry={refetch} />
        </Panel>
      ) : pageRows.length === 0 ? (
        <Panel>
          <EmptyState
            icon={AlertTriangle}
            title={search || statusFilter !== 'open' || severityFilter !== 'all' ? 'No incidents match your filters' : 'No incidents'}
            description={search ? 'Adjust the search or filters.' : 'Incidents appear here when a correlation rule matches related events.'}
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
                  <th className="px-4 py-2.5 font-semibold">First seen</th>
                  <th className="px-3 py-2.5 font-semibold">Incident</th>
                  <th className="hidden px-3 py-2.5 font-semibold lg:table-cell">Source</th>
                  <th className="px-3 py-2.5 font-semibold">Severity</th>
                  <th className="px-3 py-2.5 font-semibold">Status</th>
                  <th className="px-3 py-2.5 font-semibold">Related events</th>
                  <th className="px-4 py-2.5 font-semibold">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-card">
                {pageRows.map((incident) => (
                  <tr key={incident.id} className="align-top hover:bg-card-hover/40">
                    <td className="whitespace-nowrap px-4 py-3 font-mono text-[11px] text-text-secondary">
                      {formatCompact(incident.first_seen_at || incident.created_at)}
                    </td>
                    <td className="px-3 py-3">
                      <div className="max-w-[28rem] truncate font-medium text-text-primary" title={incident.title}>
                        {incident.title || incidentRuleLabel(incident.rule_id)}
                      </div>
                      <div className="truncate text-[10px] text-text-muted">
                        {incidentRuleLabel(incident.rule_id)} · #{incident.id}
                      </div>
                      {incident.description && (
                        <div className="truncate text-[10px] text-text-secondary" title={incident.description}>
                          {incident.description}
                        </div>
                      )}
                    </td>
                    <td className="hidden px-3 py-3 lg:table-cell">
                      <span className="font-mono text-[11px] text-text-secondary">{incident.source_ip || '—'}</span>
                    </td>
                    <td className="px-3 py-3">
                      <SeverityBadge severity={incident.severity || 'unknown'} />
                    </td>
                    <td className="px-3 py-3">
                      <StatusBadge status={incident.status || 'unknown'} />
                    </td>
                    <td className="px-3 py-3 font-mono text-xs text-text-secondary">
                      {incident.related_event_ids?.length ?? '—'}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex gap-1.5">
                        <Button variant="outline" size="sm" onClick={() => setViewingId(incident.id)}>
                          Investigate
                        </Button>
                        {incident.status === 'open' && (
                          <Button variant="ghost" size="sm" onClick={() => { setConfirmId(incident.id); setConfirmAction('acknowledge') }}>
                            Acknowledge
                          </Button>
                        )}
                        {(incident.status === 'open' || incident.status === 'acknowledged') && (
                          <Button variant="ghost" size="sm" onClick={() => { setConfirmId(incident.id); setConfirmAction('resolve') }}>
                            Resolve
                          </Button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {totalPages > 1 && (
            <div className="flex items-center justify-between border-t border-border-card px-4 py-2.5">
              <span className="text-[11px] text-text-muted">Showing first {PAGE_SIZE} of {filtered.length}</span>
            </div>
          )}
        </Panel>
      )}

      {viewingId != null && (
        <IncidentDetailDrawer
          incidentId={viewingId}
          onClose={() => setViewingId(null)}
          onStatusChange={() => { setViewingId(null); refetch() }}
        />
      )}

      <Dialog
        open={confirmId != null}
        onClose={() => (acknowledgeIncident.pending || resolveIncident.pending ? null : setConfirmId(null))}
        title={
          confirmAction === 'acknowledge'
            ? 'Acknowledge this incident?'
            : 'Resolve this incident?'
        }
        description={
          confirmAction === 'acknowledge'
            ? `Incident #${confirmId} will be marked as acknowledged.`
            : `Incident #${confirmId} will be marked as resolved. Resolved incidents cannot be reopened from the dashboard.`
        }
        destructive={confirmAction === 'resolve'}
        footer={
          <>
            <Button variant="ghost" size="sm" onClick={() => setConfirmId(null)} disabled={acknowledgeIncident.pending || resolveIncident.pending}>
              Cancel
            </Button>
            <Button
              variant={confirmAction === 'resolve' ? 'danger' : 'outline'}
              size="sm"
              onClick={handleAction}
              loading={acknowledgeIncident.pending || resolveIncident.pending}
            >
              {confirmAction === 'acknowledge' ? 'Mark as acknowledged' : 'Mark as resolved'}
            </Button>
          </>
        }
      >
        {(acknowledgeIncident.error || resolveIncident.error) && (
          <p className="text-xs text-[#fca5a5]">{describeApiError(acknowledgeIncident.error || resolveIncident.error)}</p>
        )}
      </Dialog>
    </div>
  )
}
