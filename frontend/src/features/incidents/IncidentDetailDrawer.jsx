// Incident investigation drawer: the incident record plus its related events
// (GET /api/v1/incidents/{id}) shown in chronological order.
import { useCallback, useState } from 'react'
import { useIncidentDetail, useAcknowledgeIncident, useResolveIncident } from '@/hooks/useTelemetry'
import { Drawer } from '@/components/ui/Drawer'
import { Button } from '@/components/ui/Button'
import { Dialog } from '@/components/ui/Dialog'
import { FieldGrid } from '@/components/ui/Field'
import { Badge, SeverityBadge, StatusBadge } from '@/components/ui/Badge'
import { ErrorState } from '@/components/ui/State'
import { Skeleton } from '@/components/ui/Skeleton'
import { describeApiError } from '@/lib/api/errors'
import { formatDateTime } from '@/lib/format/datetime'
import { categorizeEvent, eventPreview, eventSourceLabel, eventSourceTone, incidentRuleLabel } from '@/lib/format/telemetry'

export function IncidentDetailDrawer({ incidentId, onClose, onStatusChange }) {
  const { data, loading, error, refetch } = useIncidentDetail(incidentId)
  const acknowledgeIncident = useAcknowledgeIncident()
  const resolveIncident = useResolveIncident()
  const [confirming, setConfirming] = useState(false)
  const [confirmAction, setConfirmAction] = useState(null)

  const incident = data
  const related = Array.isArray(data?.related_events) ? data.related_events : []

  const handleAction = useCallback(async () => {
    if (incidentId == null || !confirmAction) return
    const result =
      confirmAction === 'acknowledge'
        ? await acknowledgeIncident.execute(incidentId)
        : await resolveIncident.execute(incidentId)
    if (result) {
      setConfirming(false)
      setConfirmAction(null)
      onStatusChange?.()
      refetch()
    }
  }, [incidentId, confirmAction, acknowledgeIncident, resolveIncident, onStatusChange, refetch])

  return (
    <Drawer
      open
      onClose={onClose}
      title={incident?.title || `Incident #${incidentId}`}
      subtitle={incident ? `${incidentRuleLabel(incident.rule_id)} · #${incident.id}` : 'Loading incident…'}
      footer={
        incident ? (
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <SeverityBadge severity={incident.severity || 'unknown'} />
              <StatusBadge status={incident.status || 'unknown'} />
            </div>
            {incident.status === 'open' && (
              <>
                <Button variant="ghost" size="sm" onClick={() => { setConfirmAction('acknowledge'); setConfirming(true) }}>
                  Acknowledge
                </Button>
                <Button variant="ghost" size="sm" onClick={() => { setConfirmAction('resolve'); setConfirming(true) }}>
                  Resolve
                </Button>
              </>
            )}
            {incident.status === 'acknowledged' && (
              <Button variant="ghost" size="sm" onClick={() => { setConfirmAction('resolve'); setConfirming(true) }}>
                Resolve
              </Button>
            )}
          </div>
        ) : null
      }
    >
      {loading && !data ? (
        <div className="space-y-3">
          <Skeleton className="h-4 w-1/2" />
          <Skeleton className="h-24 w-full" />
          <Skeleton className="h-24 w-full" />
        </div>
      ) : error && !data ? (
        <ErrorState title="Could not load incident" message={describeApiError(error)} onRetry={refetch} />
      ) : incident ? (
        <div className="flex flex-col gap-5">
          {incident.description && (
            <p className="rounded-md border border-border-card bg-background/40 p-3 text-xs leading-relaxed text-text-secondary">
              {incident.description}
            </p>
          )}

          <FieldGrid fields={[
            { label: 'Incident ID', value: `#${incident.id}`, mono: true },
            { label: 'Rule', value: incidentRuleLabel(incident.rule_id) },
            { label: 'Rule ID', value: incident.rule_id, mono: true },
            { label: 'Severity', value: incident.severity },
            { label: 'Status', value: incident.status },
            { label: 'Source IP', value: incident.source_ip, mono: true },
            { label: 'Event count', value: incident.event_count },
            { label: 'First seen', value: incident.first_seen_at, mono: true },
            { label: 'Last seen', value: incident.last_seen_at, mono: true },
            { label: 'Created at', value: incident.created_at, mono: true },
            { label: 'Resolved at', value: incident.closed_at, mono: true },
          ]} />

          <div>
            <div className="mb-2 flex items-center justify-between">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-text-muted">
                Related events ({related.length})
              </h3>
            </div>
            {related.length === 0 ? (
              <p className="rounded-md border border-border-card bg-background/40 p-3 text-xs text-text-muted">
                No related events recorded for this incident.
              </p>
            ) : (
              <ul className="flex flex-col gap-2">
                {related.map((ev) => {
                  const cat = categorizeEvent(ev.event_type)
                  return (
                    <li key={ev.id} className="rounded-md border border-border-card bg-background/40 p-3">
                      <div className="mb-1.5 flex flex-wrap items-center gap-2">
                        <span className="font-mono text-[11px] text-text-secondary">{formatDateTime(ev.timestamp)}</span>
                        <Badge tone={eventSourceTone(ev.source)}>{eventSourceLabel(ev.source)}</Badge>
                        <Badge tone={cat.tone === 'critical' ? 'critical' : 'info'}>{cat.category}</Badge>
                      </div>
                      <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-words font-mono text-[11px] leading-relaxed text-text-secondary">{eventPreview(ev)}</pre>
                    </li>
                  )
                })}
              </ul>
            )}
          </div>
        </div>
      ) : null}

      <Dialog
        open={confirming}
        onClose={() => (acknowledgeIncident.pending || resolveIncident.pending ? null : setConfirming(false))}
        title={confirmAction === 'acknowledge' ? 'Acknowledge this incident?' : 'Resolve this incident?'}
        description={
          confirmAction === 'acknowledge'
            ? `Incident #${incidentId} will be marked as acknowledged.`
            : `Incident #${incidentId} will be marked as resolved. Resolved incidents cannot be reopened from the dashboard.`
        }
        destructive={confirmAction === 'resolve'}
        footer={
          <>
            <Button variant="ghost" size="sm" onClick={() => setConfirming(false)} disabled={acknowledgeIncident.pending || resolveIncident.pending}>
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
    </Drawer>
  )
}
