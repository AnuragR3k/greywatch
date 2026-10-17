// Alert investigation drawer: the alert record plus its evidence events
// (GET /api/v1/alerts/{id}). Resolution delegates to the parent on success.

import { useState } from 'react'
import { useAlertDetail, useCloseAlert } from '@/hooks/useTelemetry'
import { Drawer } from '@/components/ui/Drawer'
import { Button } from '@/components/ui/Button'
import { Dialog } from '@/components/ui/Dialog'
import { FieldGrid } from '@/components/ui/Field'
import { SeverityBadge, StatusBadge, Badge } from '@/components/ui/Badge'
import { ErrorState } from '@/components/ui/State'
import { Skeleton } from '@/components/ui/Skeleton'
import { describeApiError } from '@/lib/api/errors'
import { formatClock, formatDateTime } from '@/lib/format/datetime'
import { alertDetailFields, alertRuleLabel, categorizeEvent, eventPreview, eventSourceLabel, eventSourceTone } from '@/lib/format/telemetry'

export function AlertDetailDrawer({ alertId, onClose, onResolved }) {
  const { data, loading, error, refetch } = useAlertDetail(alertId)
  const closeAlert = useCloseAlert()
  const [confirming, setConfirming] = useState(false)

  const alert = data?.alert
  const evidence = Array.isArray(data?.evidence_events) ? data.evidence_events : []

  const handleResolve = async () => {
    const result = await closeAlert.execute(alertId)
    if (result) {
      setConfirming(false)
      onResolved?.()
    }
  }

  return (
    <Drawer
      open
      onClose={onClose}
      title={alert?.title || `Alert #${alertId}`}
      subtitle={alert ? `${alertRuleLabel(alert.rule_id)} · #${alert.id}` : 'Loading alert…'}
      footer={
        alert ? (
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <SeverityBadge severity={alert.severity || 'unknown'} />
              <StatusBadge status={alert.status || 'unknown'} />
            </div>
            {alert.status === 'open' && (
              <Button variant="danger" size="sm" onClick={() => setConfirming(true)}>Resolve alert</Button>
            )}
          </div>
        ) : null
      }
    >
      {loading && !data ? (
        <div className="space-y-3"><Skeleton className="h-4 w-1/2" /><Skeleton className="h-24 w-full" /><Skeleton className="h-24 w-full" /></div>
      ) : error && !data ? (
        <ErrorState title="Could not load alert" message={describeApiError(error)} onRetry={refetch} />
      ) : alert ? (
        <div className="flex flex-col gap-5">
          {alert.description && (
            <p className="rounded-md border border-border-card bg-background/40 p-3 text-xs leading-relaxed text-text-secondary">{alert.description}</p>
          )}

          <FieldGrid fields={alertDetailFields(alert)} />

          <div>
            <div className="mb-2 flex items-center justify-between">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-text-muted">Evidence</h3>
              <span className="text-[10px] text-text-muted">
                {data.evidence_window_start && data.evidence_window_end
                  ? `${formatClock(data.evidence_window_start)} → ${formatClock(data.evidence_window_end)}`
                  : `${evidence.length} event${evidence.length === 1 ? '' : 's'}`}
              </span>
            </div>
            {evidence.length === 0 ? (
              <p className="rounded-md border border-border-card bg-background/40 p-3 text-xs text-text-muted">No evidence events in this window.</p>
            ) : (
              <ul className="flex flex-col gap-2">
                {evidence.map((ev) => {
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
        onClose={() => (closeAlert.pending ? null : setConfirming(false))}
        title="Resolve this alert?"
        description="The alert will be marked resolved on the server. This cannot be undone from the dashboard."
        destructive
        footer={
          <>
            <Button variant="ghost" size="sm" onClick={() => setConfirming(false)} disabled={closeAlert.pending}>Cancel</Button>
            <Button variant="danger" size="sm" onClick={handleResolve} loading={closeAlert.pending}>Mark as resolved</Button>
          </>
        }
      >
        {closeAlert.error && <p className="text-xs text-[#fca5a5]">{describeApiError(closeAlert.error)}</p>}
      </Dialog>
    </Drawer>
  )
}
