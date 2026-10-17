// Recent alerts — a compact severity-aware table. Every value is real; missing
// fields show "—". Links into the full alerts view and its investigation drawer.

import { ShieldAlert } from 'lucide-react'
import { Panel, PanelHeader, RefreshButton } from '@/components/ui/Panel'
import { SeverityBadge, StatusBadge } from '@/components/ui/Badge'
import { EmptyState, ErrorState } from '@/components/ui/State'
import { Skeleton } from '@/components/ui/Skeleton'
import { describeApiError } from '@/lib/api/errors'
import { formatCompact } from '@/lib/format/datetime'
import { alertNetworkSummary, alertRuleLabel, formatHost, isSuricataAlert } from '@/lib/format/telemetry'

export function RecentAlerts({ alerts, loading, error, onRetry, limit = 6 }) {
  const rows = (alerts || []).slice(0, limit)

  if (loading) {
    return (
      <Panel>
        <PanelHeader title="Recent alerts" icon={ShieldAlert} />
        <div className="space-y-1 p-4">
          {Array.from({ length: limit }).map((_, i) => <Skeleton key={i} className="h-9 w-full" />)}
        </div>
      </Panel>
    )
  }

  if (error) {
    return (
      <Panel>
        <PanelHeader title="Recent alerts" icon={ShieldAlert} />
        <ErrorState title="Alerts unavailable" message={describeApiError(error)} onRetry={onRetry} />
      </Panel>
    )
  }

  if (rows.length === 0) {
    return (
      <Panel>
        <PanelHeader title="Recent alerts" icon={ShieldAlert} actions={<RefreshButton onClick={onRetry} />} />
        <EmptyState title="No alerts" description="Alerts appear here when a detection rule fires." />
      </Panel>
    )
  }

  return (
    <Panel>
      <PanelHeader
        title="Recent alerts"
        icon={ShieldAlert}
        actions={
          <>
            <a href="#/dashboard/alerts" className="text-[11px] font-medium text-[#6ee7b7] hover:text-accent">View all</a>
            <RefreshButton onClick={onRetry} />
          </>
        }
      />
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-border-card text-left text-[10px] uppercase tracking-wider text-text-muted">
              <th className="px-4 py-2 font-semibold">Sev</th>
              <th className="px-2 py-2 font-semibold">Alert / rule</th>
              <th className="hidden px-2 py-2 font-semibold md:table-cell">Source</th>
              <th className="px-2 py-2 font-semibold">Time</th>
              <th className="px-4 py-2 font-semibold">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border-card">
            {rows.map((alert) => {
              const net = isSuricataAlert(alert) ? alertNetworkSummary(alert) : null
              return (
                <tr key={alert.id} className="align-top hover:bg-card-hover/50">
                  <td className="px-4 py-2.5"><SeverityBadge severity={alert.severity || 'unknown'} /></td>
                  <td className="px-2 py-2.5">
                    <div className="max-w-[24rem] truncate font-medium text-text-primary" title={alert.title || alertRuleLabel(alert.rule_id)}>
                      {alert.title || alertRuleLabel(alert.rule_id)}
                    </div>
                    <div className="truncate text-[10px] text-text-muted">
                      {alertRuleLabel(alert.rule_id)}{net ? ` · ${net}` : ''}
                    </div>
                  </td>
                  <td className="hidden px-2 py-2.5 md:table-cell">
                    <span className="font-mono text-[11px] text-text-secondary">{formatHost(alert.source_ip)}</span>
                  </td>
                  <td className="px-2 py-2.5">
                    <span className="font-mono text-[11px] text-text-secondary">{formatCompact(alert.last_triggered_at || alert.created_at)}</span>
                  </td>
                  <td className="px-4 py-2.5"><StatusBadge status={alert.status || 'unknown'} /></td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </Panel>
  )
}
