// KPI grid. Values come from real data; an unavailable metric renders "—"
// (never 0), and a first load renders a skeleton.

import { Activity, ShieldAlert, ShieldCheck, Siren } from 'lucide-react'
import { Panel } from '@/components/ui/Panel'
import { Skeleton } from '@/components/ui/Skeleton'
import { CountUp } from '@/components/motion/CountUp'
import { cn } from '@/lib/utils'

function KpiCard({ icon: Icon, label, subtitle, metric, accent }) {
  return (
    <Panel className="p-4">
      <div className="flex items-start gap-3">
        <span className={cn('flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-raised', accent)}>
          <Icon size={16} aria-hidden="true" />
        </span>
        <div className="min-w-0 flex-1">
          <p className="text-[11px] font-medium uppercase tracking-wider text-text-muted">{label}</p>
          {metric.loading ? (
            <Skeleton className="mt-1.5 h-7 w-16" />
          ) : (
            <p className="mt-0.5 text-2xl font-semibold leading-none tracking-tight text-text-primary">
              <CountUp value={metric.value} fallback="—" />
            </p>
          )}
          <p className="mt-1 truncate text-[11px] text-text-muted">
            {metric.unavailable ? 'Unavailable — API did not respond' : subtitle}
          </p>
        </div>
      </div>
    </Panel>
  )
}

export function KpiGrid({ metrics }) {
  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
      <KpiCard icon={Activity} label="Total events" subtitle="Most recent 200 events" metric={metrics.totalEvents} accent="text-severity-info" />
      <KpiCard icon={ShieldAlert} label="Open alerts" subtitle="Requiring investigation" metric={metrics.openAlerts} accent="text-severity-medium" />
      <KpiCard icon={Siren} label="High severity" subtitle="Open high / critical alerts" metric={metrics.highSeverity} accent="text-severity-critical" />
      <KpiCard icon={ShieldCheck} label="Active detections" subtitle="Distinct rules firing" metric={metrics.detections} accent="text-accent" />
    </div>
  )
}
