// Settings — reports live configuration state exposed by the API and documents
// the trust boundary. There is no remote settings API; nothing here is editable.

import { Server, Settings as SettingsIcon, ShieldCheck } from 'lucide-react'
import { useHealth, useJournalStatus, useSuricataStatus } from '@/hooks/useTelemetry'
import { Panel, PanelHeader, RefreshButton } from '@/components/ui/Panel'
import { Badge } from '@/components/ui/Badge'

import { Skeleton } from '@/components/ui/Skeleton'
import { describeApiError } from '@/lib/api/errors'

function Row({ label, value, tone, hint }) {
  return (
    <div className="flex flex-col gap-1 border-b border-border-card/60 py-3 last:border-b-0">
      <div className="flex items-center gap-2">
        <span className="text-xs font-medium text-text-primary">{label}</span>
        {tone && <Badge tone={tone}>{value}</Badge>}
        {!tone && value && <span className="font-mono text-xs text-text-secondary">{value}</span>}
      </div>
      {hint && <p className="text-[11px] leading-relaxed text-text-muted">{hint}</p>}
    </div>
  )
}

export function SettingsPage() {
  const health = useHealth()
  const journal = useJournalStatus()
  const suricata = useSuricataStatus()

  const apiBadge = health.error
    ? { tone: 'unavailable', label: 'Unavailable' }
    : health.loading && health.data == null
      ? { tone: 'unknown', label: 'Checking…' }
      : health.data?.status === 'ok'
        ? { tone: 'healthy', label: 'Online' }
        : { tone: 'unavailable', label: 'Unreachable' }

  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
      <Panel>
        <PanelHeader title="API service" subtitle="GET /health (public liveness probe)" icon={Server} />
        <div className="p-4">
          {health.loading && !health.data ? (
            <Skeleton className="h-20 w-full" />
          ) : (
            <>
              <Row
                label="Status"
                tone={apiBadge.tone}
                value={apiBadge.label}
                hint={health.error ? describeApiError(health.error) : 'Reflects API reachability only — it does not imply collectors are healthy.'}
              />
              <Row label="Service" value={health.data?.service || 'greywatch-api'} />
              <Row label="Version" value={health.data?.version || '—'} />
            </>
          )}
        </div>
      </Panel>

      <Panel>
        <PanelHeader title="Integrations" subtitle="Enabled flags reported by the collector status endpoints" icon={SettingsIcon} />
        <div className="p-4">
          <Row
            label="systemd journal"
            tone={journal.data?.enabled ? 'healthy' : 'disabled'}
            value={journal.loading && !journal.data ? 'Checking…' : journal.data?.enabled ? 'Enabled' : 'Disabled'}
            hint="GREYWATCH_JOURNAL_ENABLED"
          />
          <Row
            label="Suricata EVE"
            tone={suricata.data?.enabled ? 'healthy' : 'disabled'}
            value={suricata.loading && !suricata.data ? 'Checking…' : suricata.data?.enabled ? 'Enabled' : 'Disabled'}
            hint="GREYWATCH_SURICATA_ENABLED"
          />
          <Row label="EVE path" value={suricata.data?.eve_path || '—'} hint="GREYWATCH_SURICATA_EVE_PATH" />
        </div>
      </Panel>

      <Panel className="xl:col-span-2">
        <PanelHeader
          title="API trust boundary"
          subtitle="Documented behaviour (README → API Security)"
          icon={ShieldCheck}
          actions={<RefreshButton onClick={() => { health.refetch(); journal.refetch(); suricata.refetch() }} />}
        />
        <div className="p-4">
          <Row
            label="Local mode"
            value="Loopback only"
            hint="When GREYWATCH_API_TOKEN is unset, only 127.0.0.1 / ::1 peers may call non-public endpoints. Unknown peers are rejected."
          />
          <Row label="Token authentication" value="Authorization: Bearer <token> or X-API-Key" hint="Configure GREYWATCH_API_TOKEN for remote access. Requests with missing or invalid credentials are rejected." />
          <Row label="Rate limiting" value="Token bucket per client" hint="Protected endpoints are rate limited after authentication. 429 responses include Retry-After." />
          <Row label="Request body limit" value="GREYWATCH_MAX_REQUEST_BYTES (default 1 MiB)" hint="Oversized bodies are rejected with 413 before being buffered." />
          <Row label="Remote dashboard" value="Reverse proxy required" hint="A static client cannot hold a server-side secret; remote dashboards must terminate authentication at a reverse proxy." />
        </div>
      </Panel>
    </div>
  )
}
