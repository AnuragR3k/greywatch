// Suricata collector page.

import { Radar } from 'lucide-react'
import { useState } from 'react'
import { useSuricataStatus, useCollectSuricata } from '@/hooks/useTelemetry'
import { Panel, PanelHeader } from '@/components/ui/Panel'
import { ErrorState } from '@/components/ui/State'
import { CollectorPanel } from './CollectorPanel'

export function SuricataPage() {
  const { data: status, loading, error, refetch } = useSuricataStatus()
  const collect = useCollectSuricata()
  const [result, setResult] = useState(null)

  const handleCollect = async () => {
    setResult(null)
    const res = await collect.execute()
    if (res) setResult(res)
    refetch()
  }

  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
      <div className="flex flex-col gap-4">
        {error && !status ? (
          <Panel><ErrorState title="Suricata status unavailable" message="Could not reach /api/v1/suricata/status." onRetry={refetch} /></Panel>
        ) : (
          <CollectorPanel
            title="suricata eve"
            subtitle="Network IDS / IPS telemetry from EVE JSON"
            status={status}
            loading={loading}
            error={error}
            onRetry={refetch}
            onCollect={handleCollect}
            collecting={collect.pending}
            collectError={collect.error}
            collectResult={result}
            evePath
            disabledHint="Continuous collection is controlled by GREYWATCH_SURICATA_ENABLED. A missing or unreadable EVE file is reported as an error below, not as a healthy state."
          />
        )}
      </div>

      <Panel>
        <PanelHeader title="About this integration" icon={Radar} />
        <div className="flex flex-col gap-3 p-4 text-xs leading-relaxed text-text-secondary">
          <p>
            Greywatch tails the Suricata EVE JSON file by byte offset with rotation-safe
            de-duplication. Ingested records are stored as <span className="font-mono text-text-primary">source=suricata</span>.
          </p>
          <p>Suricata collection is <span className="text-text-primary">disabled by default</span> and enabled only with <span className="font-mono text-text-primary">GREYWATCH_SURICATA_ENABLED</span>.</p>
          <div>
            <div className="mb-1.5 text-[10px] uppercase tracking-wider text-text-muted">Supported EVE categories</div>
            <ul className="space-y-1 font-mono text-text-primary">
              <li>suricata_alert · suricata_dns</li>
              <li>suricata_http · suricata_tls</li>
              <li>suricata_flow</li>
            </ul>
          </div>
          <p>IDS <span className="font-mono text-text-primary">alert</span> records raise Greywatch detection-rule alerts (<span className="font-mono text-text-primary">SURICATA_ALERT</span>) with signature evidence; other categories remain events.</p>
        </div>
      </Panel>
    </div>
  )
}
