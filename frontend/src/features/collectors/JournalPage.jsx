// Journal collector page.

import { BookLock } from 'lucide-react'
import { useState } from 'react'
import { useJournalStatus, useCollectJournal } from '@/hooks/useTelemetry'
import { Panel, PanelHeader } from '@/components/ui/Panel'
import { ErrorState } from '@/components/ui/State'
import { CollectorPanel } from './CollectorPanel'

export function JournalPage() {
  const { data: status, loading, error, refetch } = useJournalStatus()
  const collect = useCollectJournal()
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
          <Panel><ErrorState title="Journal status unavailable" message="Could not reach /api/v1/journal/status." onRetry={refetch} /></Panel>
        ) : (
          <CollectorPanel
            title="systemd journal"
            subtitle="PAM, SSH, and sudo authentication events"
            status={status}
            loading={loading}
            error={error}
            onRetry={refetch}
            onCollect={handleCollect}
            collecting={collect.pending}
            collectError={collect.error}
            collectResult={result}
            disabledHint="Continuous collection is controlled by GREYWATCH_JOURNAL_ENABLED. The manual action runs exactly one cycle regardless of that flag."
          />
        )}
      </div>

      <Panel>
        <PanelHeader title="About this integration" icon={BookLock} />
        <div className="flex flex-col gap-3 p-4 text-xs leading-relaxed text-text-secondary">
          <p>
            Greywatch reads authentication events straight from the systemd journal
            (<code className="font-mono text-text-primary">journalctl -o json</code>) using a
            cursor-based checkpoint, so restarts never re-ingest or lose position.
          </p>
          <p>The collector is <span className="text-text-primary">disabled by default</span> and stores events as <span className="font-mono text-text-primary">source=journal</span>.</p>
          <div>
            <div className="mb-1.5 text-[10px] uppercase tracking-wider text-text-muted">Normalized event types</div>
            <ul className="space-y-1">
              <li className="font-mono text-text-primary">ssh_login_failed · ssh_invalid_user · ssh_login_success</li>
              <li className="font-mono text-text-primary">sudo_command · sudo_session_opened / closed</li>
              <li className="font-mono text-text-primary">pam_auth_failed</li>
            </ul>
          </div>
          <p>Failed SSH logins are evaluated by the SSH brute-force detection rule.</p>
        </div>
      </Panel>
    </div>
  )
}
