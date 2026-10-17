// Dashboard toolbar. Every control here is functional: the menu button toggles
// the mobile drawer, the status pill reflects real API reachability, and
// Refresh re-fetches every mounted section via the `gw-refresh` event.

import { Menu, RefreshCw } from 'lucide-react'
import { GithubIcon } from '@/components/icons/GithubIcon'
import { cn } from '@/lib/utils'
import { StatusDot } from '@/components/ui/StatusDot'
import { Button } from '@/components/ui/Button'

const GITHUB_URL = 'https://github.com/AnuragR3k/greywatch'

const API_LABEL = {
  healthy: 'API online',
  unavailable: 'API unreachable',
  unknown: 'Connecting…',
}

export function TopBar({ title, subtitle, apiState, onRefresh, refreshing, onMenuToggle, mobileOpen }) {
  return (
    <header className="sticky top-0 z-30 border-b border-border-card bg-background/80 backdrop-blur-md">
      <div className="flex items-center gap-3 px-4 py-3">
        <button
          type="button"
          onClick={onMenuToggle}
          aria-label={mobileOpen ? 'Close navigation' : 'Open navigation'}
          aria-expanded={mobileOpen}
          className="flex h-9 w-9 items-center justify-center rounded-md text-text-primary hover:bg-card-hover lg:hidden"
        >
          <Menu size={18} />
        </button>

        <div className="min-w-0 flex-1">
          <h1 className="truncate text-sm font-semibold tracking-wide text-text-primary">{title}</h1>
          {subtitle && <p className="truncate text-[11px] text-text-muted">{subtitle}</p>}
        </div>

        <div className="flex items-center gap-2">
          <div className="hidden items-center gap-2 rounded-md border border-border-card bg-card px-2.5 py-1.5 sm:flex">
            <StatusDot tone={apiState} pulse={apiState === 'healthy'} />
            <span className="text-[11px] font-medium text-text-secondary">{API_LABEL[apiState] || API_LABEL.unknown}</span>
          </div>

          <Button variant="outline" size="sm" onClick={onRefresh} disabled={refreshing} aria-label="Refresh telemetry">
            <RefreshCw size={13} className={cn(refreshing && 'animate-spin')} aria-hidden="true" />
            <span className="hidden sm:inline">{refreshing ? 'Refreshing' : 'Refresh'}</span>
          </Button>

          <a
            href={GITHUB_URL}
            target="_blank"
            rel="noreferrer"
            aria-label="Greywatch on GitHub"
            title="Greywatch on GitHub"
            className="flex h-8 w-8 items-center justify-center rounded-md border border-border-card text-text-secondary hover:bg-card-hover hover:text-text-primary"
          >
            <GithubIcon size={14} />
          </a>
        </div>
      </div>
    </header>
  )
}
