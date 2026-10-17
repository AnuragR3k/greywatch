// Collapsible navigation rail.
//
// Desktop (>= lg): persistent rail, 240px expanded / 64px collapsed.
// Below lg: off-canvas drawer revealed from the toolbar's menu button.
// Nav config comes from app/routes.js so labels, order, and icons live once.

import { ChevronLeft, ChevronRight, Home } from 'lucide-react'
import { cn } from '@/lib/utils'
import { StatusDot } from '@/components/ui/StatusDot'
import { Tooltip } from '@/components/ui/Tooltip'

const API_LABEL = {
  healthy: 'API online',
  unavailable: 'API unavailable',
  unknown: 'Checking API…',
}

export function Sidebar({
  navItems,
  activePath,
  collapsed,
  onCollapse,
  onNavigate,
  openAlerts = 0,
  apiState = 'unknown',
  mobileOpen = false,
  onMobileClose,
}) {
  return (
    <aside
      className={cn(
        'z-40 flex h-full w-64 shrink-0 flex-col border-r border-border-card bg-[#0b0f13]/95 backdrop-blur-md transition-transform duration-300 ease-out',
        'max-lg:fixed max-lg:inset-y-0 max-lg:left-0',
        mobileOpen ? 'max-lg:translate-x-0' : 'max-lg:-translate-x-full',
        'lg:translate-x-0',
        collapsed ? 'lg:w-16' : 'lg:w-60',
      )}
      aria-label="Main navigation"
    >
      {/* Brand */}
      <div className={cn('flex h-14 items-center border-b border-border-card', collapsed ? 'justify-center px-2' : 'gap-2.5 px-4')}>
        <button
          type="button"
          onClick={() => onCollapse(!collapsed)}
          className="flex items-center gap-2.5 rounded-md"
          aria-label={collapsed ? 'Expand navigation' : 'Collapse navigation'}
          title={collapsed ? 'Expand navigation' : 'Collapse navigation'}
        >
          <BrandMark />
          {!collapsed && <span className="text-sm font-semibold tracking-tight text-text-primary">Greywatch</span>}
        </button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-0.5 overflow-y-auto px-2 py-3" aria-label="Sections">
        {navItems.map((item) => {
          const isActive = item.path === activePath
          const alertCount = item.key === 'alerts' ? openAlerts : 0
          const button = (
            <button
              type="button"
              onClick={() => onNavigate(item.path)}
              aria-current={isActive ? 'page' : undefined}
              className={cn(
                'flex w-full items-center rounded-md text-sm font-medium transition-colors',
                collapsed ? 'justify-center px-2 py-2.5' : 'gap-3 px-3 py-2.5',
                isActive
                  ? 'bg-accent/10 text-[#6ee7b7] ring-1 ring-inset ring-accent/25'
                  : 'text-text-secondary hover:bg-card-hover hover:text-text-primary',
              )}
            >
              <item.icon size={16} className="shrink-0" aria-hidden="true" />
              {!collapsed && (
                <>
                  <span className="flex-1 truncate text-left">{item.label}</span>
                  {alertCount > 0 && (
                    <span className="flex h-5 min-w-[20px] shrink-0 items-center justify-center rounded-full bg-severity-medium/15 px-1.5 font-mono text-[10px] font-semibold text-severity-medium">
                      {alertCount > 99 ? '99+' : alertCount}
                    </span>
                  )}
                </>
              )}
            </button>
          )
          return (
            <div key={item.key}>
              {collapsed ? (
                <Tooltip label={item.label} className="block w-full">{button}</Tooltip>
              ) : (
                button
              )}
            </div>
          )
        })}
      </nav>

      {/* Footer: API mode + collapse control */}
      <div className="shrink-0 border-t border-border-card px-2 py-3">
        {!collapsed && (
          <div className="mb-2 rounded-md border border-border-card bg-white/[0.02] px-3 py-2.5">
            <div className="flex items-center gap-2">
              <StatusDot tone={apiState} />
              <span className="text-[11.5px] font-semibold text-text-secondary">{API_LABEL[apiState] || API_LABEL.unknown}</span>
            </div>
            <div className="mt-1 font-mono text-[10px] leading-relaxed text-text-muted">loopback auth · v0.1.0</div>
          </div>
        )}
        {!collapsed && (
          <a
            href="#/"
            onClick={onMobileClose}
            className="mb-1 flex w-full items-center gap-2 rounded-md px-3 py-2 text-xs font-medium text-text-secondary transition-colors hover:bg-card-hover hover:text-text-primary"
          >
            <Home size={14} aria-hidden="true" />
            Product site
          </a>
        )}
        <button
          type="button"
          onClick={() => onCollapse(!collapsed)}
          aria-label={collapsed ? 'Expand navigation' : 'Collapse navigation'}
          className={cn(
            'flex w-full items-center rounded-md px-3 py-2 text-xs font-medium text-text-secondary transition-colors hover:bg-card-hover hover:text-text-primary',
            collapsed ? 'justify-center' : 'gap-2',
          )}
        >
          {collapsed ? <ChevronRight size={14} aria-hidden="true" /> : <ChevronLeft size={14} aria-hidden="true" />}
          {!collapsed && <span>Collapse</span>}
        </button>
      </div>
    </aside>
  )
}

function BrandMark() {
  return (
    <svg width="24" height="24" viewBox="0 0 32 32" fill="none" aria-hidden="true">
      <path d="M16 2.5 27 7v9.2c0 6.3-4.4 10.9-11 13.3C9.4 27.1 5 22.5 5 16.2V7L16 2.5Z" fill="#0E1512" stroke="#34d399" strokeWidth="1.6" strokeLinejoin="round" />
      <path d="M16 10.5c3.4 0 5.6 2.2 6.4 5.5-.8 3.3-3 5.5-6.4 5.5S10.4 19.3 9.6 16c.8-3.3 3-5.5 6.4-5.5Z" stroke="#34d399" strokeWidth="1.5" />
      <circle cx="16" cy="16" r="2.3" fill="#a3e635" />
    </svg>
  )
}
