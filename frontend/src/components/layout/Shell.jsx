// Application shell: fixed-width sidebar + flexible main column.
//
// Layout contract (verified by measurement at 1440/1920/320):
//   * the sidebar is a fixed ~240px rail on desktop and an off-canvas drawer
//     below the lg breakpoint;
//   * the main column is `flex-1 min-w-0` and takes ALL remaining width — there
//     is deliberately no max-width on the shell or the dashboard content;
//   * the toolbar spans the full main column and the content scrolls beneath.

import { useCallback, useState } from 'react'
import { ErrorBoundary } from '@/components/ui/ErrorBoundary'
import { Sidebar } from './Sidebar'
import { TopBar } from './TopBar'

export function Shell({
  navItems,
  activePath,
  onNavigate,
  title,
  subtitle,
  openAlerts = 0,
  apiState = 'unknown',
  onRefresh,
  refreshing = false,
  children,
}) {
  const [collapsed, setCollapsed] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)

  const handleNavigate = useCallback((path) => {
    onNavigate(path)
    setMobileOpen(false)
  }, [onNavigate])

  return (
    <div className="flex h-screen w-full overflow-hidden bg-background text-text-primary">
      <Sidebar
        navItems={navItems}
        activePath={activePath}
        collapsed={collapsed}
        onCollapse={setCollapsed}
        onNavigate={handleNavigate}
        openAlerts={openAlerts}
        apiState={apiState}
        mobileOpen={mobileOpen}
        onMobileClose={() => setMobileOpen(false)}
      />

      {mobileOpen && (
        <button
          type="button"
          aria-label="Close navigation"
          onClick={() => setMobileOpen(false)}
          className="fixed inset-0 z-30 bg-black/60 backdrop-blur-sm lg:hidden"
        />
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar
          title={title}
          subtitle={subtitle}
          apiState={apiState}
          onRefresh={onRefresh}
          refreshing={refreshing}
          onMenuToggle={() => setMobileOpen((o) => !o)}
          mobileOpen={mobileOpen}
        />
        <main className="min-w-0 flex-1 overflow-y-auto">
          {/* No max-width: the dashboard content uses the full main width. */}
          <div className="w-full p-4 lg:p-6">
            <ErrorBoundary>{children}</ErrorBoundary>
          </div>
        </main>
      </div>
    </div>
  )
}
