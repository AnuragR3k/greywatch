// Dashboard container: owns shell-level state (open-alert badge, API status,
// refresh) and renders the view for the current route.

import { useCallback, useMemo, useState } from 'react'
import { Shell } from '@/components/layout/Shell'
import { NAV_ITEMS, navItemForPath } from './routes'
import { useAlerts, useHealth } from '@/hooks/useTelemetry'
import { OverviewPage } from '@/features/overview/OverviewPage'
import { AlertsPage } from '@/features/alerts/AlertsPage'
import { IncidentsPage } from '@/features/incidents/IncidentsPage'
import { EventsPage } from '@/features/events/EventsPage'
import { JournalPage } from '@/features/collectors/JournalPage'
import { SuricataPage } from '@/features/collectors/SuricataPage'
import { SettingsPage } from '@/features/settings/SettingsPage'

function renderView(path, onNavigate) {
  if (path.startsWith('/dashboard/alerts')) return <AlertsPage />
  if (path.startsWith('/dashboard/incidents')) return <IncidentsPage />
  if (path.startsWith('/dashboard/events')) return <EventsPage />
  if (path.startsWith('/dashboard/journal')) return <JournalPage />
  if (path.startsWith('/dashboard/suricata')) return <SuricataPage />
  if (path.startsWith('/dashboard/settings')) return <SettingsPage />
  return <OverviewPage onNavigate={onNavigate} />
}

export function Dashboard({ path, navigate }) {
  const [refreshing, setRefreshing] = useState(false)

  // Shared, de-duplicated reads: the open-alert badge and the API status pill.
  const { data: alerts } = useAlerts({ status: 'all', limit: 100 })
  const { data: health, loading: healthLoading } = useHealth()

  const openAlerts = useMemo(
    () => (alerts ? alerts.filter((a) => a.status === 'open').length : 0),
    [alerts],
  )

  const apiState = health?.status === 'ok'
    ? 'healthy'
    : healthLoading && health == null
      ? 'unknown'
      : 'unavailable'

  const activeNav = navItemForPath(path)

  const handleRefresh = useCallback(() => {
    setRefreshing(true)
    window.dispatchEvent(new CustomEvent('gw-refresh'))
    setTimeout(() => setRefreshing(false), 700)
  }, [])

  return (
    <Shell
      navItems={NAV_ITEMS}
      activePath={activeNav.path}
      onNavigate={navigate}
      title={activeNav.title}
      subtitle={activeNav.subtitle}
      openAlerts={openAlerts}
      apiState={apiState}
      onRefresh={handleRefresh}
      refreshing={refreshing}
    >
      {renderView(path, navigate)}
    </Shell>
  )
}
