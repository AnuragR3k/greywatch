// Application routes and navigation. The dashboard is mounted under
// `/dashboard/*`; everything else is the marketing landing page.

import {
  LayoutDashboard,
  ShieldAlert,
  ScrollText,
  BookLock,
  Radar,
  AlertTriangle,
  Settings,
} from 'lucide-react'

export const LANDING_PATH = '/dashboard'
export const DASHBOARD_ROOT = '/dashboard'

export const NAV_ITEMS = [
  { key: 'overview', label: 'Overview', path: '/dashboard', icon: LayoutDashboard, title: 'Overview', subtitle: 'Operating state, detections, and collector health' },
  { key: 'alerts', label: 'Alerts', path: '/dashboard/alerts', icon: ShieldAlert, title: 'Alerts', subtitle: 'Detected alerts requiring investigation' },
  { key: 'incidents', label: 'Incidents', path: '/dashboard/incidents', icon: AlertTriangle, title: 'Incidents', subtitle: 'Correlated security events and alerts' },
  { key: 'events', label: 'Events', path: '/dashboard/events', icon: ScrollText, title: 'Events', subtitle: 'Normalized security events and raw records' },
  { key: 'journal', label: 'Journal collector', path: '/dashboard/journal', icon: BookLock, title: 'Journal collector', subtitle: 'systemd PAM / SSH / sudo authentication collection' },
  { key: 'suricata', label: 'Suricata', path: '/dashboard/suricata', icon: Radar, title: 'Suricata', subtitle: 'EVE JSON network telemetry collection' },
  { key: 'settings', label: 'Settings', path: '/dashboard/settings', icon: Settings, title: 'Settings', subtitle: 'Configuration and API trust boundary' },
]

export function navItemForPath(path) {
  const exact = NAV_ITEMS.find((item) => item.path === path)
  if (exact) return exact
  // longest-prefix match for nested routes
  return [...NAV_ITEMS]
    .filter((item) => item.path !== '/dashboard' && path.startsWith(item.path))
    .sort((a, b) => b.path.length - a.path.length)[0] || NAV_ITEMS[0]
}
