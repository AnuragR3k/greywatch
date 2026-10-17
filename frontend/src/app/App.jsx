// Greywatch application root.
//
//   "/"             — marketing landing page
//   "/dashboard/*"  — the SOC application (Shell + views)
//
// The dashboard is a separate component so its data hooks never run while the
// marketing page is displayed.

import { useEffect } from 'react'
import { useHashRoute } from './useHashRoute'
import { LandingPage } from '@/features/landing/LandingPage'
import { Dashboard } from '@/app/Dashboard'

export function App() {
  const { path, navigate } = useHashRoute()
  const isDashboard = path.startsWith('/dashboard')

  // Keep the document title meaningful per surface.
  useEffect(() => {
    document.title = isDashboard
      ? 'Greywatch · Security operations'
      : 'Greywatch · Open-source SIEM for Linux'
  }, [isDashboard])

  if (!isDashboard) {
    return <LandingPage onEnterDashboard={() => navigate('/dashboard')} />
  }
  return <Dashboard path={path} navigate={navigate} />
}
