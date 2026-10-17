// Minimal hash router. No dependency: the dashboard and landing page are two
// top-level surfaces, so a tiny switch keeps routing understandable.

import { useCallback, useEffect, useState } from 'react'

function currentPath() {
  if (typeof window === 'undefined') return '/'
  const hash = window.location.hash.replace(/^#/, '')
  return hash || '/'
}

export function useHashRoute() {
  const [path, setPath] = useState(currentPath)

  useEffect(() => {
    const onChange = () => setPath(currentPath())
    window.addEventListener('hashchange', onChange)
    return () => window.removeEventListener('hashchange', onChange)
  }, [])

  const navigate = useCallback((to) => {
    if (window.location.hash.replace(/^#/, '') === to) return
    window.location.hash = to
  }, [])

  return { path, navigate }
}
