import { useEffect } from 'react'
import Lenis from 'lenis'
import { prefersReducedMotion } from '@/lib/motion/gsap'

/**
 * Lenis smooth scrolling for the landing page only. Disabled under reduced
 * motion, and it never touches nested scroll containers (tables, drawers) —
 * only the window scroll is smoothed. Listener + RAF are cleaned up on unmount.
 */
export function SmoothScroll({ children }) {
  useEffect(() => {
    if (prefersReducedMotion()) return undefined

    const lenis = new Lenis({
      duration: 0.9,
      smoothWheel: true,
      // Leave touch/native scrolling alone on mobile.
      syncTouch: false,
    })

    let raf
    const loop = (time) => {
      lenis.raf(time)
      raf = requestAnimationFrame(loop)
    }
    raf = requestAnimationFrame(loop)

    return () => {
      cancelAnimationFrame(raf)
      lenis.destroy()
    }
  }, [])

  return children
}
