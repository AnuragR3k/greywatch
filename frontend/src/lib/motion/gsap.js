// Motion helpers built on GSAP. All helpers no-op under prefers-reduced-motion
// so critical security information is never gated behind an animation.

import { gsap } from 'gsap'
import { useGSAP } from '@gsap/react'

gsap.registerPlugin(useGSAP)

export { gsap, useGSAP }

/** True when the user prefers reduced motion (or the environment has no matchMedia). */
export function prefersReducedMotion() {
  if (typeof window === 'undefined' || !window.matchMedia) return false
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches
}

/** Staggered transform-only entrance for elements matching `selector`. */
export function revealChildren(scope, selector = '[data-reveal]', { stagger = 0.06, y = 10 } = {}) {
  if (prefersReducedMotion()) return null
  try {
    return gsap.context(() => {
      gsap.fromTo(
        selector,
        { y, autoAlpha: 0 },
        { y: 0, autoAlpha: 1, duration: 0.45, ease: 'power2.out', stagger, clearProps: 'transform,opacity,visibility' },
      )
    }, scope)
  } catch {
    return null
  }
}
